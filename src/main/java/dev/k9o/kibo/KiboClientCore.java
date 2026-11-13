package dev.k9o.kibo;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.LongSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import dev.k9o.Crypto;
import dev.k9o.Crypto.CoreOptions;
import dev.k9o.Crypto.Plain;
import dev.k9o.Crypto.Result;
import dev.k9o.Crypto.Sealed;
import dev.k9o.KError;

/**
 * The client core for {@code k9o.crypto()} on a BYOK or HYOK project: opens and seals data on this machine, against your own
 * KMS or HSM, so the platform never sees plaintext or the key. There is no crypto here: sealing, opening, the key pin and the
 * token exchange all run in the audited Rust core ({@code kibo-kms-rest-ffi}), reached through {@link AppCore}. This class
 * only sequences them:
 *
 * <pre>federated token (platform) -> acquire_kms_credential (your cloud) -> app_crypto_seal / app_crypto_open (your KMS)</pre>
 *
 * Everything that picks a key, a provider, a role, a region or an endpoint comes from the {@link Config} you pass. Nothing
 * comes from the platform's answer: the token response's {@code provider} and {@code projectId} are checked against your
 * configuration, and a mismatch is refused, never followed.
 *
 * <p>Register it with {@code k9o.crypto().useClientCore(KiboClientCore.create(config))}, and set {@code expectedKeyRefs} on the
 * client too: the router passes that list on every call and an empty list is refused.
 */
public final class KiboClientCore implements Crypto.ClientCore {

    /** Code raised when the credential exchange runs past its deadline. */
    public static final String EXCHANGE_TIMEOUT = "KIBO_EXCHANGE_TIMEOUT";

    /** Fetches a federated token: {@code (crypt, op) -> k9o.crypto().federatedToken(crypt, op).data()}. A fresh token on every call. */
    @FunctionalInterface
    public interface TokenSource {
        Crypto.FederatedToken get(String crypt, String op);
    }

    /** Where your key lives and how to reach it. All of it is yours: the platform supplies none of these. */
    public record Config(
        Crypto.KeyRefProvider provider,
        String posture,
        String projectId,
        AppCore.KeyRef keyRef,
        AppCore.ProviderConfig providerConfig,
        AppCore.FederationSpec federation,
        List<String> expectedKeyRefs,
        TokenSource federatedToken,
        AppCore core,
        long exchangeDeadlineMs,
        LongSupplier nowUnixSecs
    ) {
        /**
         * @param provider            your cloud; must equal {@code federation.provider()}
         * @param posture             {@code "byok"} or {@code "hyok"}
         * @param projectId           the project id; null to take the token response's value (a configured value is never overridden)
         * @param keyRef              the exact key this application uses
         * @param providerConfig      region for AWS, address for Vault, host suffix for an Azure cloud outside the built-in list; may be null
         * @param federation          how to exchange the platform's identity token for a credential on your cloud
         * @param expectedKeyRefs     the keys this application allows; required and non-empty
         * @param federatedToken      the token source
         * @param core                the bound core
         * @param exchangeDeadlineMs  how long the exchange may take; 0 means the default of 30000
         * @param nowUnixSecs         the host clock in Unix seconds; null means the system clock
         */
        public Config {
            expectedKeyRefs = expectedKeyRefs == null ? null : List.copyOf(expectedKeyRefs);
        }
    }

    private static final Pattern CORE_ERROR = Pattern.compile("^([A-Z][A-Z0-9_]*):\\s*([\\s\\S]*)$");
    private static final long SKEW_SECS = 60;
    private static final ExecutorService EXCHANGE = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "kibo-exchange");
        t.setDaemon(true);
        return t;
    });

    private final Config config;
    private final List<String> pin;
    private final long deadlineMs;
    private final LongSupplier now;
    private final Map<String, AppCore.Credential> creds = new ConcurrentHashMap<>();
    private volatile boolean capsChecked;

    private KiboClientCore(Config config, List<String> pin) {
        this.config = config;
        this.pin = pin;
        this.deadlineMs = config.exchangeDeadlineMs() > 0 ? config.exchangeDeadlineMs() : 30_000;
        this.now = config.nowUnixSecs() != null ? config.nowUnixSecs() : () -> System.currentTimeMillis() / 1000;
    }

    /** Build the client core. Throws {@code K9O_INVALID_FIELD_VALUE} when the configuration is incomplete or inconsistent. */
    public static KiboClientCore create(Config config) {
        if (config == null || config.provider() == null || config.federation() == null) throw bad("provider and federation are required", "provider");
        if (config.provider() != config.federation().provider()) throw bad("provider and federation.provider must be the same cloud", "provider");
        if (!"byok".equals(config.posture()) && !"hyok".equals(config.posture())) throw bad("posture must be \"byok\" or \"hyok\"", "posture");
        List<String> pin = config.expectedKeyRefs();
        if (pin == null || pin.isEmpty()) {
            throw bad("expectedKeyRefs is required: this client never seals or opens without a key pin", "expectedKeyRefs");
        }
        for (String r : pin) {
            if (r == null || r.isBlank() || r.indexOf('*') >= 0) throw bad("expectedKeyRefs: each entry must be an exact key identifier", "expectedKeyRefs");
        }
        if (config.keyRef() == null || config.keyRef().externalRef() == null
            || !Crypto.keyRefMatches(config.keyRef().externalRef(), pin, config.provider())) {
            throw bad("keyRef is not in expectedKeyRefs", "keyRef");
        }
        if (config.federatedToken() == null || config.core() == null) throw bad("federatedToken and core are required", "federatedToken");
        return new KiboClientCore(config, pin);
    }

    @Override
    public boolean enforcesExpectedKeyRefs() { return true; }

    @Override
    public List<Result> encrypt(String crypt, List<Plain> items, CoreOptions options) {
        List<String> pinList = effectivePin(options);
        if (!keyInPin(pinList)) return refused(items.size());
        AppCore w = core();
        Exchanged x = credential(w, crypt, "encrypt");
        List<Result> out = new ArrayList<>();
        for (Plain it : items) {
            try {
                out.add(new Result(seal(w, x, crypt, it.plaintext(), it.context(), pinList, options), null, null, null, Map.of()));
            } catch (RuntimeException e) {
                out.add(failure(e));
            }
        }
        return out;
    }

    @Override
    public List<Result> decrypt(String crypt, List<Sealed> items, CoreOptions options) {
        List<String> pinList = effectivePin(options);
        if (!keyInPin(pinList)) return refused(items.size());
        AppCore w = core();
        Exchanged x = credential(w, crypt, "decrypt");
        List<Result> out = new ArrayList<>();
        for (Sealed it : items) {
            try {
                out.add(new Result(null, open(w, x, crypt, it.ciphertext(), it.context(), pinList, options), null, null, Map.of()));
            } catch (RuntimeException e) {
                out.add(failure(e));
            }
        }
        return out;
    }

    @Override
    public List<Result> rewrap(String crypt, List<Sealed> items, CoreOptions options) {
        List<String> pinList = effectivePin(options);
        if (!keyInPin(pinList)) return refused(items.size());
        AppCore w = core();
        Exchanged x = credential(w, crypt, "rewrap");
        List<Result> out = new ArrayList<>();
        for (Sealed it : items) {
            try {
                byte[] plaintext = open(w, x, crypt, it.ciphertext(), it.context(), pinList, options);
                out.add(new Result(seal(w, x, crypt, plaintext, it.context(), pinList, options), null, null, null, Map.of()));
            } catch (RuntimeException e) {
                out.add(failure(e));
            }
        }
        return out;
    }

    // ---- sequencing ----

    private record Exchanged(AppCore.Credential cred, String projectId) {}

    private List<String> effectivePin(CoreOptions options) {
        List<String> p = options == null ? pin : options.expectedKeyRefs();
        if (p == null || p.isEmpty()) throw bad("expectedKeyRefs is empty: refusing to call without a key pin", "expectedKeyRefs");
        return p;
    }

    // The call's own pin is matched against the configured key before any token is fetched or any credential is exchanged; the key version is ignored.
    private boolean keyInPin(List<String> p) {
        return Crypto.keyRefMatches(config.keyRef().externalRef(), p, config.provider());
    }

    private static List<Result> refused(int count) {
        List<Result> out = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            out.add(new Result(null, null, "K9O_CRYPTO_UNEXPECTED_KEY", "the configured key is not in this call's expectedKeyRefs; nothing was sent", Map.of()));
        }
        return out;
    }

    private AppCore core() {
        AppCore w = config.core();
        if (!w.hasAppCrypto()) {
            throw new KError("KIBO_WASM_ERROR", "the Kibo core does not export app_crypto_seal, app_crypto_open and acquire_kms_credential; it is older than zk-bundle-v2.16.3",
                Map.of(), "Use a build of the Kibo module that ships kibo-kms-rest-ffi 2.16.3 or later.", null, null);
        }
        if (!capsChecked) {
            List<String> caps = w.coreCapabilities();
            if (caps == null || !caps.contains("expected_key_refs")) {
                throw new KError(Crypto.KEY_PIN_UNENFORCED, "the Kibo core does not declare that it enforces expected_key_refs; nothing was sent",
                    Map.of(), "Use a build of the Kibo module that ships kibo-kms-rest-ffi 2.16.3 or later.", null, null);
            }
            capsChecked = true;
        }
        return w;
    }

    private Exchanged credential(AppCore w, String crypt, String op) {
        Crypto.FederatedToken t = config.federatedToken().get(crypt, op);
        String named = t.provider();
        if (named != null && !named.equals(config.provider().name().toLowerCase(Locale.ROOT))) {
            throw bad("the platform named provider \"" + named + "\"; this client is configured for \"" + config.provider().name().toLowerCase(Locale.ROOT) + "\"", "provider");
        }
        String namedProject = t.projectId();
        if (namedProject != null && config.projectId() != null && !namedProject.equals(config.projectId())) {
            throw bad("the platform named a different project than the one configured", "projectId");
        }
        String projectId = config.projectId() != null ? config.projectId() : namedProject;
        if (projectId == null) throw bad("projectId is not configured and the platform did not name one", "projectId");

        String cacheKey = crypt + "\u0000" + op + "\u0000" + t.subject();
        AppCore.Credential cached = creds.get(cacheKey);
        // A token is fetched on every call (it is bound to the call's crypt and op); the credential from the exchange is reused until it is close to expiring.
        if (cached != null && cached.expiresAtUnixSecs() - SKEW_SECS > now.getAsLong()) return new Exchanged(cached, projectId);

        AppCore.AcquireInput in = new AppCore.AcquireInput(config.federation(), t.token(), now.getAsLong());
        Future<AppCore.Credential> f = EXCHANGE.submit(() -> w.acquireKmsCredentialBlocking(in));
        AppCore.Credential c;
        try {
            c = f.get(deadlineMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            f.cancel(true);
            throw new KError(EXCHANGE_TIMEOUT, "the token exchange with your cloud did not finish within " + deadlineMs + " ms",
                Map.of("deadlineMs", deadlineMs), "Check that your cloud's token endpoint is reachable from this host.", null, null);
        } catch (InterruptedException e) {
            f.cancel(true);
            Thread.currentThread().interrupt();
            throw new KError("KIBO_WASM_ERROR", "the token exchange was interrupted");
        } catch (ExecutionException e) {
            throw mapCoreError(e.getCause());
        }
        if (c == null || c.secret() == null) {
            throw new KError("KIBO_WASM_DECODE_ERROR", "the core returned a credential without secret or expiry");
        }
        creds.put(cacheKey, c);
        return new Exchanged(c, projectId);
    }

    private AppCore.ProviderConfig providerConfig(CoreOptions options) {
        AppCore.ProviderConfig p = config.providerConfig();
        return new AppCore.ProviderConfig(p == null ? null : p.awsRegion(), p == null ? null : p.vaultAddress());
    }

    private String seal(AppCore w, Exchanged x, String crypt, byte[] plaintext, String context, List<String> pinList, CoreOptions options) {
        byte[] container = w.sealBlocking(new AppCore.SealInput(wire(config.provider()), config.posture(), config.keyRef(), plaintext,
            x.cred(), providerConfig(options), x.projectId(), crypt, context, List.copyOf(pinList)));
        if (container == null) throw new KError("KIBO_WASM_DECODE_ERROR", "the core returned a non-byte value where bytes were expected");
        return Base64.getEncoder().encodeToString(container);
    }

    private byte[] open(AppCore w, Exchanged x, String crypt, String ciphertext, String context, List<String> pinList, CoreOptions options) {
        byte[] container = Base64.getDecoder().decode(ciphertext);
        byte[] plaintext = w.openBlocking(new AppCore.OpenInput(container, x.cred(), providerConfig(options), x.projectId(), crypt, context,
            List.copyOf(pinList)));
        if (plaintext == null) throw new KError("KIBO_WASM_DECODE_ERROR", "the core returned a non-byte value where bytes were expected");
        return plaintext;
    }

    // ---- helpers ----

    private static String wire(Crypto.KeyRefProvider p) {
        switch (p) {
            case AWS: return "aws-kms";
            case GCP: return "gcp-kms";
            case AZURE: return "azure-kv";
            default: return "hashicorp-vault";
        }
    }

    private static KError bad(String message, String field) {
        return new KError("K9O_INVALID_FIELD_VALUE", message, Map.of("field", field), null, null, null);
    }

    /** The core rejects with {@code "<CODE>: <message>"}; {@code UPSTREAM_KMS_ERROR} is your own KMS failing. */
    private static KError mapCoreError(Throwable e) {
        if (e instanceof KError k) return k;
        String raw = e == null || e.getMessage() == null ? String.valueOf(e) : e.getMessage();
        Matcher m = CORE_ERROR.matcher(raw);
        return m.matches() ? new KError(m.group(1), m.group(2)) : new KError("KIBO_WASM_ERROR", raw);
    }

    private static Result failure(RuntimeException e) {
        KError k = mapCoreError(e);
        return new Result(null, null, k.getCode(), k.getMessage(), Map.of());
    }
}
