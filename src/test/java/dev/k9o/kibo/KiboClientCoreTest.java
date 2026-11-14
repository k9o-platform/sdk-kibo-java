package dev.k9o.kibo;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;

import org.junit.jupiter.api.Test;

import dev.k9o.Crypto;
import dev.k9o.Crypto.CoreOptions;
import dev.k9o.Crypto.FederatedToken;
import dev.k9o.Crypto.Plain;
import dev.k9o.Crypto.Result;
import dev.k9o.Crypto.Sealed;
import dev.k9o.KError;

class KiboClientCoreTest {

    static final String KEY = "arn:aws:kms:eu-central-1:111122223333:key/mine";

    static FederatedToken tok(String provider, String projectId) {
        return new FederatedToken("jwt-secret", "x", "i", "proj_1:crypt:c:op:encrypt", "a", "k", provider, projectId);
    }

    /** A fake core: seal prefixes {1,2,3}; open refuses a container not starting with 1. */
    static class Fake implements AppCore {
        final List<String> log;
        List<String> caps = List.of("expected_key_refs");
        boolean hasAppCrypto = true;
        boolean stall;
        RuntimeException sealFails;

        Fake(List<String> log) { this.log = log; }

        public byte[] sealBlocking(SealInput in) {
            log.add("seal:" + in.crypt() + ":" + in.projectId() + ":" + String.join(",", in.expectedKeyRefs()));
            if (sealFails != null) throw sealFails;
            byte[] out = new byte[3 + in.plaintext().length];
            out[0] = 1; out[1] = 2; out[2] = 3;
            System.arraycopy(in.plaintext(), 0, out, 3, in.plaintext().length);
            return out;
        }

        public byte[] openBlocking(OpenInput in) {
            log.add("open:" + in.crypt() + ":" + String.join(",", in.expectedKeyRefs()));
            if (in.container()[0] != 1) throw new RuntimeException("K9O_CRYPTO_UNEXPECTED_KEY: no");
            return Arrays.copyOfRange(in.container(), 3, in.container().length);
        }

        public Credential acquireKmsCredentialBlocking(AcquireInput in) {
            log.add("exchange:" + in.identityToken());
            if (stall) {
                try { Thread.sleep(60_000); } catch (InterruptedException e) { throw new RuntimeException("interrupted"); }
            }
            return new Credential("cred-1", 10_000);
        }

        public List<String> coreCapabilities() { return caps; }

        public boolean hasAppCrypto() { return hasAppCrypto; }
    }

    static KiboClientCore.Config cfg(List<String> log, Function<KiboClientCore.Config, KiboClientCore.Config> over) {
        KiboClientCore.Config base = new KiboClientCore.Config(
            Crypto.KeyRefProvider.AWS, "byok", "proj_1", new AppCore.KeyRef(1, KEY), null,
            new AppCore.FederationSpec.Aws("arn:aws:iam::1:role/r", "s", "eu-central-1", KEY, 900),
            List.of(KEY),
            (crypt, op) -> { log.add("token:" + crypt + ":" + op); return tok("aws", "proj_1"); },
            new Fake(log), 0, () -> 1000);
        return over.apply(base);
    }

    static KiboClientCore.Config cfg(List<String> log) { return cfg(log, c -> c); }

    static KiboClientCore.Config with(KiboClientCore.Config c, List<String> pin, KiboClientCore.TokenSource src, AppCore core, String projectId,
                                      long deadline, java.util.function.LongSupplier now) {
        return new KiboClientCore.Config(c.provider(), c.posture(), projectId, c.keyRef(), c.providerConfig(), c.federation(),
            pin, src == null ? c.federatedToken() : src, core == null ? c.core() : core, deadline, now == null ? c.nowUnixSecs() : now);
    }

    static final CoreOptions NO_OPTS = null;
    static List<Plain> one() { return List.of(Plain.of(new byte[] {1})); }

    static String code(Runnable r) {
        return assertThrows(KError.class, r::run).getCode();
    }

    @Test
    void encryptTokenThenExchangeThenSeal_roundTripsThroughDecrypt() {
        List<String> log = new ArrayList<>();
        KiboClientCore core = KiboClientCore.create(cfg(log));
        List<Result> enc = core.encrypt("c", List.of(Plain.of("hi")), NO_OPTS);
        assertEquals(List.of("token:c:encrypt", "exchange:jwt-secret", "seal:c:proj_1:" + KEY), log);
        List<Result> dec = core.decrypt("c", List.of(Sealed.of(enc.get(0).ciphertext())), NO_OPTS);
        assertEquals("hi", dec.get(0).text());
    }

    @Test
    void declaresItEnforcesThePin() {
        assertTrue(KiboClientCore.create(cfg(new ArrayList<>())).enforcesExpectedKeyRefs());
    }

    @Test
    void refusesToBeBuiltWithoutAPinWithAnEmptyPinOrWithAKeyOutsideThePin() {
        KiboClientCore.Config c = cfg(new ArrayList<>());
        { KError e = assertThrows(KError.class, () -> KiboClientCore.create(with(c, null, null, null, "proj_1", 0, null)));
            assertEquals("K9O_INVALID_FIELD_VALUE", e.getCode());
            assertTrue(e.getMessage().contains("key pin")); }
        { KError e = assertThrows(KError.class, () -> KiboClientCore.create(with(c, List.of(), null, null, "proj_1", 0, null)));
            assertEquals("K9O_INVALID_FIELD_VALUE", e.getCode());
            assertTrue(e.getMessage().contains("key pin")); }
        KError e = assertThrows(KError.class, () -> KiboClientCore.create(
            with(c, List.of("arn:aws:kms:eu-central-1:111122223333:key/other"), null, null, "proj_1", 0, null)));
        assertTrue(e.getMessage().contains("keyRef"));
    }

    @Test
    void anEmptyPinFromTheRouterReachesNoNetworkAndNoKms() {
        List<String> log = new ArrayList<>();
        KiboClientCore core = KiboClientCore.create(cfg(log));
        KError e = assertThrows(KError.class, () -> core.decrypt("c", List.of(Sealed.of("AQID")), new CoreOptions(List.of())));
        assertTrue(e.getMessage().contains("key pin"));
        assertEquals(List.of(), log);
    }

    @Test
    void aPerCallPinWithoutTheConfiguredKeyIsRefusedBeforeTokenExchangeSealOrOpen() {
        List<String> log = new ArrayList<>();
        KiboClientCore core = KiboClientCore.create(cfg(log));
        CoreOptions other = new CoreOptions(List.of("arn:aws:kms:eu-central-1:111122223333:key/other"));
        List<Result> enc = core.encrypt("c", List.of(Plain.of(new byte[] {1}), Plain.of(new byte[] {2})), other);
        assertEquals(2, enc.size());
        for (Result r : enc) assertEquals("K9O_CRYPTO_UNEXPECTED_KEY", r.code());
        assertEquals("K9O_CRYPTO_UNEXPECTED_KEY", core.decrypt("c", List.of(Sealed.of("AQID")), other).get(0).code());
        assertEquals("K9O_CRYPTO_UNEXPECTED_KEY", core.rewrap("c", List.of(Sealed.of("AQID")), other).get(0).code());
        assertEquals(List.of(), log);
        // a matching per-call pin still reaches the token, exchange and seal
        List<Result> ok = core.encrypt("c", one(), new CoreOptions(List.of(KEY)));
        assertTrue(ok.get(0).ok());
        assertEquals(List.of("token:c:encrypt", "exchange:jwt-secret", "seal:c:proj_1:" + KEY), log);
    }

    @Test
    void aCoreThatDoesNotListExpectedKeyRefsIsRefusedBeforeAnyTokenIsFetched() {
        List<String> log = new ArrayList<>();
        Fake f = new Fake(log);
        f.caps = List.of();
        KiboClientCore core = KiboClientCore.create(with(cfg(log), List.of(KEY), null, f, "proj_1", 0, null));
        assertEquals("K9O_CRYPTO_KEY_PIN_UNENFORCED", code(() -> core.encrypt("c", one(), NO_OPTS)));
        assertEquals(List.of(), log);
    }

    @Test
    void anOlderCoreWithoutTheNewFunctionsIsRefused() {
        List<String> log = new ArrayList<>();
        Fake f = new Fake(log);
        f.hasAppCrypto = false;
        KiboClientCore core = KiboClientCore.create(with(cfg(log), List.of(KEY), null, f, "proj_1", 0, null));
        assertEquals("KIBO_WASM_ERROR", code(() -> core.encrypt("c", one(), NO_OPTS)));
        assertEquals(List.of(), log);
    }

    @Test
    void aResponseNamingAnotherProviderOrProjectIsRefusedAndNothingIsExchanged() {
        for (FederatedToken t : new FederatedToken[] {tok("gcp", "proj_1"), tok("aws", "proj_other")}) {
            List<String> log = new ArrayList<>();
            KiboClientCore core = KiboClientCore.create(with(cfg(log), List.of(KEY), (crypt, op) -> t, null, "proj_1", 0, null));
            assertEquals("K9O_INVALID_FIELD_VALUE", code(() -> core.encrypt("c", one(), NO_OPTS)));
            assertEquals(List.of(), log);
        }
    }

    @Test
    void projectIdComesFromTheResponseOnlyWhenNotConfigured() {
        List<String> log = new ArrayList<>();
        KiboClientCore core = KiboClientCore.create(with(cfg(log), List.of(KEY), null, null, null, 0, null));
        core.encrypt("c", one(), NO_OPTS);
        assertEquals("seal:c:proj_1:" + KEY, log.get(log.size() - 1));
        KiboClientCore none = KiboClientCore.create(with(cfg(new ArrayList<>()), List.of(KEY), (crypt, op) -> tok("aws", null), null, null, 0, null));
        assertEquals("K9O_INVALID_FIELD_VALUE", code(() -> none.encrypt("c", one(), NO_OPTS)));
    }

    @Test
    void theExchangedCredentialIsReusedUntilNearExpiryThenExchangedAgain() {
        List<String> log = new ArrayList<>();
        AtomicLong t = new AtomicLong(1000);
        KiboClientCore core = KiboClientCore.create(with(cfg(log), List.of(KEY), null, null, "proj_1", 0, t::get));
        core.encrypt("c", one(), NO_OPTS);
        core.encrypt("c", one(), NO_OPTS);
        assertEquals(1, log.stream().filter(l -> l.startsWith("exchange")).count());
        assertEquals(2, log.stream().filter(l -> l.startsWith("token")).count(), "a token is fetched on every call");
        t.set(9_950); // inside the 60 s skew of 10_000
        core.encrypt("c", one(), NO_OPTS);
        assertEquals(2, log.stream().filter(l -> l.startsWith("exchange")).count());
    }

    @Test
    void aStalledExchangeIsAbandonedAtTheDeadline() {
        List<String> log = new ArrayList<>();
        Fake f = new Fake(log);
        f.stall = true;
        KiboClientCore core = KiboClientCore.create(with(cfg(log), List.of(KEY), null, f, "proj_1", 20, null));
        assertEquals("KIBO_EXCHANGE_TIMEOUT", code(() -> core.encrypt("c", one(), NO_OPTS)));
    }

    @Test
    void oneBadItemFailsOnItsOwnAndCarriesTheCoresCode() {
        KiboClientCore core = KiboClientCore.create(cfg(new ArrayList<>()));
        String good = core.encrypt("c", List.of(Plain.of(new byte[] {9})), NO_OPTS).get(0).ciphertext();
        List<Result> r = core.decrypt("c", List.of(Sealed.of("AAAA"), Sealed.of(good)), NO_OPTS);
        assertFalse(r.get(0).ok());
        assertEquals("K9O_CRYPTO_UNEXPECTED_KEY", r.get(0).code());
        assertTrue(r.get(1).ok());
    }

    @Test
    void rewrapOpensAndSealsUnderTheConfiguredKeyWithTheRewrapToken() {
        List<String> log = new ArrayList<>();
        KiboClientCore core = KiboClientCore.create(cfg(log));
        String ct = core.encrypt("c", List.of(Plain.of(new byte[] {7})), NO_OPTS).get(0).ciphertext();
        log.clear();
        List<Result> r = core.rewrap("c", List.of(Sealed.of(ct)), NO_OPTS);
        assertTrue(r.get(0).ok());
        assertEquals("token:c:rewrap", log.get(0));
        assertEquals(List.of("open", "seal"), log.subList(log.size() - 2, log.size()).stream().map(l -> l.split(":")[0]).toList());
    }

    @Test
    void decryptUsesTheDecryptOp() {
        List<String> log = new ArrayList<>();
        KiboClientCore core = KiboClientCore.create(cfg(log));
        core.decrypt("c", List.of(Sealed.of(Base64.getEncoder().encodeToString(new byte[] {1, 2, 3, 4}))), NO_OPTS);
        assertEquals("token:c:decrypt", log.get(0));
    }

    @Test
    void neitherTheTokenNorTheCredentialAppearsInAnError() {
        List<String> log = new ArrayList<>();
        Fake f = new Fake(log);
        f.sealFails = new RuntimeException("UPSTREAM_KMS_ERROR: denied");
        KiboClientCore core = KiboClientCore.create(with(cfg(log), List.of(KEY), null, f, "proj_1", 0, null));
        List<Result> r = core.encrypt("c", one(), NO_OPTS);
        assertEquals("UPSTREAM_KMS_ERROR", r.get(0).code());
        String s = r.toString() + r.get(0).message();
        assertFalse(s.contains("jwt-secret"));
        assertFalse(s.contains("cred-1"));
        AppCore.Credential cred = new AppCore.Credential("cred-1", 1);
        assertFalse(cred.toString().contains("cred-1"));
        assertFalse(new AppCore.AcquireInput(null, "jwt-secret", 1).toString().contains("jwt-secret"));
        assertFalse(new AppCore.SealInput("aws-kms", "byok", null, "pt".getBytes(StandardCharsets.UTF_8), cred, null, "p", "c", null, List.of()).toString().contains("cred-1"));
    }
}
