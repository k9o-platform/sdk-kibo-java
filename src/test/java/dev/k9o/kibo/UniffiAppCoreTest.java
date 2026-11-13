package dev.k9o.kibo;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assumptions;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The shipped adapter against the real bound core. Every test skips when the generated binding or the native library is
 * not loadable (set {@code -Djna.library.path} to the directory holding the library, or put it on the classpath as the
 * README says). Nothing here uses a real credential.
 *
 * <p>The provider tests send a placeholder credential to the provider and expect it to be refused there, so they reach
 * the network and run only with {@code -Dkibo.core.refusal=true}.
 */
class UniffiAppCoreTest {

    private static final Pattern CORE_ERROR = Pattern.compile("^([A-Z][A-Z0-9_]*):\\s*([\\s\\S]*)$");
    private static UniffiAppCore core;

    @BeforeAll
    static void load() {
        try {
            UniffiAppCore c = new UniffiAppCore();
            c.coreCapabilities();
            core = c;
        } catch (Throwable t) { // missing binding classes, missing native library
            Assumptions.abort("bound core not loadable: " + t);
        }
    }

    @Test
    void declaresTheKeyPin() {
        assertTrue(core.coreCapabilities().contains("expected_key_refs"), core.coreCapabilities().toString());
    }

    @Test
    void unknownProviderIsAConversionError() {
        RuntimeException e = assertThrows(RuntimeException.class, () -> core.sealBlocking(seal("nope-kms", "byok", "k")));
        assertTrue(e.getMessage().startsWith("KIBO_FFI_ERROR: unknown provider"), e.getMessage());
    }

    @Test
    void unknownPostureIsAConversionError() {
        RuntimeException e = assertThrows(RuntimeException.class, () -> core.sealBlocking(seal("aws-kms", "other", "k")));
        assertTrue(e.getMessage().startsWith("KIBO_FFI_ERROR: unknown posture"), e.getMessage());
    }

    @Test
    void negativeValuesAreRefusedBeforeTheCore() {
        RuntimeException e = assertThrows(RuntimeException.class,
            () -> core.acquireKmsCredentialBlocking(new AppCore.AcquireInput(new AppCore.FederationSpec.Gcp("a"), "t", -1)));
        assertTrue(e.getMessage().startsWith("KIBO_FFI_ERROR: time out of range"), e.getMessage());
    }

    @Test
    void awsRefusedByTheProvider() {
        String key = "arn:aws:kms:eu-central-1:111122223333:key/00000000-0000-0000-0000-000000000000";
        String sts = "{\"AccessKeyId\":\"AKIAPLACEHOLDER000000\",\"SecretAccessKey\":\"placeholder-secret\",\"SessionToken\":\"placeholder-secret\"}";
        refused(new AppCore.SealInput("aws-kms", "byok", new AppCore.KeyRef(1, key), "hello".getBytes(StandardCharsets.UTF_8),
            new AppCore.Credential(sts, 4_102_444_800L), new AppCore.ProviderConfig("eu-central-1", null), "proj_1", "crypt", null, List.of(key)));
    }

    @Test
    void gcpRefusedByTheProvider() {
        refused(seal("gcp-kms", "byok", "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"));
    }

    @Test
    void azureRefusedByTheProvider() {
        refused(seal("azure-kv", "byok", "https://placeholder.vault.azure.net/keys/k/00000000000000000000000000000000"));
    }

    @Test
    void vaultRefusedByTheProvider() {
        refused(seal("hashicorp-vault", "byok", "transit/keys/k", new AppCore.ProviderConfig(null, "https://vault.invalid:8200")));
    }

    @Test
    void federationExchangeIsRefusedByTheProvider() {
        Assumptions.assumeTrue(Boolean.getBoolean("kibo.core.refusal"));
        RuntimeException e = assertThrows(RuntimeException.class, () -> core.acquireKmsCredentialBlocking(new AppCore.AcquireInput(
            new AppCore.FederationSpec.Vault("https://vault.invalid:8200", "jwt", "role"), "placeholder-token", 1_700_000_000L)));
        assertCoreFormat(e.getMessage());
    }

    private static void refused(AppCore.SealInput in) {
        Assumptions.assumeTrue(Boolean.getBoolean("kibo.core.refusal"));
        RuntimeException e = assertThrows(RuntimeException.class, () -> core.sealBlocking(in));
        assertCoreFormat(e.getMessage());
    }

    private static void assertCoreFormat(String message) {
        assertTrue(CORE_ERROR.matcher(message).matches(), message);
        assertFalse(message.startsWith("KIBO_FFI_ERROR"), message);
        assertFalse(message.contains("placeholder-secret"), "the credential must not appear in an error");
    }

    private static AppCore.SealInput seal(String provider, String posture, String key) {
        return seal(provider, posture, key, null);
    }

    private static AppCore.SealInput seal(String provider, String posture, String key, AppCore.ProviderConfig pc) {
        return new AppCore.SealInput(provider, posture, new AppCore.KeyRef(1, key), "hello".getBytes(StandardCharsets.UTF_8),
            new AppCore.Credential("placeholder-secret", 4_102_444_800L), pc, "proj_1", "crypt", null, List.of(key));
    }
}
