package dev.k9o.kibo;

import java.util.List;

import dev.k9o.Crypto;

/**
 * What {@link KiboClientCore} needs from the bound Kibo core (kibo-kms-rest-ffi 2.16.3 or later): seal, open, the token
 * exchange and the capability list. {@link UniffiAppCore}, shipped with this SDK, satisfies it over the generated
 * uniffi Kotlin package ({@code uniffi.kibo_kms_rest_ffi}); it converts the records below to the binding's types and
 * back. The records mirror the core's input and output types; the core's snake_case wire names are noted on each.
 *
 * <p>A method throws when the core refuses; the exception message is the core's text, {@code "<CODE>: <message>"}. Every
 * method may block.
 */
public interface AppCore {

    /** {@code app_crypto_seal}: seals {@code plaintext} under the key. Returns the container bytes. */
    byte[] sealBlocking(SealInput input);

    /** {@code app_crypto_open}: opens a container. Returns the plaintext. */
    byte[] openBlocking(OpenInput input);

    /** {@code acquire_kms_credential}: exchanges the platform's identity token for a credential on your cloud. */
    Credential acquireKmsCredentialBlocking(AcquireInput input);

    /** {@code core_capabilities}: the features this core declares; {@code expected_key_refs} is the key pin. */
    List<String> coreCapabilities();

    /**
     * {@code false} for an adapter over a core older than 2.16.3, which lacks the functions above. {@link KiboClientCore}
     * refuses such a core with {@code KIBO_WASM_ERROR}.
     */
    default boolean hasAppCrypto() { return true; }

    /** A key: {@code version} and {@code external_ref}. */
    record KeyRef(int version, String externalRef) {}

    /** {@code provider_config}: {@code aws_region}, {@code vault_address}; each may be null. */
    record ProviderConfig(String awsRegion, String vaultAddress) {}

    /** {@code FfiCredential}: {@code secret} and {@code expires_at_unix_secs}. A credential: {@link #toString} redacts it. */
    record Credential(String secret, long expiresAtUnixSecs) {
        @Override
        public String toString() { return "Credential[secret=<redacted>, expiresAtUnixSecs=" + expiresAtUnixSecs + "]"; }
    }

    /** {@code FfiFederationSpec}: how to exchange the identity token on your cloud. */
    sealed interface FederationSpec {
        Crypto.KeyRefProvider provider();

        /** {@code provider: "aws"}: {@code role_arn, session_name, region, key_arn, duration_secs}. */
        record Aws(String roleArn, String sessionName, String region, String keyArn, long durationSecs) implements FederationSpec {
            public Crypto.KeyRefProvider provider() { return Crypto.KeyRefProvider.AWS; }
        }

        /** {@code provider: "gcp"}: {@code audience}. */
        record Gcp(String audience) implements FederationSpec {
            public Crypto.KeyRefProvider provider() { return Crypto.KeyRefProvider.GCP; }
        }

        /** {@code provider: "azure"}: {@code tenant_id, client_id, scope}. */
        record Azure(String tenantId, String clientId, String scope) implements FederationSpec {
            public Crypto.KeyRefProvider provider() { return Crypto.KeyRefProvider.AZURE; }
        }

        /**
         * {@code provider: "vault"}: {@code vault_addr, mount, role}. {@code jwtAuthMount} is the JWT auth mount: the name Vault
         * serves the JWT login under, {@code jwt} for {@code auth/jwt} (not the transit mount, which comes from the key reference).
         * The adapter hands it to the core as the core's {@code mount} field.
         */
        record Vault(String vaultAddr, String jwtAuthMount, String role) implements FederationSpec {
            public Crypto.KeyRefProvider provider() { return Crypto.KeyRefProvider.VAULT; }
        }
    }

    /** {@code FfiFederationInput}: {@code spec, identity_token, now_unix_secs}. {@link #toString} redacts the token. */
    record AcquireInput(FederationSpec spec, String identityToken, long nowUnixSecs) {
        @Override
        public String toString() { return "AcquireInput[spec=" + spec + ", identityToken=<redacted>, nowUnixSecs=" + nowUnixSecs + "]"; }
    }

    /**
     * {@code AppSealInput}. {@code provider} is the wire name ({@code aws-kms}, {@code gcp-kms}, {@code azure-kv},
     * {@code hashicorp-vault}); {@code posture} is {@code byok} or {@code hyok}; {@code context} may be null.
     * {@link #toString} shows no plaintext and no credential.
     */
    record SealInput(String provider, String posture, KeyRef keyRef, byte[] plaintext, Credential kmsCred, ProviderConfig providerConfig,
                     String projectId, String crypt, String context, List<String> expectedKeyRefs) {
        @Override
        public String toString() { return "SealInput[provider=" + provider + ", crypt=" + crypt + "]"; }
    }

    /** {@code AppOpenInput}; see {@link SealInput}. */
    record OpenInput(byte[] container, Credential kmsCred, ProviderConfig providerConfig, String projectId, String crypt, String context,
                     List<String> expectedKeyRefs) {
        @Override
        public String toString() { return "OpenInput[crypt=" + crypt + "]"; }
    }
}
