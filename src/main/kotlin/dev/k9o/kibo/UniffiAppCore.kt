package dev.k9o.kibo

import uniffi.kibo_kms_rest_ffi.AppOpenInput
import uniffi.kibo_kms_rest_ffi.AppSealInput
import uniffi.kibo_kms_rest_ffi.FfiCredential
import uniffi.kibo_kms_rest_ffi.FfiFederationInput
import uniffi.kibo_kms_rest_ffi.FfiFederationSpec
import uniffi.kibo_kms_rest_ffi.FfiKeyRef
import uniffi.kibo_kms_rest_ffi.FfiPosture
import uniffi.kibo_kms_rest_ffi.FfiProviderConfig
import uniffi.kibo_kms_rest_ffi.KmsProvider
import uniffi.kibo_kms_rest_ffi.ZkFfiUniffiException
import uniffi.kibo_kms_rest_ffi.acquireKmsCredentialBlocking as ffiAcquireKmsCredential
import uniffi.kibo_kms_rest_ffi.appCryptoOpenBlocking
import uniffi.kibo_kms_rest_ffi.appCryptoSealBlocking
import uniffi.kibo_kms_rest_ffi.coreCapabilities as ffiCoreCapabilities

/**
 * [AppCore] over the generated uniffi binding of the Kibo core (`uniffi.kibo_kms_rest_ffi`).
 *
 * It only converts: the SDK's plain values (longs, wire-name strings, records) become the binding's typed records, unsigned
 * integers, enums and federation variants, and the binding's errors become the `"<CODE>: <detail>"` text that
 * [KiboClientCore] turns into a `KError`. Sealing, opening and the token exchange all run in the core.
 *
 * Needs the generated binding and the native library on the classpath; see the README. Without them this class does not
 * load, and nothing else in the SDK depends on it.
 */
class UniffiAppCore : AppCore {

    override fun sealBlocking(input: AppCore.SealInput): ByteArray = guarded {
        appCryptoSealBlocking(
            AppSealInput(
                provider = provider(input.provider()),
                posture = posture(input.posture()),
                kmsCred = credential(input.kmsCred()),
                keyRef = FfiKeyRef(unsignedLong(input.keyRef().version().toLong(), "key version"), input.keyRef().externalRef()),
                providerConfig = providerConfig(input.providerConfig()),
                projectId = input.projectId(),
                crypt = input.crypt(),
                context = input.context(),
                plaintext = input.plaintext(),
                expectedKeyRefs = input.expectedKeyRefs(),
            )
        ).container
    }

    override fun openBlocking(input: AppCore.OpenInput): ByteArray = guarded {
        appCryptoOpenBlocking(
            AppOpenInput(
                kmsCred = credential(input.kmsCred()),
                providerConfig = providerConfig(input.providerConfig()),
                projectId = input.projectId(),
                crypt = input.crypt(),
                context = input.context(),
                container = input.container(),
                expectedKeyRefs = input.expectedKeyRefs(),
            )
        ).plaintext
    }

    override fun acquireKmsCredentialBlocking(input: AppCore.AcquireInput): AppCore.Credential = guarded {
        val spec: FfiFederationSpec = when (val s = input.spec()) {
            is AppCore.FederationSpec.Aws ->
                FfiFederationSpec.Aws(s.roleArn(), s.sessionName(), s.region(), s.keyArn(), unsignedInt(s.durationSecs(), "duration"))
            is AppCore.FederationSpec.Gcp -> FfiFederationSpec.Gcp(s.audience())
            is AppCore.FederationSpec.Azure -> FfiFederationSpec.Azure(s.tenantId(), s.clientId(), s.scope())
            // The core's field is named `mount`; the SDK's name says what it is.
            is AppCore.FederationSpec.Vault -> FfiFederationSpec.Vault(s.vaultAddr(), s.jwtAuthMount(), s.role())
            else -> throw ConversionException("unknown federation spec")
        }
        val c = ffiAcquireKmsCredential(FfiFederationInput(spec, input.identityToken(), unsignedLong(input.nowUnixSecs(), "time")))
        AppCore.Credential(c.secret, c.expiresAtUnixSecs.toLong())
    }

    override fun coreCapabilities(): List<String> = guarded { ffiCoreCapabilities() }

    private class ConversionException(message: String) : RuntimeException(message)

    private companion object {
        fun provider(wire: String): KmsProvider = when (wire) {
            "aws-kms" -> KmsProvider.AWS_KMS
            "gcp-kms" -> KmsProvider.GCP_KMS
            "azure-kv" -> KmsProvider.AZURE_KV
            "hashicorp-vault" -> KmsProvider.HASHICORP_VAULT
            else -> throw ConversionException("unknown provider '$wire'")
        }

        fun posture(wire: String): FfiPosture = when (wire) {
            "byok" -> FfiPosture.BYOK
            "hyok" -> FfiPosture.HYOK
            else -> throw ConversionException("unknown posture '$wire'")
        }

        fun credential(c: AppCore.Credential) = FfiCredential(c.secret(), unsignedLong(c.expiresAtUnixSecs(), "credential expiry"))

        fun providerConfig(p: AppCore.ProviderConfig?) = FfiProviderConfig(p?.awsRegion(), p?.vaultAddress())

        fun unsignedInt(v: Long, what: String): UInt {
            if (v < 0 || v > UInt.MAX_VALUE.toLong()) throw ConversionException("$what out of range")
            return v.toUInt()
        }

        fun unsignedLong(v: Long, what: String): ULong {
            if (v < 0) throw ConversionException("$what out of range")
            return v.toULong()
        }

        /** Runs a core call; the core's errors become `"<CODE>: <detail>"`, which KiboClientCore parses. */
        fun <T> guarded(call: () -> T): T = try {
            call()
        } catch (e: ZkFfiUniffiException) {
            throw RuntimeException(
                when (e) {
                    is ZkFfiUniffiException.Platform -> "${e.code}: ${e.detail}"
                    is ZkFfiUniffiException.PostureViolation -> "${e.code}: ${e.detail}"
                    // The customer's KMS refused; the core assigns no code.
                    is ZkFfiUniffiException.UpstreamKms -> "UPSTREAM_KMS_ERROR: ${e.detail}"
                }
            )
        } catch (e: ConversionException) {
            throw RuntimeException("KIBO_FFI_ERROR: ${e.message}")
        }
    }
}
