package dev.k9o.kibo;

import java.util.Map;

import dev.k9o.KError;

import uniffi.kibo_kms_rest_ffi.DecryptInput;
import uniffi.kibo_kms_rest_ffi.DecryptOutput;
import uniffi.kibo_kms_rest_ffi.EncryptInput;
import uniffi.kibo_kms_rest_ffi.EncryptOutput;
import uniffi.kibo_kms_rest_ffi.ZkFfiUniffiException;

import static uniffi.kibo_kms_rest_ffi.Kibo_kms_rest_ffiKt.zkEncryptBlocking;
import static uniffi.kibo_kms_rest_ffi.Kibo_kms_rest_ffiKt.zkDecryptBlocking;

/**
 * Java facade for the Kibo Zero-Knowledge BYOK/HYOK vault crypto surface.
 *
 * <p>ZERO crypto here: every wrap/unwrap, envelope framing, posture-floor
 * enforcement, and KMS round-trip lives in the audited Rust core
 * ({@code kibo-kms-rest-ffi}, piece C). Java has no coroutines, so this calls
 * the SYNC {@code zkEncryptBlocking}/{@code zkDecryptBlocking} exports (which
 * drive the same canonical async op to completion on a process-wide tokio
 * runtime inside the core; crypto-identical to the async exports).
 *
 * <p>The JVM binding is the uniffi-generated Kotlin binding (package
 * {@code uniffi.kibo_kms_rest_ffi}) — pure-JVM (JNA), Java-callable. The
 * generated binding and the native lib are CI-injected build artifacts. The
 * three {@code ZkFfiUniffiException} variants map to the shared {@link KError}
 * (consistent with the Python/Ruby server SDKs), codes passed through.
 *
 * <p>NOTE: the static-import facade class {@code Kibo_kms_rest_ffiKt} is
 * Kotlin's default file-facade name for {@code kibo_kms_rest_ffi.kt}; if the
 * binding adds {@code @file:JvmName}, adjust the import. JVM compile-verified
 * in CI (no local JVM at the authoring seat).
 */
public final class Kibo {

    private Kibo() {
    }

    /**
     * Encrypt {@code input.getPlaintext()} via the customer KMS, client-side.
     * Returns the opaque ZKFE envelope. Throws {@link KError} on failure.
     */
    public static EncryptOutput encrypt(EncryptInput input) {
        try {
            return zkEncryptBlocking(input);
        } catch (ZkFfiUniffiException e) {
            throw toKError(e);
        }
    }

    /**
     * Decrypt a ZKFE {@code input.getEnvelope()}. {@code strategy},
     * {@code attestationTier}, and {@code encryptionContext} MUST match the
     * encrypt-time values (AAD-bound). Throws {@link KError} on failure.
     */
    public static DecryptOutput decrypt(DecryptInput input) {
        try {
            return zkDecryptBlocking(input);
        } catch (ZkFfiUniffiException e) {
            throw toKError(e);
        }
    }

    /** Map the bound core's uniffi exception to {@link KError}, codes passed through. */
    private static KError toKError(ZkFfiUniffiException e) {
        if (e instanceof ZkFfiUniffiException.PostureViolation) {
            ZkFfiUniffiException.PostureViolation pv = (ZkFfiUniffiException.PostureViolation) e;
            return new KError(
                pv.getCode(),
                pv.getDetail(),
                Map.of(
                    "dimension", pv.getDimension(),
                    "requested", pv.getRequested(),
                    "declared", pv.getDeclared()
                ),
                null, null, null
            );
        }
        if (e instanceof ZkFfiUniffiException.Platform) {
            ZkFfiUniffiException.Platform p = (ZkFfiUniffiException.Platform) e;
            return new KError(p.getCode(), p.getDetail());
        }
        if (e instanceof ZkFfiUniffiException.UpstreamKms) {
            // Customer's own KMS failed — no K9O_* code (upstream failures carry no K9O_* code).
            ZkFfiUniffiException.UpstreamKms u = (ZkFfiUniffiException.UpstreamKms) e;
            return new KError("UPSTREAM_KMS_ERROR", u.getDetail());
        }
        return new KError("KIBO_FFI_ERROR", e.getMessage());
    }
}
