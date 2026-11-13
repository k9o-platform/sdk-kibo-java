# dev.k9o:kibo

Official Java SDK for [Kilimanjaro](#75-about-kilimanjaro) Kibo.

Encrypt and decrypt on the client with keys held in your own KMS, so the platform never sees plaintext.

The platform never sees plaintext or unwrapped keys. Encryption and decryption run on your machine, with your KMS credentials.

## Contents

**A. Get started**

1. [Links](#1-links)
2. [Install](#2-install)
3. [Choose the right package](#3-choose-the-right-package)
4. [Usage](#4-usage)

**B. Use Kibo**

5. [Encrypt through `k9o.crypto()` on a BYOK or HYOK project](#5-encrypt-through-k9ocrypto-on-a-byok-or-hyok-project)

**C. Troubleshoot**

6. [Handling errors](#6-handling-errors)

**D. Reference**

7. [Appendix](#7-appendix)
   - 7.1 [Requirements](#71-requirements)
   - 7.2 [Error codes](#72-error-codes)
   - 7.3 [Methods](#73-methods)
   - 7.4 [Related packages](#74-related-packages)
   - 7.5 [About Kilimanjaro](#75-about-kilimanjaro)
8. [License](#8-license)

## A. Get started

### 1. Links

- Website: <https://kilimanjaro.dev>
- Documentation / Developer Hub: <https://docs.kilimanjaro.dev>
- API: <https://api.k9o.io>
- Console: <https://console.k9o.io>
- Open source
  - Platform: <https://github.com/k9o-platform>
  - Community: <https://github.com/k9o-community>

### 2. Install

Maven:

```xml
<dependency>
    <groupId>dev.k9o</groupId>
    <artifactId>kibo</artifactId>
    <version>1.5.0</version>
</dependency>
```

Gradle:

```groovy
implementation 'dev.k9o:kibo:1.5.0'
```

Requires JDK 21 or newer and a native library for your platform. See [requirements](#71-requirements).

### 3. Choose the right package

| Package | Use it when you are… | Registry | Source |
| --- | --- | --- | --- |
| `dev.k9o:core` | Building a backend service: the platform client and Gate. | [Maven Central](https://central.sonatype.com/artifact/dev.k9o/core) | [sdk-java](https://github.com/k9o-platform/sdk-java) |
| `dev.k9o:kibo` | Encrypting and decrypting with a key you hold in your own KMS. | [Maven Central](https://central.sonatype.com/artifact/dev.k9o/kibo) | [sdk-kibo-java](https://github.com/k9o-platform/sdk-kibo-java) |

### 4. Usage

`dev.k9o.kibo.Kibo` has two static, synchronous methods: `encrypt` and `decrypt`. See [methods](#73-methods) for details.

```java
import dev.k9o.kibo.Kibo;
import uniffi.kibo_kms_rest_ffi.DecryptOutput;
import uniffi.kibo_kms_rest_ffi.EncryptOutput;

EncryptOutput encrypted = Kibo.encrypt(encryptInput);
byte[] envelope = encrypted.getEnvelope();

DecryptOutput decrypted = Kibo.decrypt(decryptInput);
byte[] plaintext = decrypted.getPlaintext();
```

- The input and output types live in the package `uniffi.kibo_kms_rest_ffi`.
- When decrypting, supply the same strategy, attestation tier and encryption context used to encrypt.
- Decryption fails if any of those three differ.

## B. Use Kibo

### 5. Encrypt through `k9o.crypto()` on a BYOK or HYOK project

The platform never sees the plaintext or the key. The key, your cloud and the exchange are all set here, from your own configuration. `KiboClientCore` runs the bound core through `AppCore`. `UniffiAppCore` is the adapter that ships with this SDK: it converts to the generated `uniffi.kibo_kms_rest_ffi` types and back, and turns the core's errors into `"<CODE>: <detail>"`.

Setup: the generated Kotlin binding goes in `src/main/kotlin/uniffi/kibo_kms_rest_ffi/` and the native library in `src/main/resources/<os-arch>/` (or on `-Djna.library.path`), as for `Kibo` above. When the binding file is present the build compiles it together with `UniffiAppCore` on its own; without it the build still compiles and tests the pure-Java part (`AppCore`, `KiboClientCore`), and `UniffiAppCore` and `Kibo` are left out. `UniffiAppCore` needs core 2.16.3 or later; without the binding or the library, creating it fails with a class or library loading error.

```java
import dev.k9o.Crypto;
import dev.k9o.kibo.AppCore;
import dev.k9o.kibo.KiboClientCore;
import dev.k9o.kibo.UniffiAppCore;

String key = "arn:aws:kms:eu-central-1:111122223333:key/abc";
AppCore core = new UniffiAppCore();

k9o.crypto().useClientCore(KiboClientCore.create(new KiboClientCore.Config(
    Crypto.KeyRefProvider.AWS, "byok", null,
    new AppCore.KeyRef(1, key),
    new AppCore.ProviderConfig("eu-central-1", null),
    new AppCore.FederationSpec.Aws(roleArn, "app", "eu-central-1", key, 900),
    List.of(key), // required
    (crypt, op) -> k9o.crypto().federatedToken(crypt, op).data(),
    core, 0, null)));
```

- `expectedKeyRefs` is required. Without it the core would open whatever key a stored container names. Set the same list in the client options: the router passes it on every call, and an empty list is refused before any network call.
- A core that does not declare `expected_key_refs` is refused with `K9O_CRYPTO_KEY_PIN_UNENFORCED` before any token is fetched. A core that lacks the app-crypto functions is refused with `KIBO_WASM_ERROR`; use `zk-bundle-v2.16.3` or later.
- A federated-token response that names another `provider` or `projectId` is refused with `K9O_INVALID_FIELD_VALUE`, never followed. Leave `projectId` null to take the response's value.
- The exchange is abandoned after `exchangeDeadlineMs` (default 30 s) with `KIBO_EXCHANGE_TIMEOUT`. The credential is reused until 60 s before it expires; a token is fetched on every call.
- A failure in one item is that item's `code` and `message` (`UPSTREAM_KMS_ERROR` is your own KMS); the other items still succeed.

## C. Troubleshoot

### 6. Handling errors

Failures are thrown as `dev.k9o.KError` from `dev.k9o:core`. Codes from the cryptographic core pass through unchanged.

```java
try {
    Kibo.encrypt(encryptInput);
} catch (KError e) {
    System.out.println(e.getCode());
}
```

See [error codes](#72-error-codes) for what each situation returns.

## D. Reference

### 7. Appendix

- [Requirements](#71-requirements)
- [Error codes](#72-error-codes)
- [Methods](#73-methods)
- [Related packages](#74-related-packages)
- [About Kilimanjaro](#75-about-kilimanjaro)

#### 7.1 Requirements

| Requirement | Detail |
|---|---|
| JDK | 21 or newer |
| Native library | Bundled in the JAR under `<os-arch>/` and loaded at runtime through JNA |
| Dependencies | `dev.k9o:core`, JNA, Kotlin standard library, kotlinx-coroutines |

#### 7.2 Error codes

| Situation | `getCode()` |
|---|---|
| Your declared posture floor rejects the request | `K9O_CRYPTO_POSTURE_FLOOR_VIOLATION` |
| The credential exchange ran past its deadline | `KIBO_EXCHANGE_TIMEOUT` |
| Another platform error from the core | The code the core returned |
| Your KMS returned an error | `UPSTREAM_KMS_ERROR` |
| Any other failure in the core | `KIBO_FFI_ERROR` |

A posture-floor error also sets `getContext()` entries `dimension`, `requested` and `declared`.

#### 7.3 Methods

| Method | What it does |
|---|---|
| `EncryptOutput encrypt(EncryptInput input)` | Encrypts plaintext through your KMS and returns an opaque envelope |
| `DecryptOutput decrypt(DecryptInput input)` | Decrypts an envelope produced by `encrypt` |

#### 7.4 Related packages

| Package | Purpose |
|---|---|
| `dev.k9o:core` | The Kilimanjaro platform client |

#### 7.5 About Kilimanjaro

Kilimanjaro is a modular developer platform for building secure enterprise applications.
You define AI agents, functions and data pipelines on the platform.
The SDKs let you deploy and invoke them, read and write your data, publish to and subscribe to streams, sign users in,
and encrypt with keys you hold.

It provides four building blocks:

- **Keep**: AI security and governance. Guardrails and policy for the agents you run.
- **Pulse**: data intelligence and real-time stream processing. Streams, analytics and live feeds.
- **Gate**: customer identity and access management. Sign-in and sessions, and automatic data scoping
  so a signed-in user reaches only their own data.
- **Kibo**: cryptographic keys and secrets management. Client-side encryption with keys you hold, and a secrets vault.

### 8. License

Apache-2.0 © Formelo Inc. See `LICENSE` and `NOTICE`.
