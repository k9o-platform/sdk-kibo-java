# Changelog — dev.k9o:kibo (Java)

## 1.5.0 (unreleased)

### Added

- `KiboClientCore`, the client core for `k9o.crypto()` on a BYOK or HYOK project: opens and seals on this machine against your own KMS or HSM. It takes a federated token, exchanges it for a credential on your cloud, then seals or opens through the bound core (kibo-kms-rest-ffi 2.15.0 or later, reached through the new `AppCore` interface). Key, provider, region, role and endpoint come from your configuration only. `expectedKeyRefs` is required and non-empty, and the configured key must be in it; an empty list from the router is refused before any network call. A core that does not declare `expected_key_refs` is refused with `K9O_CRYPTO_KEY_PIN_UNENFORCED`, and a core without the new functions with `KIBO_WASM_ERROR`. A token response naming another `provider` or `projectId` is refused with `K9O_INVALID_FIELD_VALUE`. The exchange has a deadline (default 30 s, `KIBO_EXCHANGE_TIMEOUT`); the credential is cached per crypt, op and subject until 60 s before it expires. No token or credential appears in an error or `toString`. Item failures carry the core's code.

- `UniffiAppCore`, a ready adapter that runs `KiboClientCore` over the generated Kibo core binding, so you no longer write your own. It converts the SDK's values to the binding's types and turns the core's errors into `"<CODE>: <detail>"` (`UPSTREAM_KMS_ERROR` for your KMS's refusals). It is compiled when the binding is in `src/main/kotlin` (profile `with-binding`); without the binding the module still builds its pure-Java part (profile `no-binding`).

### Changed

- The Vault federation spec field `mount` is now `jwtAuthMount` (`AppCore.FederationSpec.Vault`). It is the JWT auth mount: the name Vault serves the JWT login under, `jwt` for `auth/jwt` (not the transit mount, which comes from the key reference).

- A call whose own `expectedKeyRefs` does not contain the configured key is refused per item with `K9O_CRYPTO_UNEXPECTED_KEY` before the federated token is fetched and before the cloud exchange (it was only refused later, inside seal/open).

- Depends on `dev.k9o:core` 1.5.0 (for `Crypto.ClientCore`).

- README description.
