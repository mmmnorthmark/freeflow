# FreeFlow Project Memory

## Build and validation

- FreeFlow is a macOS Swift app compiled directly with `swiftc` through the root `Makefile`.
- Run the complete deterministic test suite with `make test`.
- Build a locally testable, ad-hoc-signed app with `make all CODESIGN_IDENTITY=-`.
- Local build artifacts belong under `build/`; the development app is `build/FreeFlow Dev.app`.
- Keep Swift's module cache under `build/SwiftModuleCache` so sandboxed builds remain reproducible.

## Versioning

- The commit released as v1.2.0 is tag `v1.2.0` at `1de2c2fec50cfa24bf988b670a7598138914a05f`.
- Release workflows stamp versions for published artifacts, but local builds copy `Info.plist` directly. Keep `CFBundleShortVersionString` and `CFBundleVersion` aligned with the intended local base version so About displays the correct value.

## Security invariants

- Provider endpoints require HTTPS/WSS except for valid localhost, IPv4 loopback, or IPv6 loopback development endpoints.
- Never include raw provider response bodies or realtime error messages in user-visible errors or public logs.
- Secrets live in Keychain using `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`; plaintext settings are migration input only and must be removed.
- Pipeline history retention is opt-in. When disabled, clear persisted history and delete associated captured audio.
- Updates must use the exact `FreeFlow.dmg` release asset, trusted GitHub download hosts, exact byte size when supplied, matching bundle identity/signing team, valid code signature, and a passing Gatekeeper assessment.
