# Suite architecture

## Boundary

End-To-End Everywhere Suite is an implementation of security architectures described by E2EESA. It does not redefine the standard.

The product family is organized as:

1. **Core runtime** — profile-bound cryptographic and state-management primitives.
2. **Identity and device layer** — user, organization, device, endpoint, and recipient identities.
3. **E2E Capsule layer** — portable encrypted objects for text, files, structured data, and application payloads.
4. **Client surfaces** — desktop, mobile, browser, email, messaging, calling, CLI, and SDKs.
5. **Ciphertext services** — relays, object storage, directories, transparency, push, and conferencing infrastructure.
6. **Administration** — policy and lifecycle control without implicit plaintext access.
7. **Assurance** — E2EESA conformance evidence, interoperability tests, reproducible builds, and external review.

## Trust rule

A service is not an E2EE endpoint merely because it participates in delivery. Server-side relays, queues, object stores, gateways, notification services, and conferencing routers must remain outside the plaintext trust boundary unless a selected E2EESA profile explicitly says otherwise.

## Dependency direction

Higher-level products depend on stable lower-level contracts:

```
apps / extensions / SDKs
          |
      E2E Capsule
          |
 identity + devices + recovery
          |
    secure core runtime
          |
       E2EESA
```

Application layers may not bypass the core runtime to directly choose cryptographic primitives.
