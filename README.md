# JWT Issuer Proof of Concept

## Overview

Simple PoC to issue JSON Web Tokens (JWTs) with a canister on the Internet Computer.
It allows the issuance of two types of JWTs:

- Symmetric (kind: `mac`, algo: `HS256`) uses a secret stored in the canister (not secure against a single malicious node provider).
- Asymmetric (kind: `tecdsa`, algo `ES256k`) uses Threshold ECDSA (tECDSA).

The JWT's `sub` (subject) field will be set to the principal of the caller.
In `tECDSA` mode the `iss` (issuer) field will be set to the [`did:key`](https://w3c-ccg.github.io/did-method-key/) representation of the tECDSA public key.

## Quickstart

If you want to test your project locally, you can use the following commands:

```bash
# Starts the replica, running in the background
dfx start --background

# Deploys your canisters to the replica and generates your candid interface
dfx deploy
```

### Interacting with the minimal web UI

Once the job completes, your application will be available at `http://localhost:8000?canisterId={frontend_canister_id}`.

### Interacting wth dfx

```bash
Coming soon :)
```


