## TLS1.3 with TPM2.0

### Introduction

Unlike on Windows, Linux doesn't have KeyGuard equivalent VSM based technology to protect private keys.
This Proof of Concept demonstrates how to use TPM2.0 to protect private keys for a Linux client and utilize it for
TLS1.3 communication.

This PoC implements minimal TLS1.3 manually and TPM2.0 operations using TSS2.0 wrapper.

### Architecture

:::mermaid
sequenceDiagram
    participant Client
    participant TPM as Client TPM
    participant CA
    participant Server
    Client ->> Client: Create CSR
    Client ->> TPM: create_unrestricted_signing_rsa_public
    TPM ->> Client: TPMT_PUBLIC
    Client ->> TPM: create_primary
    TPM ->> Client: KeyHandle
    Client ->> TPM: sign the CSR
    TPM ->> Client: signature (using RSA key generated and stored on TPM)
    Client ->> CA: GetCertificate
    CA ->> Client: Certificate (signed by CA)
    Client ->> Server: ClientHello
    Server ->> Client: ServerHello
    Server ->> Client: ChangeCipherSpec
    Note over Client, Server: All message from now are encrypted
    Server ->> Client: ServerKeyExchange
    Server ->> Client: ServerCertificate
    Server ->> Client: CertificateRequest
    Server ->> Client: ServerHelloDone
    Client ->> Server: ClientCertificate
    Client ->> TPM: sign for CertificateVerify
    TPM ->> Client: signature (using RSA key generated and stored on TPM)
    Client ->> Server: CertificateVerify
    Client ->> Server: Finished
    Server ->> Client: ApplicationData
:::

### Key Takeaways
1. In TLS1.3, the only time the client uses its private key is during CertificateVerify.
2. KeyResumption and PSK can be used to minimize overhead of TPM operations. Thus, it is suitable for non server use cases.


### Build and Run
#### swtpm
```bash
swtpm_setup --tpm-state /tmp --tpm2 --create-platform-cert --display  --create-ek-cert --overwrite
swtpm socket --tpmstate dir=/tmp --ctrl type=tcp,port=2322 --log level=20 --tpm2 --flags not-need-init,startup-clear --server type=tcp,port=2321
```
#### Build Client
```bash
cargo run
```
#### Build Server
```bash 
cd server
cargo run
```
### TODO
Benchmark against firmware TPM.