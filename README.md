# double_ratchet


This project demonstrates a simplified implementation of the **Double Ratchet Algorithm**, which is the core cryptographic mechanism behind end-to-end encrypted messaging protocols like Signal. It combines the **X3DH (Extended Triple Diffie-Hellman)** key exchange with symmetric key ratcheting to ensure forward secrecy and post-compromise security.

---

## Overview

The Double Ratchet Algorithm ensures secure communication between two parties (Alice and Bob) by:

1. **X3DH Key Exchange**: Establishing an initial shared secret key using Diffie-Hellman key exchange with long-term, ephemeral, and one-time keys.
2. **DH Ratchet**: Periodically rotating the Diffie-Hellman keys to derive new shared secrets.
3. **Symmetric Ratchet**: Using HKDF-based symmetric ratchets to derive new encryption keys for each message.

The implementation includes the following components:
- **Alice and Bob Classes**: Representing two participants in the protocol.
- **Symmetric Ratchet**: Key derivation using HKDF to generate encryption keys and IVs.
- **AES-CBC Encryption**: Encrypting and decrypting messages with PKCS7 padding.

---

## Features

- **X3DH Key Exchange**: Establishes a shared key between two users securely.
- **Double Ratchet Algorithm**: Ensures forward secrecy and security against key compromise.
- **Symmetric Encryption**: Uses AES-CBC for encrypting messages with derived keys.
- **Key Management**: Secure generation and management of long-term, ephemeral, and one-time keys.

---

## Prerequisites

To run this project, ensure you have the following:

- Python 3.8+
- Required libraries:

Install dependencies via pip:
```bash
pip install cryptography pycryptodome
```



## Usage

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/double-ratchet-demo.git
   cd double-ratchet-demo
   ```

2. Run the script:
   ```bash
   python double_ratchet_demo.py
   ```

3. Observe the key exchange, ratcheting, and encrypted communication between Alice and Bob in the output:

Example output:
```
[Alice]	Shared key: ...
[Bob]	Shared key: ...
[Alice]	Send ratchet seed: ...
[Alice]	Sending ciphertext to Bob: ...
[Bob]	Decrypted message: Hello Bob!
...
```

---

## How It Works

### 1. **X3DH Key Exchange**
Alice and Bob generate multiple keys:
- Long-term Identity Keys (IK)
- Signed Pre-Keys (SPK)
- Ephemeral Keys (EK)
- One-Time Pre-Keys (OPK)

They perform multiple DH exchanges to derive a shared secret key.

### 2. **Root and Symmetric Ratchets**
- A **root ratchet** derives new seeds for the send and receive ratchets.
- The **symmetric ratchets** generate keys and IVs for AES encryption.

### 3. **DH Ratchet**
Each time Alice or Bob sends/receives a message, a DH key rotation occurs to derive new shared secrets, ensuring forward secrecy.

### 4. **Message Encryption**
- AES-CBC is used for encrypting messages.
- PKCS7 padding ensures the plaintext aligns with AES block size.

---

## Security Features

- **Forward Secrecy**: Compromise of one key does not reveal past messages.
- **Post-Compromise Security**: New keys are derived after each message exchange, limiting the impact of key compromise.
- **Message Integrity**: Ensured through proper encryption and key management.

---

## Limitations

- This is a simplified demonstration of the Double Ratchet Algorithm.
- It does not include message authentication or additional protections implemented in real-world protocols.

---

## References

- [Signal Protocol Whitepaper](https://signal.org/docs/)
- [Double Ratchet Algorithm - Technical Details](https://signal.org/docs/specifications/doubleratchet/)
- [X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)

---


Feel free to contribute or provide feedback!
