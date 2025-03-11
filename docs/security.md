# Security

This document outlines the cryptographic methods used in the RelaySMS Vault. All cryptographic operations are defined in the [`crypto.py`](../src/crypto.py) file.

## Cryptographic Methods

### AES Encryption

**Advanced Encryption Standard (AES)** is used for secure data storage.

- **Key Size**: 256 bits (32 bytes)
- **Mode of Operation**: AES-EAX
- **Purpose**: Encrypts and decrypts data at rest.
- **Reference**: [NIST AES Specification](https://www.nist.gov/publications/advanced-encryption-standard-aes)

### HMAC for Integrity Verification

**Hash-based Message Authentication Code (HMAC)** ensures data integrity.

- **Algorithm**: SHA-512
- **Key Size**: 256 bits (32 bytes)
- **Purpose**: Verifies data authenticity.
- **Reference**: [RFC 2104 - HMAC](https://datatracker.ietf.org/doc/html/rfc2104)

### Fernet Encryption

**Fernet encryption** is used for token encryption.

- **Key Size**: 256 bits (32 bytes)
- **Purpose**: Encrypts and decrypts identity tokens.
- **Reference**: [Fernet Cryptography Documentation](https://cryptography.io/en/latest/fernet/)

### Message Encryption

**Signal Double Ratchet Algorithm** encrypts and decrypts messages.

- **Key Exchange**: X25519 public key exchange.
- **Algorithm**: Double Ratchet for message encryption.
- **Purpose**: Secures message transmission.
- **Reference**: [Signal Protocol Documentation](https://signal.org/docs/specifications/doubleratchet/)
