---
permalink: /
title: "BIP 340 Adaptor Signatures Module for libsecp256k1-zkp: Enhancing Privacy and Functionality in Bitcoin Transactions"
author_profile: true
redirect_from: 
  - /about/
  - /about.html
---

## Introduction

Cryptographic protocols have revolutionized secure transactions and communication. Adaptor Signatures, gaining interest within the Bitcoin community, are especially relevant after the activation of BIP 340 Schnorr signatures with the 2021 Bitcoin Taproot upgrade. Schnorr signatures offer a more efficient and secure alternative to ECDSA, providing enhanced security and privacy.

This project proposes the development of a **BIP 340 Adaptor Signatures Module** for **libsecp256k1-zkp**. The module will implement algorithms for pre-signing, verification, adapting, and extracting adaptors, unlocking new possibilities for applications like the Lightning Network.

![Bitcoin Logo](./images/bitcoin.webp "Bitcoin Logo")

## Overview of Key Algorithms

- **Pre-signing**: Modifies BIP 340 signing to accept an additional elliptic curve point `T`, outputting a pre-signature.
- **Verification**: Verifies pre-signatures by taking a pre-signature and point `T` as arguments.
- **Adaptation**: Transforms pre-signatures into valid BIP 340 signatures.
- **Extraction**: Extracts an adaptor from a pre-signature and a BIP 340 signature.

## Adaptor Signature Scheme

An adaptor signature allows a party to create a signature for a transaction that another party can finalize without revealing private keys. Here's a breakdown:

- **Adaptor signature** `(s', R, T)`: Alice creates this for Bob, who can use it to generate a valid signature without knowing Alice’s private key.
- **R**: A random elliptic curve point used in the signature process.
- **T**: An elliptic curve point sent by Alice, necessary for Bob to finalize the signature.
- **e**: A value computed using the hash `H(R + T || P || m)`.
- **t**: A value extracted by Alice that Bob uses to generate a valid signature.

### Atomic Swap Steps

1. Alice sends Bob the adaptor signature `(s', R, T)`.
2. Bob computes `e = H(R + T || P || m)`.
3. Bob computes the valid signature `s = s' + e*k` and broadcasts it.
4. Alice extracts `t = s - s'`, which Bob uses to generate a valid signature.

### Pre-signing Algorithm

The pre-signing process is similar to BIP 340 but includes the adaptor point `T`.

#### Inputs

- Private key: `p`
- Public key: `P = p * G`
- Message: `m`
- Nonce: `r`
- Adaptor point: `T`

#### Outputs

Pre-signature commitment `(s', R, T)`

#### Steps

1. Calculate `R = r * G`.
2. Calculate `e = H(R || P || m)`.
3. Calculate `s = r + e * p`.
4. Calculate `s' = s - H(R + T || P || m) * r`.
5. Return pre-signature commitment `(s', R, T)`.

Note that this algorithm is almost identical to the BIP 340 signing algorithm, except that
it uses the adaptor point T in step 4 to produce a pre-signature commitment instead of a
valid signature. Also note that the pre-signature commitment includes the adaptor point T,
which is necessary for using the pre-signature in the adaptor signature scheme.

```python
import hashlib
import random

# Curve parameters for secp256k1
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x798E667EF9DCBBAC55A06295CE870807029BFCDB2DCE280959F2815816F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD178448468554199C47D08FFB100488

# Define secp256k1 elliptic curve
secp256k1 = (P, N, Gx, Gy)
curve = EllipticCurve(secp256k1)

# Generate a private key
private_key = random.randint(1, N - 1)

# Compute the public key from the private key
public_key = curve.multiply(Gx, Gy, private_key)

# Define the pre-signing function
def pre_sign(message, T, private_key):
    # Generate a random nonce r
    r = random.randint(1, N - 1)
    # Compute the nonce point R = r*G
    R = curve.multiply(Gx, Gy, r)
    # Compute the Schnorr challenge e = H(R || T || P || m)
    e = int.from_bytes(hashlib.sha256(R.to_bytes() + T.to_bytes() + public_key.to_bytes() + message.encode()).digest(), byteorder='big')
    # Compute the Schnorr signature s = (r + e * private_key) % N
    s = (r + e * private_key) % N
    # Return the pre-signature as a tuple (s, R, T)
    return (s, R, T)

# Test the pre-signing function
message = "Hello, World!"
T = curve.multiply(Gx, Gy, random.randint(1, N - 1))
pre_signature = pre_sign(message, T, private_key)
print("Pre-signature:", pre_signature)
```

### Verification Algorithm

Verifies a pre-signature.

#### Inputs

- Pre-signature `(s', R, T)`
- Public key `P`
- Message `m`

#### Steps

1. Compute the Schnorr challenge `e = H(R || T || P || m)`.
2. Calculate `U = s' * G - e * T`.
3. Calculate `V = R + e * P`.
4. Return `True` if `U == V`, else `False`.

Sample Implementation:

```python
import hashlib

# Verify a pre-signature with a given point T
def verify_pre_signature(pre_signature, T, public_key, message):
    # Unpack the pre-signature tuple
    s_prime, R, T_prime = pre_signature

    # Compute the Schnorr challenge e = H(R || T || P || m)
    e = int.from_bytes(hashlib.sha256(R.to_bytes() + T.to_bytes() + public_key.to_bytes() + message.encode()).digest(), byteorder='big')

    # Compute the check points U = s'*G - e*T and V = R + e*P
    U = curve.subtract(curve.multiply(Gx, Gy, s_prime), curve.multiply(T.x, T.y, e))
    V = curve.add(R, curve.multiply(public_key.x, public_key.y, e))

    # Check if U = V
    return U == V

# Test the verification function with the pre-signature and point T generated earlier
message = "Hello, World!"
public_key = curve.multiply(Gx, Gy, private_key)
valid = verify_pre_signature(pre_signature, T, public_key, message)

print("Pre-signature verification:", valid)
```

### Adapt Algorithm

Converts a pre-signature into a valid BIP 340 signature.

#### Inputs

- Pre-signature `(R, s, e)`
- Adaptor `t`

#### Outputs

BIP 340 signature `(R', s')`

#### Steps

1. Calculate `R' = R + t*G`.
2. Calculate `e' = H(R' || P || m)`.
3. Calculate `s' = (s + e' * t) mod n`.
4. Return `(R', s')` as the BIP 340 signature sig.

Sample Implementation:

```python
import hashlib

# Adapt a pre-signature with a given point T
def adapt(pre_sig, t):
    # Extract the values from the pre-signature tuple
    R, s, e = pre_sig

    # Calculate the adapted nonce point R' = R + t*G
    curve = secp256k1  # Curve parameters for secp256k1
    Gx, Gy = curve[2], curve[3]  # Base point coordinates
    R_prime = curve.add(R, curve.multiply(Gx, Gy, t))

    # Calculate the adapted challenge e' = H(R' || P || m)
    P = curve.multiply(Gx, Gy, private_key)  # Public key corresponding to the private key used to sign the message
    m = "Hello, World!"  # The message that was signed
    e_prime = int.from_bytes(hashlib.sha256(R_prime.to_bytes() + P.to_bytes() + m.encode()).digest(), byteorder='big')

    # Calculate the adapted signature s' = (s + e'*t) mod n
    n = curve[1]  # Order of the secp256k1 curve
    s_prime = (s + e_prime * t) % n

    # Return the adapted signature as a tuple (R', s')
    return (R_prime, s_prime)
```

### Extract Adaptor Algorithm

Extracts the adaptor `t`.

#### Inputs

- Pre-signature `(R, s', T)`
- BIP 340 signature `(R, s)`

### Output

An adaptor t, which is a scalar value such that t*G = T (where G is the secp256k1
base point).

#### Steps

1. Compute `s = s' + e*(t - t') mod n`, where n is the order of the secp256k1 curve and
e is the Schnorr challenge derived from R, P, and m.
2. Compute `R' = R + t*G and R'' = R + t'*G`.
3. If `R = R', return t`.
4. If `R = R'', return t'`.
5. Otherwise, raise an error indicating that the BIP 340 signature and the
pre-signature are not compatible.

Note that the function assumes that the pre-signature and the BIP 340 signature are valid
and were created using the same message and public key. If these assumptions do not
hold, the function may not return a valid adaptor.

Sample implementation:

```python
import hashlib

def extract_adaptor(pre_sig, sig):
    # Extract values from the pre-signature and signature tuples
    R, s_prime, T = pre_sig
    R_sig, s_sig = sig

    # Calculate the challenge e
    P = curve.multiply(Gx, Gy, private_key)  # Public key corresponding to the private key used to sign the message
    e = int.from_bytes(hashlib.sha256(R.to_bytes() + T.to_bytes() + P.to_bytes() + message.encode()).digest(), byteorder='big')

    # Calculate R_prime and R_doubleprime
    R_prime = curve.add(R, curve.multiply(Gx, Gy, t))
    R_doubleprime = curve.add(R, curve.multiply(Gx, Gy, t_prime))

    # Check if R_prime or R_doubleprime matches R_sig
    if R == R_prime:
        return t
    elif R == R_doubleprime:
        return t_prime
    else:
        raise ValueError("BIP 340 signature and pre-signature are not compatible.")
```

## Future Deliveries

Once the module is completed, developers may create new tools and applications that utilize BIP 340 adaptor signatures to enable new use cases and improve the overall functionality and privacy of the Bitcoin ecosystem. I intend to pursue new ways to further improve and maintain the privacy of the Bitcoin ecosystem.

## Benefits to the Community

1. **Improved privacy:** Adaptor signatures can enable more private atomic swaps and Point Time Lock Contracts (PTLCs) in the Lightning Network.
2. **Reduced transaction size:** Adaptor signatures can reduce the size of transactions, leading to lower fees and improved scalability.
3. **Improved security:** BIP 340 signatures are more secure than the currently used ECDSA signatures, and the use of adaptor signatures can further improve security by reducing the risk of certain attacks.
4. **Innovation:** The development of adaptor signatures for BIP 340 can open up new possibilities for Bitcoin/crypto applications and use cases.

Overall, the BIP 340 Adaptor Signatures Module has the potential to enhance the privacy, security, and scalability of the Bitcoin/crypto ecosystem, while also promoting innovation and advancing the state-of-the-art in cryptography.


### About Me

Hi, I'm Victor. I am a passionate software engineer with a an interest in blockchain technology and cryptocurrency. My recent work includes contributing to the BIP 340 Adaptor Signatures module for libsecp256k1-zkp, where I have been working on enhancing cryptographic protocols. With a background in full-stack development and a keen interest in security and decentralized systems, I aim to drive innovation in the blockchain space