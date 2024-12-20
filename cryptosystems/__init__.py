"""
`cryptosystems` module
====================
The `cryptosystems` module provides classes and functions for various symmetric and asymmetric cryptosystems. It includes the following classes:
- SYMMETRIC CIPHERS (Basic Cryptosystems):
    + **AdditiveCipher**: A class for the Additive Cipher.
    + **MultiplicativeCipher**: A class for the Multiplicative Cipher.
    + **AffineCipher**: A class for the Affine Cipher.
    + **HillCipher**: A class for the Hill Cipher.
    + **VigenereCipher**: A class for the Vigenere Cipher.
    + **PlayfairCipher**: A class for the Playfair Cipher.
    + **AutokeyCipher**: A class for the Autokey Cipher.

- SYMMETRIC CIPHERS (Modern Cryptosystems):
    + **DES**: A class for the Data Encryption Standard (DES). Provides methods for encryption and decryption. Only ECB mode is supported.
    + **AES**: A class for the Advanced Encryption Standard (AES). Provides methods for encryption and decryption. Supports key sizes of 128, 192, and 256 bits. Only ECB mode is supported.

- ASYMMETRIC CIPHERS:
    + **RSA**: A class for the RSA cryptosystem. Provides methods for key encryption, decryption, signature generation, and signature verification.
    + **ElGamal**: A class for the ElGamal cryptosystem. Provides methods for encryption, decryption, signature generation, and signature verification.
    + **Rabin**: A class for the Rabin cryptosystem. Provides methods for encryption, decryption, signature generation, and signature verification.
    + **Paillier**: A class for the Paillier cryptosystem. Provides methods for encryption, decryption, signature generation, and signature verification.
    + **DiffieHellman**: A class for the Diffie-Hellman key exchange protocol. Provides methods for generating public and private keys, and deriving shared secrets.
    + **ECC**: A class for the Elliptic Curve Cryptography (ECC). Provides methods for encryption, decryption, signature generation, and signature verification.

- HASH FUNCTIONS:
    + **MD5**: A class for the MD5 hash function.
    + **SHA256**: A class for the SHA-256 hash function.

The module also includes the following functions in the `functions` submodule:
- **getRandomInteger**: Generate a random integer of N bits.
- **getRandomRange**: Generate a random number N such that a <= N < b.
- **isPrime**: Test if a number is prime, using the Miller-Rabin test.
- **getPrime**: Return a random N-bit prime number.
"""

import sys
sys.set_int_max_str_digits(0)
from .functions import *
from .classical_symmetric import *
from .modern_symmetric import *
from .asymmetric import *
from .key_exchange import *
from .hash_functions import *