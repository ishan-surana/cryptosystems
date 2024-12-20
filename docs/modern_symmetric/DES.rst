DES
===

The ``DES`` class implements the Data Encryption Standard, a symmetric-key block cipher that encrypts and decrypts data using a 64-bit key with 8 parity bits, effective to a 56-bit key.

.. class:: DES(key: (str | bytes))

    Creates a new DES instance with the specified key.

    :param key: The 8 byte/character key used for encryption.
    :type key: str | bytes

Introduction
------------

The Data Encryption Standard (DES) is a symmetric-key block cipher that encrypts and decrypts data using an effective 56-bit key. DES operates on 64-bit blocks of data. The algorithm consists of an initial permutation, 16 rounds of processing, and a final permutation. Each round involves expansion, substitution, permutation, and key mixing. DES is a widely used encryption algorithm, but it is considered insecure for modern applications due to its small key size.

Mathematical Details
----------------------

DES Encryption/Decryption Process
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. **Initial Permutation (IP)**: The 64-bit input data block is subjected to an initial permutation defined as:

   .. math::
      P_{\text{initial}} = \text{IP} \cdot \text{Input data}

   where :math:`P_{\text{initial}}` is the 64-bit permuted input.

2. **Rounds**: The DES algorithm performs 16 rounds of processing, each consisting of the following steps:

   .. math::
      :nowrap:
    
      \begin{gather*}
      L_{i+1} = R_i\\
      R_{i+1} = L_i \oplus f(R_i, K_i)
      \end{gather*}

   where:
      - :math:`L_i` and :math:`R_i` are the left and right halves of the data at round :math:`i`,
      - :math:`f(R_i, K_i)` is the round function that involves expansion, substitution, and permutation of :math:`R_i` using subkey :math:`K_i`,
      - :math:`\oplus` denotes the XOR operation.

3. **Final Permutation (FP)**: After the 16 rounds, the left and right halves are swapped and the final permutation is applied:

   .. math::
      P_{\text{final}} = \text{FP} \cdot (R_{16}, L_{16})

   where :math:`P_{\text{final}}` is the final 64-bit encrypted output.

.. note::
    The decryption process is the exact same as the encryption process, however, the round keys are used in reverse order as that in encryption.

Round Function :math:`f`
^^^^^^^^^^^^^^^^^^^^^^^^

The round function :math:`f(R, K)` involves the following steps:

1. **Expansion**: The 32-bit right half :math:`R` is expanded to 48 bits by applying an expansion permutation :math:`E`:

   .. math::
      E(R) \rightarrow 48 \, \text{bits}

2. **Key Mixing**: The expanded 48-bit block is XORed with the round key :math:`K_i` (which is derived from the original 56-bit key):

   .. math::
      E(R) \oplus K_i

3. **Substitution**: The 48-bit result is divided into 8 groups of 6 bits each, and each group is substituted using a predefined substitution box (S-box). The S-box maps 6 bits to 4 bits.

4. **Permutation**: The output of the substitution is permuted using a fixed permutation :math:`P`:

   .. math::
      P(E(R) \oplus K_i) \rightarrow 32 \, \text{bits}

Key Schedule
^^^^^^^^^^^^^

The 56-bit key is divided into two 28-bit halves, which are rotated and permuted over the 16 rounds to generate the 16 subkeys :math:`K_1, K_2, \ldots, K_{16}`. Each subkey is 48 bits long.

Usage
-----

.. code-block:: python

   # Example usage of DES to encrypt and decrypt a message
   from cryptosystems import DES
   cipher = DES("password")  # Example 64-bit key
   ciphertext = cipher.encrypt("Hello World")
   print(ciphertext) # b'\xf4\\V\x1a\xc7S\xb7\xdeZ\xc1\xe9\x14\n\x15Y\xe8'
   plaintext = cipher.decrypt(ciphertext)
   print(plaintext) # 'Hello World'

Methods
-------

.. function:: encrypt(plaintext: str) -> bytes

    Encrypts the given plaintext using DES.

    :param plaintext: The plaintext message to be encrypted.
    :type plaintext: str
    :return: The encrypted ciphertext.
    :rtype: bytes

.. function:: decrypt(ciphertext: bytes) -> str

    Decrypts the given ciphertext using DES.

    :param ciphertext: The ciphertext message to be decrypted.
    :type ciphertext: bytes
    :return: The decrypted plaintext.
    :rtype: str

Notes
-----

- **Key Size**: The key size for DES is 56 bits, which is considered insecure by modern standards.
- **Block Size**: The block size for DES is 64 bits.
- **Security**: DES is vulnerable to brute-force attacks and should not be used for secure communication.
- **Application**: DES is mainly used for educational purposes, cryptographic exercises, and compatibility with legacy systems.
- **Speed**: DES is relatively fast compared to other encryption algorithms, but it is not as fast as many modern algorithms like AES, which have been optimized for performance.
