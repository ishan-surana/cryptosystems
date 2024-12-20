AES
===

The ``AES`` class implements the Advanced Encryption Standard, a symmetric-key block cipher that encrypts and decrypts data using key sizes of 128, 192, or 256 bits.

.. class:: AES(key: (str | bytes))

    Creates a new AES instance with the specified key.

    :param key: The key used for encryption, which can be 16, 24, or 32 bytes long.
    :type key: str | bytes

Introduction
------------

The Advanced Encryption Standard (AES) is a symmetric-key block cipher that encrypts and decrypts data in 128-bit blocks using key sizes of 128, 192, or 256 bits. AES operates through multiple rounds of processing based on the selected key size. The algorithm involves substitution, permutation, and mixing of data. AES is widely used and considered secure for modern applications, replacing older encryption algorithms like DES due to its larger key size and robustness against attacks.

Mathematical Details
----------------------

AES Encryption/Decryption Process
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. **Key Expansion**: The AES key is expanded into an array of key schedule words, which are used in each round. The number of round keys depends on the key size:

   - For a 128-bit key, there are 10 rounds.
   - For a 192-bit key, there are 12 rounds.
   - For a 256-bit key, there are 14 rounds.

   The expanded key is derived as follows:

   .. math::
      K_{i} = \text{Key Expansion}(K_0) \quad \text{for} \quad i = 1, 2, \ldots

2. **Initial Round**: The input data block is XORed with the first round key.

.. math::
    P_{\text{initial}} = \text{Input data} \oplus K_0

3. **Rounds**: AES performs multiple rounds depending on the key size (10, 12, or 14). Each round involves the following operations:

   1. **SubBytes**: Each byte in the state is substituted using the S-box, :math:`S`.   
   2. **ShiftRows**: The rows of the state are cyclically shifted by a certain number of positions.   
   3. **MixColumns**: The columns of the state are mixed using a fixed matrix.   
   4. **AddRoundKey**: The round key is XORed with the state.

4. **Final Round**: The final round skips the MixColumns step and only involves SubBytes, ShiftRows, and AddRoundKey.

.. math::
    P_{\text{final}} = \text{State after final round}

.. note::
    The decryption process is the similar to the encryption process but uses inverse of the operations, denoted by prefix ``Inv`` before the operation name.

Round Function
^^^^^^^^^^^^^^^

The round function for AES involves the following steps:

1. **SubBytes**: Each byte of the state is substituted using the S-box, :math:`S`:

.. math::
  S_{\text{state}} = S(\text{state})

2. **ShiftRows**: The rows of the state are cyclically shifted. If we represent the state as a 4x4 matrix :math:`\text{State} = [s_{ij}]` where `i` is the row index and `j` is the column index, the rows are shifted as follows:

- First row remains unchanged.
- Second row is shifted by 1 byte to the left.
- Third row is shifted by 2 bytes to the left.
- Fourth row is shifted by 3 bytes to the left.

For example, if the initial state matrix is:

.. math::
   \text{State} =
   \begin{bmatrix}
   s_{00} & s_{01} & s_{02} & s_{03} \\
   s_{10} & s_{11} & s_{12} & s_{13} \\
   s_{20} & s_{21} & s_{22} & s_{23} \\
   s_{30} & s_{31} & s_{32} & s_{33}
   \end{bmatrix}

After **ShiftRows**:

.. math::
   \text{State} =
   \begin{bmatrix}
   s_{00} & s_{01} & s_{02} & s_{03} \\
   s_{11} & s_{12} & s_{13} & s_{10} \\
   s_{22} & s_{23} & s_{20} & s_{21} \\
   s_{33} & s_{30} & s_{31} & s_{32}
   \end{bmatrix}

3. **MixColumns**: This step provides diffusion by mixing the columns of the state matrix. Each column of the state is treated as a polynomial over :math:`GF(2^8` (the finite field of 256 elements).

Each column is multiplied by a fixed matrix:

.. math::
   \text{MixColumn Matrix} =
   \begin{bmatrix}
   2 & 3 & 1 & 1 \\
   1 & 2 & 3 & 1 \\
   1 & 1 & 2 & 3 \\
   3 & 1 & 1 & 2
   \end{bmatrix}

The multiplication is performed in :math:`GF(2^8)` field, where numbers are represented as polynomials with coefficients in the field. The multiplication of the state column vector :math:`C = [c_0, c_1, c_2, c_3]^T` with the MixColumn matrix is done by performing finite field multiplications and additions. Each element of the resulting column is computed as a sum of the individual field multiplications.

For example, for the first element of the new column:

.. math::
   c_0' = \text{Multiply}(2, c_0) \oplus \text{Multiply}(3, c_1) \oplus \text{Multiply}(1, c_2) \oplus \text{Multiply}(1, c_3)

where :math:`\text{Multiply}(a, b)` denotes the multiplication of :math:`a` and :math:`b` in the finite field :math:`GF(2^8)`.

4. **AddRoundKey**: The round key is XORed with the state:

.. math::
   S_{\text{state}} \oplus K_i = \text{State after round i}

Key Schedule
^^^^^^^^^^^^^

AES uses a key expansion algorithm to generate a set of round keys from the original key. For each round, a round key is XORed with the state in the AddRoundKey step.

Usage
-----

.. code-block:: python

    # Example usage of AES to encrypt and decrypt a message
    from cryptosystems import AES
    cipher = AES("passwordpassword")  # Example 256-bit key
    ciphertext = cipher.encrypt("Hello World")
    print(ciphertext)  # b'\x97\x89\xab\xde\xfa\x2a\x1c\xd9\xb0\xa5\x96\x4c\xf4\xfc\x45\x59'
    plaintext = cipher.decrypt(ciphertext)
    print(plaintext)  # 'Hello World'

Methods
-------

.. function:: encrypt(plaintext: str) -> bytes

    Encrypts the given plaintext using AES.

    :param plaintext: The plaintext message to be encrypted.
    :type plaintext: str
    :return: The encrypted ciphertext.
    :rtype: bytes

.. function:: decrypt(ciphertext: bytes) -> str

    Decrypts the given ciphertext using AES.

    :param ciphertext: The ciphertext message to be decrypted.
    :type ciphertext: bytes
    :return: The decrypted plaintext.
    :rtype: str

Notes
-----
- **Key Size**: AES supports key sizes of 128, 192, or 256 bits, providing strong security.
- **Block Size**: AES operates on 128-bit blocks.
- **Security**: AES is considered secure against all known practical attacks and is widely used for securing sensitive data.
- **Application**: AES is used in a variety of applications, including securing communications, data storage, and financial transactions.
- **Speed**: AES is highly efficient and fast compared to older encryption algorithms like DES.
