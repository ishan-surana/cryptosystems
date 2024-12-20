HillCipher
==========

The ``HillCipher`` class implements the Hill cipher, a polygraphic substitution cipher that uses linear algebra to encrypt and decrypt messages by manipulating blocks of letters.

.. class:: HillCipher(key_matrix: list)

   Creates a new HillCipher instance with the specified key matrix.

   :param key_matrix: The key matrix used for encryption. Must be square and invertible modulo 26.
   :type key_matrix: list of lists (2x2 or 3x3 matrix)

Introduction
------------
The Hill cipher is a classical polygraphic substitution cipher that encrypts blocks of text using matrix multiplication. The cipher operates on groups of letters rather than individual letters, making it more resistant to frequency analysis than traditional monoalphabetic ciphers. The encryption and decryption processes involve matrix operations with a key matrix, providing a more complex and secure method of encryption compared to simpler ciphers.

Mathematical Details
--------------------
In the Hill cipher:

- The plaintext is divided into blocks of fixed size (typically 2x2 or 3x3 matrices).

- Each block of plaintext is represented as a vector of numbers (corresponding to the letters).

- The encryption formula is:
   .. math::

      C = K \times P \mod 26

   where:
     - :math:`C` is the ciphertext block,
     - :math:`P` is the plaintext block,
     - :math:`K` is the key matrix.

- The decryption formula is:
   .. math::

      P = K^{-1} \times C \mod 26

   where :math:`K^{-1}` is the modular inverse of the key matrix :math:`K` modulo 26.

.. note::

    The key matrix :math:`K` must be invertible modulo 26 for the Hill cipher to work correctly. If the key matrix is not invertible, decryption will not be possible.

Usage
-----

.. code-block:: python

   # Example usage of Hill Cipher to encrypt and decrypt a message
   from cryptosystems import HillCipher
   cipher = HillCipher([[3, 3], [2, 5]])
   ciphertext = cipher.encrypt("HelloWorld")
   print(ciphertext) # 'HiozeIpjql'
   plaintext = cipher.decrypt(ciphertext)
   print(plaintext) # 'HelloWorld'

Methods
-------

.. function:: encrypt(plaintext: str) -> str

    Encrypts the given plaintext using the Hill cipher.

    :param plaintext: The plaintext message to be encrypted.
    :type plaintext: str
    :return: The encrypted ciphertext.
    :rtype: str

.. function:: decrypt(ciphertext: str) -> str

    Decrypts the given ciphertext using the Hill cipher.

    :param ciphertext: The ciphertext message to be decrypted.
    :type ciphertext: str
    :return: The decrypted plaintext.
    :rtype: str

Notes
-----

- **Key Matrix**: The key matrix :math:`K` must be square (i.e., have the same number of rows and columns) and invertible modulo 26. If the matrix is not invertible, decryption will not be possible.
- **Limitations**: The Hill cipher operates on blocks of letters. The length of the plaintext must be a multiple of the block size (e.g., for a 2x2 matrix, the plaintext should have an even number of letters). If the plaintext length is not a multiple of the block size, padding is required.
- **Security**: The Hill cipher is stronger than simple monoalphabetic ciphers and can be harder to break using frequency analysis. However, it is still vulnerable to more advanced cryptanalysis techniques, especially if the key is known or guessed.
- **Application**: The Hill cipher is suitable for educational purposes, cryptographic exercises, and learning about linear algebra's role in encryption. However, it is not secure for modern use.
