PlayfairCipher
===============

The ``PlayfairCipher`` class implements the Playfair cipher, a classical digraph cipher that encrypts pairs of letters (digraphs) using a 5x5 matrix of letters as the key.

.. class:: PlayfairCipher(key: str)

    Creates a new PlayfairCipher instance with the specified keyword.

    :param key: The keyword used to generate the 5x5 key matrix. 
                Non-letter characters are ignored, and duplicates are removed.
    :type key: str

Introduction
------------
The Playfair cipher is a classical substitution cipher that encrypts pairs of letters (digraphs) rather than individual letters. It was invented by Charles Wheatstone in 1854 and was later popularized by the British during World War I. The cipher uses a 5x5 matrix containing letters of the alphabet (usually omitting 'J'). Each pair of plaintext letters is substituted with letters from the matrix according to a set specific rule.

Mathematical Details
--------------------
In the Playfair cipher:

- A 5x5 key matrix is created using a keyword.

- The plaintext is divided into digraphs (pairs of letters).

- **The encryption rules are:**

  1. If both letters are the same (or only one letter remains), insert a filler letter (commonly 'X') between them.
  2. If the letters appear in the same row, replace them with the letters to their immediate right (wrapping around to the beginning of the row if necessary).
  3. If the letters appear in the same column, replace them with the letters immediately below (wrapping around to the top of the column if necessary).
  4. If the letters are in different rows and columns, replace them with the letters in the same row but in the column of the other letter of the pair.

- **The decryption is the reverse of the encryption process.**

.. note::

    In the implementation of Playfair Cipher, the letter 'J' as replaced with 'I' wherever encountered. Therefore, the encryption and decryption will work as expected for plaintext and key without the letter 'J', however there may be some deviations wherever J is encountered.

Usage
-----
.. code-block:: python

    # Example usage of Playfair Cipher to encrypt and decrypt a message
    from cryptosystems import PlayfairCipher
    cipher = PlayfairCipher("key")
    ciphertext = cipher.encrypt("Hello World")
    print(ciphertext) # 'Dahak Ldskn'
    plaintext = cipher.decrypt(ciphertext)
    print(plaintext) # 'Hello World'

Methods
-------
.. function:: encrypt(plaintext: str) -> str

    Encrypts the given plaintext using the Playfair cipher.

    :param plaintext: The plaintext message to be encrypted.
    :type plaintext: str
    :return: The encrypted ciphertext.
    :rtype: str

.. function:: decrypt(ciphertext: str) -> str

    Decrypts the given ciphertext using the Playfair cipher.

    :param ciphertext: The ciphertext message to be decrypted.
    :type ciphertext: str
    :return: The decrypted plaintext.
    :rtype: str

Notes
-----
- **Key Matrix**: The Playfair cipher uses a 5x5 matrix of letters. The matrix is filled by using the keyword followed by the remaining letters of the alphabet (typically 'J' is omitted or merged with 'I').
- **Padding**: If the plaintext length is odd, a filler character ('X') is added at the end to complete the final digraph.
- **Security**: While stronger than simple substitution ciphers like Additive, Multiplicative or Affine, the Playfair cipher is still vulnerable to frequency analysis, especially when a short keyword is used.
- **Application**: The Playfair cipher is often used for educational purposes and cryptographic exercises, but it is not considered secure for modern use.
