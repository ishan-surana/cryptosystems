AdditiveCipher
==============

The ``AdditiveCipher`` class implements the Additive Cipher, a type of monoalphabetic substitution cipher that shifts each character by a addding with a specified integer key.

.. class:: AdditiveCipher(key: int)

   Creates a new AdditiveCipher instance with the specified key.
   
   :param key: The integer by which each letter in the plaintext is shifted. Valid values are between 0 and 25.
   :type key: int

Introduction
-------------
The Additive Cipher (also known as the Caesar Cipher) is one of the oldest known encryption techniques. Each character in the plaintext is shifted by a fixed number of positions based on a given key. Although easy to implement, this cipher is insecure for practical use since it is easily broken by frequency analysis.

Mathematical Details
--------------------
In the Additive Cipher:

- Each letter in the alphabet is mapped to a numeric value.

- The encryption formula is:
   .. math::

      c = (p + k) \mod 26

   where:
     - :math:`c` is the ciphertext letter,
     - :math:`p` is the plaintext letter,
     - :math:`k` is the key (shift amount).

- Decryption reverses this shift with the formula:
   .. math::

      p = (c - k) \mod 26

Usage
-----

.. code-block:: python
   
   # Example usage of Additive Cipher to encrypt and decrypt a message
   from cryptosystems import AdditiveCipher
   cipher = AdditiveCipher(3)
   ciphertext = cipher.encrypt("Hello World")
   print(ciphertext) # 'Khosk Zruog'
   plaintext = cipher.decrypt(ciphertext)
   print(plaintext) # 'Hello World'

Methods
-------

.. function:: encrypt(plaintext: str) -> str

   Encrypts the plaintext using the Additive Cipher.

   :param plaintext: The text to be encrypted.
   :type plaintext: str
   :return: The encrypted ciphertext.
   :rtype: str

.. function:: decrypt(ciphertext: str) -> str

   Decrypts the ciphertext using the Additive Cipher.

   :param ciphertext: The text to be decrypted.
   :type ciphertext: str
   :return: The decrypted plaintext.
   :rtype: str

Notes
-----

- **Limitations**: The Additive Cipher operates on the letters of the alphabet. It does not encrypt spaces, punctuation, or numbers. The key must be an integer between 0 and 25.
- **Security**: The Additive Cipher is not secure for practical. The Additive Cipher is vulnerable to frequency analysis, making it unsuitable for secure communications.
- **Application**: Suitable for educational purposes or very basic encoding.