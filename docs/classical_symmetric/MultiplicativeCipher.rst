MultiplicativeCipher
====================

The ``MultiplicativeCipher`` class implements the Multiplicative Cipher, a type of monoalphabetic substitution cipher where each character is mapped to another by multiplying with a specified integer key.

.. class:: MultiplicativeCipher(key: int)

   Creates a new MultiplicativeCipher instance with the specified key.
   
   :param key: The integer by which each letter in the plaintext is multiplied. The key must be coprime with 26. Valid values are between 1 and 25.
   :type key: int

.. attention::

   MultiplicativeCipher is a basic symmetric cipher, which should be used ONLY for educational purposes, and NOT in production. Proceed accordingly.

Introduction
-------------
The Multiplicative Cipher is a variant of the Caesar Cipher, but instead of a simple shift, each letter in the plaintext is substituted by another letter in the alphabet, where the substitution is determined by multiplying the position of each letter in the alphabet by a key, and then reducing the result modulo 26. This method provides a stronger cipher compared to the Additive Cipher but is still vulnerable to frequency analysis.

Mathematical Details
--------------------
In the Multiplicative Cipher:

- Each letter in the alphabet is mapped to a numeric value.

- The encryption formula is:
   .. math::

      c = (p \times k) \mod 26

   where:
     - :math:`c` is the ciphertext letter,
     - :math:`p` is the plaintext letter,
     - :math:`k` is the key (multiplicative factor).

- Decryption reverses this multiplication with the formula:
   .. math::

      p = (c \times k^{-1}) \mod 26

   where :math:`k^{-1}` is the modular multiplicative inverse of :math:`k` modulo 26, which exists only if :math:`k` and 26 are coprime.

Usage
-----
.. code-block:: python
     
   # Example usage of Multiplicative Cipher to encrypt and decrypt a message
   from cryptosystems import MultiplicativeCipher
   cipher = MultiplicativeCipher(7)
   ciphertext = cipher.encrypt("Hello World")
   print(ciphertext) # 'Czggj Rjmgy'
   plaintext = cipher.decrypt(ciphertext)
   print(plaintext) # 'Hello World'

Methods
-------

.. function:: encrypt(plaintext: str) -> str

   Encrypts the plaintext using the Multiplicative Cipher.

   :param plaintext: The text to be encrypted.
   :type plaintext: str
   :return: The encrypted ciphertext.
   :rtype: str

.. function:: decrypt(ciphertext: str) -> str

   Decrypts the ciphertext using the Multiplicative Cipher.

   :param ciphertext: The text to be decrypted.
   :type ciphertext: str
   :return: The decrypted plaintext.
   :rtype: str

Notes
-----
- **Limitations**: The Multiplicative Cipher only works if the key is coprime with 26 (i.e., the greatest common divisor of the key and 26 is 1). It also does not encrypt spaces, punctuation, or numbers.
- **Security**: The Multiplicative Cipher provides a stronger encryption than the Additive Cipher but is still not secure against modern cryptanalysis techniques such as frequency analysis.
- **Application**: Suitable for educational purposes or basic encoding systems, but not recommended for secure communications.
