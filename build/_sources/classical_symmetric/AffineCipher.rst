AffineCipher
============

The ``AffineCipher`` class implements the Affine cipher, a type of monoalphabetic substitution cipher. The Affine cipher is a combination of the Additive and Multiplicative ciphers, having two keys: one for addition and one for multiplication.

.. class:: AffineCipher(a: int, b: int)

    Creates a new AffineCipher instance with the specified keys.

    :param a: The multiplicative key. Must be coprime with 26.
    :type a: int
    :param b: The additive key.
    :type b: int

.. attention::

   AffineCipher is a basic symmetric cipher, which should be used ONLY for educational purposes, and NOT in production. Proceed accordingly.

Introduction
------------
The Affine cipher is a type of monoalphabetic substitution cipher. It is a combination of the Additive and Multiplicative ciphers, having two keys: one for addition and one for multiplication. Each character in the plaintext is shifted by a fixed number of positions based on the given keys, first by multiplication and then by addition. This creates a more complex encryption than either multiplicative or additive ciphers alone.

Mathematical Details
--------------------
In the Affine cipher:

- Each letter in the alphabet is mapped to a numeric value.

- The encryption formula is:
    .. math::

       c = (a \times p + b) \mod 26

    where:
     - :math:`c` is the ciphertext letter value
     - :math:`p` is the plaintext letter value  
     - :math:`a` is the multiplicative key (must be coprime with 26)
     - :math:`b` is the additive key

- The decryption formula is:
    .. math::

       p = a^{-1}(c - b) \bmod 26

    where
     - :math:`a^{-1}` is the modular multiplicative inverse of :math:`a` modulo 26.

.. note::

    The keys :math:`a` and :math:`b` must be coprime with 26 for the Affine cipher to work correctly. If the keys are not coprime, the decryption process may not be possible.

Usage
-----

.. code-block:: python

   # Example usage of Affine Cipher to encrypt and decrypt a message
   from cryptosystems import AffineCipher
   cipher = AffineCipher(5, 8)
   ciphertext = cipher.encrypt("Hello World")
   print(ciphertext) # 'Rclla Oaplx'
   plaintext = cipher.decrypt(ciphertext)
   print(plaintext) # 'Hello World'

Methods
-------

.. function:: encrypt(plaintext: str) -> str

    Encrypts the given plaintext using the Affine cipher.

    :param plaintext: The plaintext message to be encrypted.
    :type plaintext: str
    :return: The encrypted ciphertext.
    :rtype: str

.. function:: decrypt(ciphertext: str) -> str
    
    Decrypts the given ciphertext using the Affine cipher.
    
    :param ciphertext: The ciphertext message to be decrypted.
    :type ciphertext: str
    :return: The decrypted plaintext.
    :rtype: str

Notes
-----

- **Multiplicative Inverse**: The multiplicative key :math:`a` must have a multiplicative inverse modulo 26 for decryption to work correctly (ie, :math:`a` should be coprime with 26). This is because the decryption formula involves multiplying by the inverse of the key modulo 26. If the key does not have a multiplicative inverse, decryption will not be possible.
- **Limitations**: The Affine cipher can only encrypt and decrypt letters of the alphabet. It does not handle spaces, punctuation, or other characters. The keys :math:`a` and :math:`b` must be integers between 0 and 25.
- **Security**: The Affine cipher is relatively weak compared to modern encryption methods and can be easily broken using frequency analysis or brute force methods.
- **Application**: Suitable for educational purposes, but not secure for practical use in modern cryptography.
