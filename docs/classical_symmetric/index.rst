Classical Symmetric Cryptosystems
=================================

This is the index file for the classical symmetric cryptosystems. The classical symmetric cryptosystems are implemented in the ``classical_symmetric`` submodule and can be imported directly from the package.

--------------
Introduction
--------------

Classical symmetric cryptosystems are the oldest form of encryption systems. They are based on the concept of a shared secret key between the sender and the receiver. The key is used to encrypt and decrypt the message. The classical symmetric cryptosystems are computationally inexpensive and generally faster than the modern asymmetric cryptosystems, but they have the disadvantage of requiring the sender and the receiver to share the secret key. If the key is compromised, the security of the system is compromised. The basic types of classical symmetric cryptosystems are:

- **Substitution Cipher**: In a substitution cipher, each letter in the plaintext is replaced with another letter according to a fixed rule.

  - **Monoalphabetic Substitution Cipher**: In a monoalphabetic substitution cipher, each letter in the plaintext is replaced with a fixed letter in the ciphertext. The same letter is always replaced with the same letter.
  - **Polyalphabetic Substitution Cipher**: In a polyalphabetic substitution cipher, each letter in the plaintext is replaced with a different letter according to a fixed rule. The rule may change depending on the position of the letter in the plaintext.

- **Transposition Cipher**: In a transposition cipher, the letters of the plaintext are rearranged according to a fixed rule. The order of the letters is changed, but the letters themselves are not changed.

--------------
Usage Examples
--------------
.. tab-set::

    .. tab-item:: Additive

        .. code-block:: python
                
            # Example usage of Additive Cipher to encrypt and decrypt a message
            from cryptosystems import AdditiveCipher
            cipher = AdditiveCipher(3)
            ciphertext = cipher.encrypt("Hello World")
            print(ciphertext) # 'Khosk Zruog'
            plaintext = cipher.decrypt(ciphertext)
            print(plaintext) # 'Hello World'
                
    .. tab-item:: Multiplicative
            
        .. code-block:: python
                    
            # Example usage of Multiplicative Cipher to encrypt and decrypt a message
            from cryptosystems import MultiplicativeCipher
            cipher = MultiplicativeCipher(5)
            ciphertext = cipher.encrypt("Hello World")
            print(ciphertext) # 'Czggj Rjmgy'
            plaintext = cipher.decrypt(ciphertext)
            print(plaintext) # 'Hello World'
            
    .. tab-item:: Affine
            
        .. code-block:: python
                    
            # Example usage of Affine Cipher to encrypt and decrypt a message
            from cryptosystems import AffineCipher
            cipher = AffineCipher(5, 8)
            ciphertext = cipher.encrypt("Hello World")
            print(ciphertext) # 'Rclla Oaplx'
            plaintext = cipher.decrypt(ciphertext)
            print(plaintext) # 'Hello World'
            
    .. tab-item:: Hill
                
        .. code-block:: python
                
            # Example usage of Hill Cipher to encrypt and decrypt a message
            from cryptosystems import HillCipher
            cipher = HillCipher([[3, 3], [2, 5]])
            ciphertext = cipher.encrypt("HelloWorld")
            print(ciphertext) # 'HiozeIpjql'
            plaintext = cipher.decrypt(ciphertext)
            print(plaintext) # 'HelloWorld'
                
    .. tab-item:: Playfair
                
        .. code-block:: python
            
            # Example usage of Playfair Cipher to encrypt and decrypt a message
            from cryptosystems import PlayfairCipher
            cipher = PlayfairCipher("key")
            ciphertext = cipher.encrypt("Hello World")
            print(ciphertext) # 'Dahak Ldskn'
            plaintext = cipher.decrypt(ciphertext)
            print(plaintext) # 'Hello World'

    .. tab-item:: Vigenere
                
        .. code-block:: python
    
            # Example usage of Vigenere Cipher to encrypt and decrypt a message
            from cryptosystems import VigenereCipher
            cipher = VigenereCipher("key")
            ciphertext = cipher.encrypt("Hello World")
            print(ciphertext) # 'Rijvs Uyvjk'
            plaintext = cipher.decrypt(ciphertext)
            print(plaintext) # 'Hello World'

    .. tab-item:: Autokey
                
        .. code-block:: python
                        
            # Example usage of Autokey Cipher to encrypt and decrypt a message
            from cryptosystems import AutokeyCipher
            cipher = AutokeyCipher("key")
            ciphertext = cipher.encrypt("Hello World")
            print(ciphertext) # 'Rijss Hzfhr'
            plaintext = cipher.decrypt(ciphertext)
            print(plaintext) # 'Hello World'           

--------
Classes
--------
The classical symmetric cryptosystems implemented in the ``classical_symmetric`` submodule are:

.. toctree::
    :maxdepth: 1

    AdditiveCipher
    MultiplicativeCipher
    AffineCipher
    HillCipher
    PlayfairCipher
    VigenereCipher
    AutokeyCipher