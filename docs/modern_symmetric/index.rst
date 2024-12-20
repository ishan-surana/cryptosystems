Modern Symmetric Cryptosystems
==============================

This is the index file for the modern symmetric cryptosystems. The modern symmetric cryptosystems are implemented in the ``modern_symmetric`` submodule and can be imported directly from the package.

.. note::

    Currently, the ``cryptosystems`` library supports DES and AES algorithm in ECB mode. Future updates will expand the library to include additional modes and a broader range of ciphers.

--------------
Introduction
--------------
Modern symmetric cryptosystems are advanced encryption techniques that utilize computationally complex algorithms and larger keys to provide stronger security than classical symmetric ciphers. These ciphers rely on a shared secret key for both encryption and decryption. Unlike classical ciphers, modern ciphers are designed to resist attacks using more sophisticated methods such as brute-force, chosen-plaintext, and differential cryptanalysis. They are widely used in various applications, including securing internet communications, file encryption, and data protection.

Some of the key modern symmetric cryptosystems include:

- **Block Ciphers**: Block ciphers encrypt data in fixed-size blocks (e.g., 128, 192, or 256 bits). They transform a plaintext block into a ciphertext block of the same size using the key.

  - **Advanced Encryption Standard (AES)**: AES is one of the most widely used encryption algorithms. It supports key sizes of 128, 192, and 256 bits and operates on 128-bit blocks of plaintext.
  - **Data Encryption Standard (DES)**: DES is an older block cipher that operates on 64-bit blocks with an effective 56-bit key. It is now considered insecure due to advances in cryptanalysis and computing power.
  - **Triple DES (3DES)**: Triple DES applies the DES algorithm three times with either two or three unique keys to improve security compared to DES.
    
- **Stream Ciphers**: Stream ciphers encrypt data bit by bit or byte by byte, typically using a keystream generated from the key.

  - **RC4**: RC4 is a widely used stream cipher that generates a pseudorandom keystream and XORs it with the plaintext to produce the ciphertext.

--------------
Usage Examples
--------------
.. tab-set::
                
    .. tab-item:: DES
            
        .. code-block:: python
                        
                # Example usage of DES to encrypt and decrypt a message
                from cryptosystems import DES
                cipher = DES("password")  # Example 64-bit key
                ciphertext = cipher.encrypt("Hello World")
                print(ciphertext) # b'\xf4\\V\x1a\xc7S\xb7\xdeZ\xc1\xe9\x14\n\x15Y\xe8'
                plaintext = cipher.decrypt(ciphertext)
                print(plaintext) # 'Hello World'

    .. tab-item:: AES

        .. code-block:: python
                
                # Example usage of AES to encrypt and decrypt a message
                from cryptosystems import AES
                cipher = AES("passwordpassword")  # Example 128-bit key
                ciphertext = cipher.encrypt("Hello World")
                print(ciphertext) # b"G\xe4\xc3\x8b\xd9\x02>\x88\xe0)\x94Z\xdbE'\x96"
                plaintext = cipher.decrypt(ciphertext)
                print(plaintext) # 'Hello World'

--------
Classes
--------
The modern symmetric cryptosystems implemented in the ``modern_symmetric`` submodule are:

.. toctree::
    :maxdepth: 1

    DES
    AES