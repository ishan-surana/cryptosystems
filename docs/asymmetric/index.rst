Asymmetric Cryptosystems
========================

This is the index file for the modern asymmetric cryptosystems. The modern asymmetric cryptosystems are implemented in the ``asymmetric`` submodule and can be imported directly from the package.

--------------
Introduction
--------------
Asymmetric cryptosystems, also known as public-key cryptosystems, use a pair of keys for encryption and decryption: a **public key** for encryption and a **private key** for decryption. These systems are based on mathematical problems that are easy to compute in one direction but difficult to reverse without the private key, for example, the Discrete Logarithm Problem. Asymmetric encryption provides enhanced security, eliminating the need for the sender and receiver to share a secret key, which is a major advantage over symmetric cryptosystems.

Asymmetric encryption is computationally more expensive than symmetric encryption but provides key advantages, such as digital signatures and secure key exchange. Some of the most widely used asymmetric cryptosystems include:

- **RSA**: RSA is one of the most widely used asymmetric cryptosystems. It relies on the difficulty of factoring large prime numbers.
- **ElGamal**: ElGamal encryption is based on the Diffie-Hellman key exchange and relies on the difficulty of computing discrete logarithms.
- **Rabin**: The Rabin cryptosystem is based on the difficulty of factoring large numbers, similar to RSA, but with a different approach and properties.
- **Paillier**: Paillier is a probabilistic encryption scheme that provides additive homomorphic properties, meaning that operations on ciphertexts correspond to operations on plaintexts.
- **Elliptic Curve Cryptography (ECC)**: ECC is a modern alternative to RSA, offering equivalent security to RSA but with much smaller key sizes, making it more efficient for resource-constrained environments.

--------------
Usage Examples
--------------
.. tab-set::

    .. tab-item:: RSA

        .. code-block:: python
                
                # Example usage of RSA to encrypt, decrypt, sign and verify a message
                from cryptosystems import RSA
                cipher = RSA()
                public_key, private_key = cipher.generate_keys()  # Generate RSA keys
                ciphertext = cipher.encrypt("Hello World", public_key)
                print(ciphertext) # 123456
                plaintext = cipher.decrypt(ciphertext, private_key, "str")
                print(plaintext) # 'Hello World'
                signature, message_hash = cipher.sign("plaintext", private_key)
                print(signature, message_hash, sep=", ") # 123456, b'\x12\x34\x56\x78\x90'
                verification = cipher.verify(signature, message_hash, public_key)
                print(verification) # True
                
    .. tab-item:: ElGamal
            
        .. code-block:: python
                        
                # Example usage of ElGamal to encrypt and decrypt a message
                from cryptosystems import ElGamal
                cipher = ElGamal()
                public_key, private_key = cipher.generate_keys()  # Generate ElGamal keys
                ciphertext = cipher.encrypt("Hello World", public_key)
                print(ciphertext) # (123456, 654321)
                plaintext = cipher.decrypt(ciphertext, private_key, "str")
                print(plaintext) # 'Hello World'
                signature, message_hash = cipher.sign("plaintext", private_key)
                print(signature, message_hash, sep=", ") # (123456, 654321), b'\x12\x34\x56\x78\x90'
                verification = cipher.verify(signature, message_hash, public_key)
                print(verification) # True
            
    .. tab-item:: Rabin
            
        .. code-block:: python
                        
                # Example usage of Rabin to encrypt and decrypt a message
                from cryptosystems import Rabin
                cipher = Rabin()
                public_key, private_key = cipher.generate_keys()  # Generate Rabin keys
                ciphertext, message_hash = cipher.encrypt("Hello World", public_key)
                print(ciphertext, message_hash, sep=", ") # 123456, b'\x12\x34\x56\x78\x90'
                plaintext = cipher.decrypt(ciphertext, message_hash, private_key, "str")
                print(plaintext) # 'Hello World'
                signature, message_hash = cipher.sign("plaintext", private_key)
                print(signature, message_hash, sep=", ") # 123456, b'\x12\x34\x56\x78\x90'
                verification = cipher.verify(signature, message_hash, public_key)
                print(verification) # True
            
    .. tab-item:: Paillier
                
        .. code-block:: python
                        
                # Example usage of Paillier to encrypt and decrypt a message
                from cryptosystems import Paillier
                cipher = Paillier()
                public_key, private_key = cipher.generate_keys()  # Generate Paillier keys
                ciphertext = cipher.encrypt("Hello World", public_key)
                print(ciphertext) # 123456
                plaintext = cipher.decrypt(ciphertext, private_key, "str")
                print(plaintext) # 'Hello World'
                # Paillier signing and verification not implemented yet.
                addition = paillier.homomorphic_add(paillier.encrypt(100, public_key), paillier.encrypt(200, public_key), public_key)
                result = paillier.decrypt(sum, private_key, "int") # 300

    .. tab-item:: ECC
                
        .. code-block:: python
                        
                # Example usage of ECC to encrypt and decrypt a message
                from cryptosystems import ECC
                cipher = ECC()
                public_key, private_key = cipher.generate_keys()  # Generate ECC keys
                ciphertext = cipher.encrypt("Hello World", public_key)
                print(ciphertext) # ((12345, 67890), (98765, 43210))
                plaintext = cipher.decrypt(ciphertext, private_key, "str")
                print(plaintext) # 'Hello World'
                signature, message_hash = cipher.sign("plaintext", private_key)
                print(signature, message_hash, sep=", ") # (123456, 654321), b'\x12\x34\x56\x78\x90'
                verification = cipher.verify(signature, message_hash, public_key)
                print(verification) # True

--------
Classes
--------
The modern asymmetric cryptosystems implemented in the ``asymmetric`` submodule are:

.. toctree::
    :maxdepth: 1

    RSA
    ElGamal
    Rabin
    Paillier
    ECC
