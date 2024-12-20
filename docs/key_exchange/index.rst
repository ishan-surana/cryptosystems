Key Exchange
============

This is the index file for key exchange protocols. Key exchange protocols allow two parties to securely share a cryptographic key over an insecure channel. The key exchange protocols are implemented in the ``key_exchange`` submodule and can be imported directly from the package.

.. note::

    Currently, the ``cryptosystems`` library supports Diffie-Hellman and ECDH algorithms. Future updates will expand the library to include a broader range of key exchange protocols.

--------------
Introduction
--------------
Key exchange protocols are essential for secure communication in modern cryptography. They allow two parties to establish a shared secret, which can be used for encrypting subsequent communications. These protocols rely on mathematical principles that make it difficult for an eavesdropper to derive the shared key without having access to specific private information. Unlike symmetric cryptography, where the key must be shared beforehand, key exchange protocols enable secure establishment of the key during the communication itself.

Key exchange is a foundational element in various cryptosystems, providing the means to securely establish a common key between parties. Notably, these protocols are commonly used in securing internet communications, including protocols like HTTPS.

Some of the most widely used key exchange protocols include:

- **Diffie-Hellman**: One of the first practical key exchange protocols, Diffie-Hellman allows two parties to securely exchange a secret over an insecure channel. It is based on the difficulty of solving the discrete logarithm problem.
- **Elliptic Curve Diffie-Hellman (ECDH)**: An adaptation of the Diffie-Hellman protocol that uses elliptic curve cryptography. ECDH offers similar security to traditional Diffie-Hellman but with smaller key sizes, making it more efficient.
- **Post-Quantum Key Exchange**: These are emerging protocols designed to resist attacks from quantum computers. Lattice-based schemes and other quantum-resistant approaches are currently being explored as alternatives to traditional key exchange methods.

--------------
Usage Examples
--------------
.. tab-set::

    .. tab-item:: DiffieHellman

        .. code-block:: python
                
                # Example usage of DiffieHellman to generate shared secret
                from cryptosystems import DiffieHellman
                dh = DiffieHellman()
                public_key, private_key = dh.generate_keys()  # Generate DH keys
                # Get other individual's public key
                shared_secret = dh.generate_keys(pub_other, private_key) # 1234567890

    .. tab-item:: ECDH

        .. code-block:: python
                
                # Example usage of ECDH to generate shared secret
                from cryptosystems import ECDH
                ecdh = ECDH()
                public_key, private_key = ecdh.generate_keys()  # Generate ECDH keys
                # Get other individual's public key
                shared_secret = ecdh.generate_keys(pub_other, private_key) # 1234567890

--------
Classes
--------
The key exchange protocols implemented in the ``key_exchange`` submodule are:

.. toctree::
    :maxdepth: 1
    
    DiffieHellman
    ECDH