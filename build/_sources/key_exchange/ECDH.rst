ECDH
====

The ``ECDH`` class implements the Elliptic Curve Diffie-Hellman key exchange protocol, which allows two parties to securely exchange cryptographic keys over an insecure channel. This protocol is based on elliptic curve cryptography (ECC), which offers the same security as traditional Diffie-Hellman but with smaller key sizes.

.. class:: ECDH

    Creates a new ECDH instance.

    :param curve: The elliptic curve to use for the key exchange. Default is 'secp256k1'.
    :type curve: str
    :param force: Argument to force computations with higher orders of numbers, irrespective of resultant performance.
    :type force: bool

Introduction
------------

The Elliptic Curve Diffie-Hellman (ECDH) protocol is a variant of the traditional Diffie-Hellman key exchange that uses elliptic curve mathematics for better security with smaller key sizes. ECDH allows two parties to exchange a shared secret over an insecure channel, and this secret can then be used for symmetric encryption (e.g., AES) or other cryptographic tasks. The security of ECDH relies on the difficulty of the elliptic curve discrete logarithm problem.

Mathematical Details
--------------------

The ECDH key exchange process involves the following steps:

1. **Agree on an elliptic curve**: Both parties agree on a common elliptic curve and base point :math:`G` (the generator point). The curve and base point do not need to be secret.

2. **Generate private keys**: Each party generates a private key, :math:`a` for Alice and :math:`b` for Bob. These private keys are kept secret.

3. **Compute public keys**: Each party computes their corresponding public key using the elliptic curve scalar multiplication:
   - Alice computes :math:`A = a \cdot G`
   - Bob computes :math:`B = b \cdot G`

4. **Exchange public keys**: Alice and Bob exchange their public keys, :math:`A` and :math:`B`.

5. **Compute the shared secret**: After receiving each other's public key, both parties compute the shared secret by performing elliptic curve scalar multiplication:
   - Alice computes :math:`S = a \cdot B`
   - Bob computes :math:`S = b \cdot A`

Both computations result in the same shared secret :math:`S`, which can be used for further cryptographic operations.

Usage
-----

.. tab-set::

    .. tab-item:: Party 1

        .. code-block:: python
                
            # Example usage of ECDH to generate shared secret
            from cryptosystems import ECDH
            ecdh = ECDH() # Default curve 'P-256'
            public_key_1, private_key_1 = ecdh.generate_keys()  # Generate ECDH keys
            # Get other individual's public key
            shared_secret = ecdh.generate_keys(public_key_2, private_key_1) # 1234567890

    .. tab-item:: Party 2

        .. code-block:: python
                
            # Example usage of ECDH to generate shared secret
            from cryptosystems import ECDH
            ecdh = ECDH() # Default curve 'P-256'
            public_key_2, private_key_2 = ecdh.generate_keys()  # Generate ECDH keys
            # Get other individual's public key
            shared_secret = ecdh.generate_keys(public_key_1, private_key_2) # 1234567890

Methods
-------

.. function:: generate_keys() -> tuple

    Generates a new ECC key pair, in the form :math:`(A, a)`, where :math:`A` is the public key and :math:`a` is the private key.

    :return: A tuple containing the private key and the public key.
    :rtype: tuple

.. function:: get_shared_secret(a: int, B: tuple) -> int

    Computes the shared secret between two parties, given their private key :math:`a` and the other party's public key :math:`B`.

    :param private_key: The private key of the party computing the shared secret.
    :type private_key: int
    :param public_key: The public key of the other party.
    :type public_key: tuple
    :return: The computed shared secret.
    :rtype: int
