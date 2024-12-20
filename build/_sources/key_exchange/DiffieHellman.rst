DiffieHellman
=============

The ``DiffieHellman`` class implements the Diffie-Hellman key exchange algorithm, which allows two parties to securely share a secret key over an insecure communication channel.

.. class:: DiffieHellman

    Creates a new Diffie-Hellman instance.

    :param prime: A large prime number, which is used to define the modulus for the Diffie-Hellman protocol.
    :type prime: int
    :param generator: The generator value used for the Diffie-Hellman algorithm, typically a primitive root modulo the prime.
    :type generator: int
    :param force: Argument to force computations with higher orders of numbers, irrespective of resultant performance.
    :type force: bool

Introduction
------------

The Diffie-Hellman key exchange algorithm is one of the first public-key protocols and is used to securely exchange cryptographic keys over a public channel. The key exchange is based on the difficulty of the discrete logarithm problem, where it is computationally infeasible to derive the shared secret key from the exchanged values. The Diffie-Hellman protocol allows two parties to independently generate the same secret key, which can then be used for further encryption or authentication, for example, using symmetric cryptographic systems like AES.

Mathematical Details
--------------------

The Diffie-Hellman key exchange process involves the following steps:

1. **Agree on a prime number and a generator**: The two parties agree on a large prime number :math:`p` and a generator :math:`g`. These values are not secret and can be publicly shared.

2. **Generate private keys**: Each party generates a private key, :math:`a` for Alice and :math:`b` for Bob. These private keys are kept secret.

3. **Compute public keys**: Each party computes their corresponding public key:
   - Alice computes :math:`A = g^a \mod p`
   - Bob computes :math:`B = g^b \mod p`

4. **Exchange public keys**: Alice and Bob exchange their public keys :math:`A` and :math:`B`.

5. **Compute the shared secret**: After receiving each other's public key, both parties compute the shared secret:
   - Alice computes :math:`S = B^a \mod p`
   - Bob computes :math:`S = A^b \mod p`

Both computations result in the same shared secret :math:`S`, which can be used for secure communication.

Usage
-----

.. tab-set::

    .. tab-item:: Party 1

        .. code-block:: python
                
                # Example usage of DiffieHellman to generate shared secret
                from cryptosystems import DiffieHellman
                dh = DiffieHellman()
                params = dh.get_params()
                # Send params to other party
                public_key_1, private_key_1 = dh.generate_keys()  # Generate DH keys
                # Get other individual's public key
                shared_secret = dh.generate_keys(public_key_2, private_key_1) # 1234567890

    .. tab-item:: Party 2

        .. code-block:: python
                
                # Example usage of DiffieHellman to generate shared secret
                from cryptosystems import DiffieHellman
                dh = DiffieHellman()
                # Get params from other party
                dh.set_params(params)
                public_key_2, private_key_2 = dh.generate_keys()  # Generate DH keys
                # Get other individual's public key
                shared_secret = dh.generate_keys(public_key_1, private_key_2) # 1234567890

Methods
-------

.. function:: generate_keys() -> tuple

    Generates a new Diffie-Hellman key pair, in the form :math:`(A, a)`, where :math:`A` is the public key and :math:`a` is the private key.

    :return: A tuple containing the private key and the public key.
    :rtype: tuple

.. function:: get_shared_secret(a: int, B: int) -> int

    Computes the shared secret between two parties, given their private key :math:`a` and the other party's public key :math:`B`.

    :param private_key: The private key of the party computing the shared secret.
    :type private_key: int
    :param public_key: The public key of the other party.
    :type public_key: int
    :return: The computed shared secret.
    :rtype: int

.. function:: get_params() -> int

    Returns the parameter :math:`p`, the prime used for instantiating Diffie Hellman.

    :return: The prime :math:`p` used for instantiating the **DiffieHellman** object.
    :rtype: int

.. function:: set_params(prime: int)

    Sets the parameters, :math:`'p'` and 'force', as per the ones being used by other party.

    :param prime: The prime :math:`p` used for instantiating the **DiffieHellman** object.
    :type prime: int
