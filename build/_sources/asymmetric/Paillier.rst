Paillier
========

The ``Paillier`` class implements the Paillier public-key encryption algorithm, whose security is based on the Decisional Composite Residuosity Assumption (DCRA).

.. class:: Paillier

    Creates a new Paillier instance.

    :param bits: Number of bits for the modulus. Primes are generated having half the bits. Default is **2048**.
    :type bits: int
    :param force: Argument to force computations with higher orders of numbers, irrespective of resultant performance.
    :type force: bool

.. attention::
    The Paillier signature scheme has not been implemented yet, and hence, the ``sign`` and ``verify`` functions do not yield any result. Use the Paillier cryptosystem accordingly.

Introduction
------------

The Paillier cryptosystem is a probabilistic asymmetric encryption algorithm that is semantically secure under the decisional composite residuosity assumption. It is particularly known for its homomorphic properties, allowing operations to be performed on encrypted data without decrypting it. Specifically, Paillier supports both additive homomorphism and partial homomorphism, which is useful for secure computations on encrypted data.

.. note::
    The implementation of Paillier cryptosystem in this module uses a simpler variant, recommended to faster computation time for implementation purposes. The details can be found `here <https://en.wikipedia.org/wiki/Paillier_cryptosystem#Key_generation>`_

Mathematical Details
--------------------

Paillier Key Generation
^^^^^^^^^^^^^^^^^^^^^^^

The Paillier key generation process involves the following steps:

1. **Choose two large prime numbers**: Two large prime numbers, :math:`p` and :math:`q`, are chosen randomly.
2. **Compute the modulus**: The modulus, :math:`n`, is computed as:

.. math::
   n = p \cdot q

3. **Compute the Carmichael's totient**: The Carmichael's totient :math:`\lambda(n)` is computed as:

.. math::
  \lambda(n) = \text{lcm}(p-1, q-1)

However, using the simplified version of the Paillier algorithm, we use:

.. math::
  \lambda(n) = \phi(n) = (p-1) \cdot (q-1)

4. **Choose the public key**: A random integer :math:`g` is selected such that its order is :math:`n^2`. The public key is then the pair :math:`(n, g)`.

5. **Compute the private key**: The private key :math:`\mu` is computed as:

.. math::
   \mu = (L(g^\lambda \mod n^2))^{-1} \mod n

where :math:`L(x) = \frac {(x-1)}{n}` is the L-function.

Paillier Encryption/Decryption Process
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. **Encryption**: The plaintext message, :math:`m`, is encrypted using the public key :math:`(n, g)` as follows:

.. math::
   c = g^m \cdot r^n \mod n^2

where :math:`r` is a random integer chosen from the range :math:`1 < r < n`.

2. **Decryption**: The ciphertext message, :math:`c`, is decrypted using the private key :math:`(n, \lambda(n), \mu)` as follows:

.. math::
   m = L(c^\lambda \mod n^2) \cdot \mu \mod n

where :math:`L(x)` is the L-function, defined as :math:`L(x) = \frac {(x-1)}{n}`.

Paillier Homomorphic Property
-----------------------------

Paillier is additively homomorphic, meaning that given two ciphertexts :math:`c_1` and :math:`c_2` of messages :math:`m_1` and :math:`m_2`, the following holds:

.. math::
   c_1 \cdot c_2 \mod n^2 = g^{m_1 + m_2} \cdot r^n \mod n^2

This allows for the addition of encrypted messages without decrypting them.

Usage
-----

.. code-block:: python

    # Example usage of Paillier to encrypt, decrypt, and perform homomorphic addition
    from cryptosystems import Paillier
    cipher = Paillier()
    public_key, private_key = cipher.generate_keys()  # Generate Paillier keys
    ciphertext = cipher.encrypt(42, public_key)
    print(ciphertext)  # Encrypted form of 42
    plaintext = cipher.decrypt(ciphertext, private_key)
    print(plaintext)  # 42
    ciphertext2 = cipher.encrypt(58, public_key)
    result = cipher.homomorphic_add(ciphertext, ciphertext2, public_key)
    print(result)  # Encrypted form of 100 (42 + 58)
    print(cipher.decrypt(result, private_key))  # 100

Methods
-------

.. function:: generate_keypair() -> tuple

    Generates a new Paillier key pair, in the form :math:`(n, g)` for the public key and :math:`(n, y, u)` for the private key.

    :return: A tuple containing the public key and private key.
    :rtype: tuple

.. function:: encrypt(plaintext: (int | str | bytes), public_key: tuple) -> int

    Encrypts the given plaintext using the Paillier algorithm and returns the ciphertext.

    :param plaintext: The plaintext message to be encrypted.
    :type plaintext: int | str | bytes
    :param public_key: The public key used for encryption, in the form :math:`(n, g)`.
    :type public_key: tuple
    :return: The encrypted ciphertext.
    :rtype: int

.. function:: decrypt(ciphertext: int, private_key: tuple, return_type: str) -> (int | str | bytes)

    Decrypts the given ciphertext using the Paillier algorithm and returns the deciphered plaintext.

    :param ciphertext: The ciphertext message to be decrypted.
    :type ciphertext: int
    :param private_key: The private key used for decryption, in the form :math:`(n, y, u)`.
    :type private_key: tuple
    :return: The decrypted plaintext.
    :rtype: int

.. function:: homomorphic_add(ciphertext1: int, ciphertext2: int, public_key: tuple) -> int

    Adds two ciphertexts together using the homomorphic properties of the Paillier algorithm.

    :param ciphertext1: The first ciphertext message to be added.
    :type ciphertext1: int
    :param ciphertext2: The second ciphertext message to be added.
    :type ciphertext2: int
    :param public_key: The public key used for encryption, in the form :math:`(n, g)`.
    :type public_key: tuple
    :return: The resulting ciphertext of the sum of the plaintexts.
    :rtype: int

.. attention::
    Below functions are not implemented yet. Documentation is created only for reference.

.. function:: sign(message: (int | str | bytes), private_key: tuple) -> int

    Signs the given message using the Paillier algorithm and returns the signature.

    :param message: The plaintext message to be signed.
    :type message: int | str | bytes
    :param private_key: The private key used for signing, the form :math:`(n, y, u)`.
    :type private_key: tuple
    :return: The signature (int) and the SHA256 hash (bytes) of the message.
    :rtype: int

.. function:: verify(signature: int, signature: (int | str | bytes), message_hash: bytes, public_key: tuple) -> bool

    Verifies the given signature using the Paillier algorithm and returns True or False.

    :param signature: The signature to be verified.
    :type signature: int
    :param message: The message whose signature is to be verified.
    :type message: int | str | bytes
    :param public_key: The public key used for verification, in the form :math:`(n, g)`.
    :type public_key: tuple
    :return: True or False, the result of whether the signature is valid.
    :rtype: bool

References
----------

- `Paillier Original Paper <https://link.springer.com/content/pdf/10.1007/3-540-48910-X_16.pdf>`_
- `Paillier cryptosystem - Wikipedia <https://en.wikipedia.org/wiki/Paillier_cryptosystem>`