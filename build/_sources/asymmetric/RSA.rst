RSA
===

The ``RSA`` class implements the Rivest-Shamir-Adleman public-key encryption algorithm, whose security is based upon the Integer Factorization problem.

.. class:: RSA

    Creates a new RSA instance.

    :param bits: Number of bits for the modulus. Primes are generated having half the bits. Default is **2048**.
    :type bits: int
    :param force: Argument to force computations with higher orders of numbers, irrespective of resultant performance.
    :type force: bool

.. note::
   The implementation of RSA in this module follows the standards set by NIST in `FIPS 186-5 <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf>`_. Refer the `Standards <../Standards.html>`_ to see the full list of NIST Standards and Guidelines considered.

Introduction
------------

The Rivest-Shamir-Adleman (RSA) algorithm is a widely used public-key encryption algorithm that provides secure data transmission. It is based on the principles of asymmetric cryptography, where a pair of keys is used to encrypt and decrypt data. The security of RSA relies on the difficulty of factoring large composite numbers, which makes it computationally infeasible to determine the private key from the public key.

Mathematical Details
----------------------

RSA Key Generation
^^^^^^^^^^^^^^^^^^

The RSA key generation process involves the following steps:

1. **Choose two large prime numbers**: Two large prime numbers, :math:`p` and :math:`q`, are chosen randomly.
2. **Compute the modulus**: The modulus, :math:`n`, is computed as:

.. math::
   n = p \cdot q

3. **Compute the totient**: The Euler's totient, :math:`\phi(n)`, is computed as:

.. math::
   \phi(n) = (p-1) \cdot (q-1)

4. **Choose the public exponent**: A small prime number, :math:`e`, is chosen as the public exponent. In the implementation, the standard value of **65537** is used.
5. **Compute the private exponent**: The private exponent, :math:`d`, is computed as:

.. math::
   d = e^{-1} \mod \phi(n)

The public key is then the pair :math:`(n, e)`, and the private key is :math:`(n, d)`.

RSA Encryption/Decryption Process
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- **Encryption**: The plaintext message, :math:`m`, is encrypted using the public key :math:`(n, e)` as follows:

.. math::
   c = m^e \mod n

- **Decryption**: The ciphertext message, :math:`c`, is decrypted using the private key :math:`(n, d)` as follows:

.. math::
   m = c^d \mod n

RSA Signature/Verification Process
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- **Signature**: The hash of the plaintext message, :math:`m_h`, is signed using the private key :math:`(n, d)` as follows:

.. math::
   s = m_h^d \mod n

- **Verification**: The signature, :math:`s`, for a message :math:`m` with hash :math:`m_h`, is verified using the public key :math:`(n, e)` as follows:

.. math::
   m_h' = s^e \mod n

The result of the verification is given by:

.. math::
   m_h' \stackrel{?}{=} m_h

Usage
-----

.. code-block:: python

    # Example usage of RSA to encrypt, decrypt, sign and verify a message
    from cryptosystems import RSA
    cipher = RSA()
    public_key, private_key = cipher.generate_keys()  # Generate RSA keys
    ciphertext = cipher.encrypt("Hello World", public_key)
    print(ciphertext) # 123456
    plaintext = cipher.decrypt(ciphertext, private_key, "str")
    print(plaintext) # 'Hello World'
    signature, message_hash = cipher.sign("Hello World", private_key)
    print(signature, message_hash, sep=", ") # 123456, b'\x12\x34\x56\x78\x90'
    verification = cipher.verify(signature, message_hash, public_key)
    print(verification) # True

Methods
-------

.. function:: generate_keypair() -> tuple

    Generates a new RSA key pair, in the form :math:`((n, e), (n, d))`.

    :return: A tuple containing the public key and private key.
    :rtype: tuple

.. function:: encrypt(plaintext: (int | str | bytes), public_key: tuple) -> int

    Encrypts the given plaintext using the RSA algorithm and returns the ciphertext.

    :param plaintext: The plaintext message to be encrypted.
    :type plaintext: int | str | bytes
    :param public_key: The public key used for encryption, in the form :math:`(n, e)`.
    :type public_key: tuple
    :return: The encrypted ciphertext.
    :rtype: int

.. function:: decrypt(ciphertext: (int | str | bytes), private_key: tuple, return_type: str) -> (int | str | bytes)

    Decrypts the given ciphertext using the RSA algorithm and returns the deciphered plaintext.

    :param ciphertext: The ciphertext message to be decrypted.
    :type ciphertext: int | str | bytes
    :param private_key: The private key used for decryption, the form :math:`(n, d)`.
    :type private_key: tuple
    :param return_type: The type in which plaintext is to be returned. It should be either 'int', 'str', or 'bytes'. Default is 'int'
    :type return_type: str
    :return: The decrypted plaintext.
    :rtype: int | str | bytes

.. function:: sign(message: (int | str | bytes), private_key: tuple) -> tuple

    Signs the given message using the RSA Algorithm and returns the signature and SHA256 hash.

    :param message: The plaintext message to be signed.
    :type message: int | str | bytes
    :param private_key: The private key used for signature, the form :math:`(n, d)`.
    :type private_key: tuple
    :return: The tuple of signature (int) and the SHA256 hash (bytes) of the message.
    :rtype: tuple

.. function:: verify(signature: (int | str | bytes), message_hash: bytes, public_key: tuple) -> bool

    Verifies the given signature using the RSA Algorithm and returns True or False.

    :param signature: The signature to be verified.
    :type signature: int | str | bytes
    :param message_hash: The SHA256 hash for the message.
    :type message_hash: bytes
    :param public_key: The public key used for verification, the form :math:`(n, e)`.
    :type public_key: tuple
    :return: True or False, the result of whether the message is verified.
    :rtype: bool

References
----------

- `RSA Original Paper <https://people.csail.mit.edu/rivest/Rsapaper.pdf>`_
- `NIST FIPS 186-5: Digital Signature Standard (DSS) <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf>`_
- `RSA (cryptosystem) - Wikipedia <https://en.wikipedia.org/wiki/RSA_(cryptosystem)>`_