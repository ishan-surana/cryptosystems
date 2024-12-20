Rabin
=====

The ``Rabin`` class implements the Rabin public-key encryption algorithm, whose security is based on the Integer Factorization problem.

.. class:: Rabin

    Creates a new Rabin instance.

    :param bits: Number of bits for the modulus. Primes are generated having half the bits. Default is **2048**.
    :type bits: int
    :param force: Argument to force computations with higher orders of numbers, irrespective of resultant performance.
    :type force: bool

Introduction
------------

The Rabin encryption algorithm is a public-key cryptosystem based on the mathematical problem of factoring large numbers. It is closely related to `RSA <RSA.html>`_ but with a different approach to encryption. Like RSA, Rabin relies on the difficulty of factoring large composite numbers, but the encryption and decryption processes in Rabin use quadratic residues. The algorithm is probabilistically secure, meaning that the decryption process may result in multiple potential plaintext values, making it inherently different from RSA in certain applications.

Mathematical Details
----------------------

Rabin Key Generation
^^^^^^^^^^^^^^^^^^^^^

The Rabin key generation process involves the following steps:

1. **Choose two large prime numbers**: Two large prime numbers, :math:`p` and :math:`q`, are chosen randomly.
2. **Compute the modulus**: The modulus, :math:`n`, is computed as:

.. math::
   n = p \cdot q

3. **Public and private keys**: The public key is the modulus :math:`n`, and the private key is the tuple of the two primes :math:`(p, q)`.

Rabin Encryption/Decryption Process
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- **Encryption**: The plaintext message, :math:`m`, is encrypted using the public key :math:`n` as follows:

.. math::
   c = m^2 \mod n

- **Decryption**: The ciphertext :math:`c` is decrypted using the private key :math:`(p, q)` as follows:

  - Using `Lagrange's simplification <https://en.wikipedia.org/wiki/Quadratic_residue#Prime_or_prime_power_modulus>`_ for primes :math:`\equiv 3 \mod 4`:

    .. math::
      :nowrap:

      \begin{gather*}
      a = c^{(p+1)/4} \mod p, \quad x_q = p^{-1} \mod q\\
      b = c^{(q+1)/4} \mod p, \quad y_p = q^{-1} \mod p
      \end{gather*}

  - The potential plaintext values are then computed as: 

    .. math::
      :nowrap:

      \begin{gather*}
      m_1 = (a \cdot q \cdot y_p + b \cdot p \cdot x_q) \mod n\\
      m_2 = -m_1 \mod n\\
      m_3 = (a \cdot q \cdot y_p - b \cdot p \cdot x_q) \mod n\\
      m_4 = -m_3 \mod n
      \end{gather*}

  The correct message is then determined by comparing with the SHA256 hash of the plaintext.

Rabin Signature/Verification Process
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- **Signature**: The hash of the plaintext message, :math:`m_h`, is signed using the private key :math:`(p, q)` as follows:

  - Compute:

    .. math::
      :nowrap:

      \begin{gather*}
      a = c^{(p+1)/4} \mod p, \quad x_q = p^{-1} \mod q\\
      b = c^{(q+1)/4} \mod p, \quad y_p = q^{-1} \mod p
      \end{gather*}

  - Any one of the roots, as derived using the method described in decryption, can be used as the signature. Therefore:

    .. math::
      s = (a \cdot q \cdot y_p + b \cdot p \cdot x_q) \mod n

- **Verification**: The result of verification of the signature, :math:`s`, for a message :math:`m` with hash :math:`m_h`, using the public key :math:`n`, is given by:

.. math::
   s^2 \mod n \stackrel{?}{=} m_h^2 \mod n

Usage
-----

.. code-block:: python

    # Example usage of Rabin to encrypt, decrypt, sign and verify a message
    from cryptosystems import Rabin
    cipher = Rabin()
    public_key, private_key = cipher.generate_keys()  # Generate Rabin keys
    ciphertext, message_hash = cipher.encrypt("Hello World", public_key)
    print(ciphertext) # 123456, b'\x12\x34\x56\x78\x90'
    plaintext = cipher.decrypt(ciphertext, message_hash, private_key, "str")
    print(plaintext) # 'Hello World'
    signature, message_hash = cipher.sign("Hello World", private_key)
    print(signature, message_hash, sep=", ") # 123456, b'\x12\x34\x56\x78\x90'
    verification = cipher.verify(signature, message_hash, public_key)
    print(verification) # True

Methods
-------

.. function:: generate_keypair() -> tuple

    Generates a new Rabin key pair, in the form :math:`n` for the public key and :math:`(p, q)` for the private key.

    :return: A tuple containing the public key and private key.
    :rtype: tuple

.. function:: encrypt(plaintext: (int | str | bytes), public_key: int) -> int

    Encrypts the given plaintext using the Rabin algorithm and returns the ciphertext.

    :param plaintext: The plaintext message to be encrypted.
    :type plaintext: int | str | bytes
    :param public_key: The public key used for encryption, in the form :math:`n`.
    :type public_key: int
    :return: The encrypted ciphertext.
    :rtype: int

.. function:: decrypt(ciphertext: int, private_key: tuple, return_type: str) -> (int | str | bytes)

    Decrypts the given ciphertext using the Rabin algorithm and returns the deciphered plaintext.

    :param ciphertext: The ciphertext message to be decrypted.
    :type ciphertext: int
    :param private_key: The private key used for decryption, the form :math:`(p, q)`.
    :type private_key: tuple
    :param return_type: The type in which plaintext is to be returned. It should be either 'int', 'str', or 'bytes'. Default is 'int'
    :type return_type: str
    :return: The decrypted plaintext.
    :rtype: int | str | bytes

.. function:: sign(message: (int | str | bytes), private_key: tuple) -> tuple

    Signs the given message using the Rabin Algorithm and returns the signature and the SHA256 hash.

    :param message: The plaintext message to be signed.
    :type message: int | str | bytes
    :param private_key: The private key used for signature, the form :math:`(p, q)`.
    :type private_key: tuple
    :return: The tuple of signature (int) and the SHA256 hash (bytes) of the message.
    :rtype: tuple

.. function:: verify(signature: (int | str | bytes), message_hash: bytes, public_key: int) -> bool

    Verifies the given signature using the Rabin Algorithm and returns True or False.

    :param signature: The signature to be verified.
    :type signature: int | str | bytes
    :param message_hash: The SHA256 hash for the message.
    :type message_hash: bytes
    :param public_key: The public key used for verification, the form :math:`n`.
    :type public_key: int
    :return: True or False, the result of whether the message is verified.
    :rtype: bool

References
----------

- `Rabin Original Paper <https://publications.csail.mit.edu/lcs/pubs/pdf/MIT-LCS-TR-212.pdf>`_
- `Rabin cryptosystem - Wikipedia <https://en.wikipedia.org/wiki/Rabin_cryptosystem>`_
- `Rabin signature algorithm - Wikipedia <https://en.wikipedia.org/wiki/Rabin_signature_algorithm>`_
- `Quadratic residue - Wikipedia [Lagrange's simplification] <https://en.wikipedia.org/wiki/Quadratic_residue#Prime_or_prime_power_modulus>`_