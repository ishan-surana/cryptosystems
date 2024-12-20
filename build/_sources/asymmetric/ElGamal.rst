ElGamal
========

The ``ElGamal`` class implements the ElGamal public-key encryption algorithm, whose security is based on the difficulty of solving the Discrete Logarithm problem in a finite field.

.. class:: ElGamal

    Creates a new ElGamal instance.

    :param bits: Number of bits for the prime number. Default is **2048**.
    :type bits: int
    :param force: Argument to force computations with higher orders of numbers, irrespective of resultant performance.
    :type force: bool

Introduction
------------

The ElGamal encryption algorithm is a public-key cryptosystem based on the Diffie-Hellman key exchange. It provides a high level of security for data transmission by utilizing asymmetric encryption. The algorithm uses modular arithmetic and relies on the difficulty of the discrete logarithm problem. The ElGamal encryption scheme consists of three main components: key generation, encryption, and decryption.

Mathematical Details
----------------------

ElGamal Key Generation
^^^^^^^^^^^^^^^^^^^^^^

The ElGamal key generation process involves the following steps:

1. **Choose a large prime number**: A large prime number :math:`p` is selected.
2. **Select a generator**: A primitive root :math:`g` (generator) modulo :math:`p` is computed.
3. **Choose a private key**: A private key :math:`x` is selected randomly from the range [1, p-2].
4. **Compute the public key**: The public key :math:`h` is computed as:

.. math::
    h = g^x \mod p

The public key is then the pair :math:`(p, g, h)`, and the private key is :math:`(p, g, x)`.

ElGamal Encryption/Decryption Process
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- **Encryption**: The plaintext message, :math:`m`, is encrypted using the public key :math:`(p, g, h)` as follows:

  - Select a random value :math:`k` from the range [1, p-2].
  - Compute the ciphertext components :math:`c_1` and :math:`c_2`:

  .. math::
    :nowrap:
    
    \begin{gather*}
    c_1 = g^k \mod p\\
    c_2 = m \cdot h^k \mod p
    \end{gather*}

  The ciphertext is then the pair :math:`(c_1, c_2)`.

- **Decryption**: The ciphertext :math:`(c_1, c_2)` is decrypted using the private key :math:`(p, g, x)` as follows:

  .. math::
    m = c_2 \cdot (c_1^x)^{-1} \mod p

  which can be also done as:

  .. math::
    m = c_2 \cdot (c_1^x)^{p-1-x} \mod p

ElGamal Signing/Verification Process
-------------------------------------

- **Signature**: The hash of the plaintext message, :math:`m_h`, is signed using the private key :math:`x` as follows:

  .. math::
    :nowrap:
    
    \begin{gather*}
    s_1 = g^k \mod p\\
    s_2 = (k^{-1} \cdot (m_h - x \cdot s_1)) \mod (p-1)
    \end{gather*}

  The signature is the pair :math:`(s_1, s_2)`.

- **Verification**: The signature :math:`(s_1, s_2)` for a message :math:`m` with hash :math:`m_h`, is verified using the public key :math:`(p, g, h)` as follows:

  .. math::
    :nowrap:
    
    \begin{gather*}
    v_1 = g^{m_h} \mod p\\
    v_2 = h^{s_1} \cdot s_1^{s_2} \mod p.
    \end{gather*}

  The result of the verification is given by:

  .. math::
   v_1 \stackrel{?}{=} v_2

Usage
-----

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

Methods
-------

.. function:: generate_keypair() -> tuple

    Generates a new ElGamal key pair, in the form :math:`((p, g, h), (p, g, x))`.

    :return: A tuple containing the public key and private key.
    :rtype: tuple

.. function:: encrypt(plaintext: (int | str | bytes), public_key: tuple) -> tuple

    Encrypts the given plaintext using the ElGamal algorithm and returns the ciphertext.

    :param plaintext: The plaintext message to be encrypted.
    :type plaintext: int | str | bytes
    :param public_key: The public key used for encryption, in the form :math:`(p, g, h)`.
    :type public_key: tuple
    :return: The encrypted ciphertext, in the form :math:`(c_1, c_2)`.
    :rtype: tuple

.. function:: decrypt(ciphertext: tuple, private_key: tuple, return_type: str) -> (int | str | bytes)

    Decrypts the given ciphertext using the ElGamal algorithm and return the deciphered plaintext.

    :param ciphertext: The ciphertext message to be decrypted, in the form :math:`(c_1, c_2)`.
    :type ciphertext: tuple
    :param private_key: The private key used for decryption, in the form :math:`(p, g, x)`.
    :type private_key: tuple
    :param return_type: The type in which plaintext is to be returned. It should be either 'int', 'str', or 'bytes'. Default is 'int'
    :type return_type: str
    :return: The decrypted plaintext.
    :rtype: int | str | bytes

.. function:: sign(message: (int | str | bytes), private_key: tuple) -> tuple

    Signs the given message using the ElGamal Algorithm and returns the signature and SHA256 hash.

    :param message: The plaintext message to be signed.
    :type message: int | str | bytes
    :param private_key: The private key used for signature, in the form :math:`(p, g, x)`.
    :type private_key: tuple
    :return: The tuple of signature for the message, in the form :math:`(s_1, s_2)`, and the SHA256 hash (bytes) of the message.
    :rtype: tuple

.. function:: verify(signature: tuple, message_hash: bytes, public_key: tuple) -> bool

    Verifies the given signature using the ElGamal Algorithm and returns True or False.

    :param signature: The signature to be verified, in the form of :math:`(s_1, s_2)`.
    :type signature: tuple
    :param message_hash: The SHA256 hash for the message.
    :type message_hash: bytes
    :param public_key: The public key used for verification, the form :math:`(p, g, h)`.
    :type public_key: tuple
    :return: True or False, the result of whether the message is verified.
    :rtype: bool

References
----------

- `ElGamal Original Paper <https://caislab.kaist.ac.kr/lecture/2010/spring/cs548/basic/B02.pdf>`_
- `ElGamal encryption - Wikipedia <https://en.wikipedia.org/wiki/ElGamal_encryption>`_
- `ElGamal signature scheme - Wikipedia <https://en.wikipedia.org/wiki/ElGamal_signature_scheme>`_