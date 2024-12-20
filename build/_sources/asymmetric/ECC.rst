ECC
===

The ``ECC`` class implements the Elliptic Curve Cryptography (ECC) algorithm, which is based on the difficulty of the Elliptic Curve Discrete Logarithm Problem (ECDLP).

.. class:: ECC

    Creates a new ECC instance.

    :param curve_name: The name of the elliptic curve to use. Default is **'P-256'**, also known as **'sep256r1'**. Options are currently limited to [**'Curve25519'**, **'P-256'**, **'secp256k1'**].
    :type curve_name: str

.. note::
    The implementation of ECC in this module is based primarily on the following two resources:
      - `Elliptic Curve Cryptography - IIT Kharagpur <https://cse.iitkgp.ac.in/~debdeep/pres/TI/ecc.pdf>`_
      - `NU Math 4527 - Number Theory 2 (Lecture 16) <https://dummit.cos.northeastern.edu/teaching_sp21_4527/4527_lecture_16_elliptic_curve_cryptography_part2.pdf>`_

    Check **References** for the entire list.

.. attention::
    For Montgomery curves (like Curve25519), the signature scheme has not been implemented yet and hence, the ``sign`` and ``verify`` functions do not yield any result. Use the ECC cryptosystem accordingly.

Introduction
------------

Elliptic Curve Cryptography (ECC) is a family of public-key cryptosystems based on the mathematics of elliptic curves. It provides higher security with smaller key sizes compared to other public-key cryptosystems, like RSA, making it more efficient. ECC is widely used in secure communications, including for SSL/TLS certificates, cryptocurrency wallets, and digital signatures. The security of ECC is based on the difficulty of solving the Elliptic Curve Discrete Logarithm Problem (ECDLP).

Mathematical Details
--------------------

ECC Key Generation
^^^^^^^^^^^^^^^^^^

The ECC key generation process involves the following steps:

1. **Choose an elliptic curve**: Select an elliptic curve defined by the equation:

.. math::
  :nowrap:

  \begin{gather*}
  y^2 = x^3 + ax + b \qquad \text{(for Weierstrass curves)}\\
  By^2 = x(x-1)(x-A) \qquad \text{(for Montgomery curves)}
  \end{gather*}

where :math:`a, b, A` and :math:`B` are constants specific to the chosen curve.

2. **Select a base point**: A base point :math:`G` is selected on the curve, which is used to generate other points on the curve.

3. **Choose a private key**: The private key :math:`b` is a randomly selected integer.

4. **Compute the public key**: The public key :math:`B` is computed by multiplying the base point :math:`G` by the private key :math:`b`:

.. math::
   B = b \cdot G

The public key is the point :math:`B` on the elliptic curve, and the private key is the integer :math:`b`.

ECC Encryption/Decryption Process
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- **Encryption**: To encrypt a message :math:`m`, we first encode it onto a point :math:`M` on the curve, by either bruteforcing the next quadratic residue directly from the message integer [for Montgomery curves], or starting after a padding of 128 bits (1 left shifted by 128), as described in the reference [for Weierstrass curves]. We then generate a random integer :math:`k` in the range :math:`[1, (n-1)]`. The ciphertext is computed using the public key :math:`B` as follows:

.. math::
    :nowrap:

    \begin{gather*}
    C_1 = k \cdot G\\
    C_2 = m + k \cdot B
    \end{gather*}

The ciphertext is the pair :math:`(C_1, C_2)`.

- **Decryption**: To decrypt the ciphertext :math:`(C_1, C_2)`, the private key :math:`b` is used to compute:

.. math::
   m = C_2 - b \cdot C_1

.. note::
    For both encryption and decryption, if Montgomery curves are used, we operate only with the X-coordinate of message point to compute :math:`C_2`, and finally take mod with the curve prime :math:`p`, returning :math:`1` for Y-coordinate.

ECC Signature/Verification Process
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- **Signature**: The hash of the plaintext message, :math:`m_h`, is signed using the private key :math:`b` as follows:

.. math::
    :nowrap:

    \begin{gather*}
    r = (k \cdot G)_x \mod n\\
    s = k^{-1} \cdot (m_h + r \cdot b) \mod n
    \end{gather*}

The signature is the pair :math:`(r, s)`.

- **Verification**: To verify a signature :math:`(r, s)` for a message :math:`m` with hash :math:`m_h`, is verified using public key :math:`B` as follows:

.. math::
    :nowrap:

    \begin{gather*}
    v_1 = s^{-1} * m_h \mod n\\
    v_2 = s^{-1} * r \mod n\\
    P = (v_1 \cdot G + v_2 \cdot B)\\
    \end{gather*}

The result of the verification is given by:

.. math::
    r \stackrel{?}{=} P_x \mod n

Usage
-----

.. code-block:: python

    # Example usage of ECC to encrypt, decrypt, sign, and verify a message
    from cryptosystems import ECC
    cipher = ECC()
    public_key, private_key = cipher.generate_keys()  # Generate ECC keys
    ciphertext = cipher.encrypt("Hello World", public_key)
    print(ciphertext)  # (123456, 654321)
    plaintext = cipher.decrypt(ciphertext, private_key, "str")
    print(plaintext)  # 'Hello World'
    signature, message_hash = cipher.sign("Hello World", private_key)
    print(signature, message_hash, sep=", ") # (123456, 654321), b'\x12\x34\x56\x78\x90'
    verification = cipher.verify(signature, message_hash, public_key)
    print(verification)  # True

Methods
-------

.. function:: generate_keypair() -> tuple

    Generates a new ECC key pair, in the form :math:`(B, b)`, where :math:`B` is the public key and :math:`b` is the private key.

    :return: A tuple containing the public key and private key.
    :rtype: tuple

.. function:: encrypt(plaintext: (int | str | bytes), public_key: tuple) -> tuple

    Encrypts the given plaintext using the ECC algorithm and returns the ciphertext.

    :param plaintext: The plaintext message to be encrypted.
    :type plaintext: int | str | bytes
    :param public_key: The public key used for encryption, in the form :math:`B = (x, y)`.
    :type public_key: tuple
    :return: The encrypted ciphertext.
    :rtype: tuple

.. function:: decrypt(ciphertext: tuple, private_key: int, return_type: str) -> (int | str | bytes)

    Decrypts the given ciphertext using the ECC algorithm and returns the deciphered plaintext.

    :param ciphertext: The ciphertext message to be decrypted, in the form :math:`C = (C_1, C_2)`.
    :type ciphertext: tuple
    :param private_key: The private key used for decryption, in the form :math:`b`.
    :type private_key: int
    :param return_type: The type in which plaintext is to be returned. It should be either 'int', 'str', or 'bytes'. Default is 'int'
    :type return_type: str
    :return: The decrypted plaintext.
    :rtype: int | str | bytes

.. function:: sign(message: (int | str | bytes), private_key: int) -> tuple

    Signs the given message using the ECC algorithm and returns the signature and SHA256 hash.

    :param message: The plaintext message to be signed.
    :type message: int | str | bytes
    :param private_key: The private key used for signature, the form :math:`b`.
    :type private_key: int
    :return: The tuple of signature for the message, in the form :math:`(r, s)`, and the SHA256 hash (bytes) of the message.
    :rtype: tuple

.. function:: verify(signature: tuple, message_hash: bytes, public_key: tuple) -> bool

    Verifies the given signature using the ECC algorithm and returns True or False.

    :param signature: The signature to be verified, in the form :math:`(r, s)`.
    :type signature: tuple
    :param message_hash: The SHA256 hash for the message.
    :type message_hash: bytes
    :param public_key: The public key used for verification, in the form :math:`B`.
    :type public_key: tuple
    :return: True or False, the result of whether the signature is valid.
    :rtype: bool

.. function:: get_params() -> tuple

    Returns the parameters of the curve with which the object was instantiated.

    :return: The tuple of curve parameters, in the form :math:`((p, a, b),\: G=(G_x, G_y),\: n,\: \text{curve_name})`, where ``curve_name`` is **"Weierstrass"**, **"Montgomery"**, etc.
    :rtype: tuple


References
----------

- `Elliptic Curve Cryptography - IIT Kharagpur <https://cse.iitkgp.ac.in/~debdeep/pres/TI/ecc.pdf>`_
- `NU Math 4527 - Number Theory 2 (Lecture 16) <https://dummit.cos.northeastern.edu/teaching_sp21_4527/4527_lecture_16_elliptic_curve_cryptography_part2.pdf>`_
- `NIST FIPS PUB 186-5: Digital Signature Standard (DSS) <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf>`_
- `Standard Curve Database - CRoCS <https://neuromancer.sk/std/>`_
- `Elliptic-curve cryptography - Wikipedia <https://en.wikipedia.org/wiki/Elliptic-curve_cryptography>`_
- `Elliptic Curve Digital Signature Algorithm - Wikipedia <https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm>`_
- `EdDSA - Wikipedia <https://en.wikipedia.org/wiki/EdDSA>`_
- `Elliptic-curve Diffie–Hellman - Wikipedia <https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman>`_