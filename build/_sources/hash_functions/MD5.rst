MD5
===

The ``MD5`` class implements the MD5 hash algorithm, as a direct wrapper on top of the functionality provided by ``hashlib``, which is widely used to generate a fixed-size 128-bit hash value from arbitrary input data. Although MD5 is now considered cryptographically broken and unsuitable for further use in security-sensitive applications, it is still used for checksums and verifying data integrity.

.. class:: MD5

    Creates a new MD5 instance.

Introduction
------------

The MD5 (Message Digest Algorithm 5) is a widely used cryptographic hash function that produces a 128-bit hash value, typically rendered as a 32-character hexadecimal number. Originally designed for data integrity verification, MD5 became widely used for checksums and digital signatures. However, due to vulnerabilities such as collision attacks, it is no longer recommended for security-critical applications.

Usage
-----

.. code-block:: python

    # Example usage of MD5 to generate hash
    from cryptosystems import MD5
    md5 = MD5()
    message_hash = md5.hash("Hello World") # b'\xb1\n\x8d\xb1d\xe0uA\x05\xb7\xa9\x9b\xe7.?\xe5'
    file_hash = md5.hash_file("test.txt") # b'\\xb1\\n\\x8d\\xb1d\\xe0uA\\x05\\xb7\\xa9\\x9b\\xe7.?\\xe5'

Methods
-------

.. function:: hash(message: (int | str | bytes)) -> bytes

    Hashes the given message using the MD5 Algorithm and returns the digest.

    :param message: The message to compute the MD5 hash of.
    :type hash_value: int | str | bytes
    :return: The MD5 hash digest of the message.
    :rtype: str

.. function:: hash_file(file: str) -> bytes

    Hashes the given file using the MD5 Algorithm and returns the digest.

    :param file: The original hash value to compare with the computed hash.
    :type file: str
    :return: The MD5 hash digest of the file with the given filename.
    :rtype: str
