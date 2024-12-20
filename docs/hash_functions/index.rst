Hash Functions
==============

This is the index file for hash functions. Hash functions are a fundamental building block in cryptography, providing a fixed-size output (hash value) from an input of any size. The hash functions serve as a direct wrapper around the ``hashlib`` library, designed to provide a unified interface for use alongside the other cryptographic modules within the package. They are implemented in the ``hash_functions`` submodule and can be imported directly from the package.

.. note::

    Currently, the ``cryptosystems`` library supports MD5, SHA-256 and SHA-512 algorithms. Future updates will expand the library to include a broader range of hash functions.

--------------
Introduction
--------------
Hash functions are used in a variety of cryptographic protocols and applications. They take an input (or message) and produce a fixed-size string of characters, which is typically a hexadecimal number. A good cryptographic hash function has several important properties: it is deterministic (the same input always produces the same output), it is fast to compute, it produces a unique hash for different inputs, and it is computationally infeasible to reverse the process (i.e., to find the original input from the hash value).

Hash functions are used in many areas of cryptography, including data integrity verification, digital signatures, message authentication codes (MACs), and password storage. They are also integral to blockchain technologies, where they are used to ensure the immutability of the data.

Some of the most widely used hash functions include:

- **MD5**: Once widely used for integrity checking and digital signatures, MD5 is now considered insecure due to vulnerabilities that allow for hash collisions (two different inputs producing the same hash).
- **SHA-1**: Similar to MD5, SHA-1 was a widely used hash function but has been deprecated due to discovered vulnerabilities in its collision resistance.
- **SHA-2**: The SHA-2 family of hash functions (which includes SHA-256, SHA-384, and SHA-512) is widely used today for cryptographic applications, offering much stronger security than MD5 and SHA-1.
- **SHA-3**: The latest member of the Secure Hash Algorithm family, SHA-3 is based on the Keccak algorithm and offers additional security features and different internal structures compared to SHA-2.
- **BLAKE2**: A cryptographic hash function that is faster than MD5 and SHA-2, while providing similar security. It is often used in applications requiring both speed and security.
- **RIPEMD-160**: A hash function that was designed as an alternative to SHA-1, offering a 160-bit output. It is used in some cryptographic applications, though it is less common than SHA-2.

--------------
Usage Examples
--------------
.. tab-set::

    .. tab-item:: MD5

        .. code-block:: python
                
                # Example usage of MD5 to generate hash
                from cryptosystems import MD5
                md5 = MD5()
                message_hash = md5.hash("Hello World") # b'\xb1\n\x8d\xb1d\xe0uA\x05\xb7\xa9\x9b\xe7.?\xe5'
                file_hash = md5.hash_file("test.txt") # b'\xb1\n\x8d\xb1d\xe0uA\x05\xb7\xa9\x9b\xe7.?\xe5'

    .. tab-item:: SHA256

        .. code-block:: python
                
                # Example usage of SHA256 to generate hash
                from cryptosystems import SHA256
                sha256 = SHA256()
                message_hash = sha256.hash("Hello World") # b'\x7f\x83\xb1e\x7f\xf1\xfcS\xb9-\xc1\x81H\xa1\xd6]\xfc-K\x1f\xa3\xd6w(J\xdd\xd2\x00\x12m\x90i'
                file_hash = sha256.hash_file("test.txt") # b'\x7f\x83\xb1e\x7f\xf1\xfcS\xb9-\xc1\x81H\xa1\xd6]\xfc-K\x1f\xa3\xd6w(J\xdd\xd2\x00\x12m\x90i'

    .. tab-item:: SHA512

        .. code-block:: python
                
                # Example usage of SHA512 to generate hash
                from cryptosystems import SHA512
                sha512 = SHA512()
                message_hash = sha512.hash("Hello World") # b'\x86\x18D\xd6pN\x85s\xfe\xc3M\x96~ \xbc\xfe\xf3\xd4$\xcfH\xbe\x04\xe6\xdc\x08\xf2\xbdX\xc7)t3q\x01^\xad\x89\x1c\xc3\xcf\x1c\x9d4\xb4\x92d\xb5\x10u\x1b\x1f\xf9\xe57\x93{\xc4k]o\xf4\xec\xc8'
                file_hash = sha512.hash_file("test.txt") # b'\x86\x18D\xd6pN\x85s\xfe\xc3M\x96~ \xbc\xfe\xf3\xd4$\xcfH\xbe\x04\xe6\xdc\x08\xf2\xbdX\xc7)t3q\x01^\xad\x89\x1c\xc3\xcf\x1c\x9d4\xb4\x92d\xb5\x10u\x1b\x1f\xf9\xe57\x93{\xc4k]o\xf4\xec\xc8'

--------
Classes
--------
The hash functions implemented in the ``hash_functions`` submodule are:

.. toctree::
    :maxdepth: 1
    
    MD5
    SHA256
    SHA512