from hashlib import md5, sha256, sha512

class MD5:
    """
    A class to hash the given message or file using the MD5 Algorithm.

    Methods
    ------------
    `hash(message: int | str | bytes)` -> bytes:
        Hashes the given message using the MD5 Algorithm and returns the digest.
    `hash_file(file: str)` -> bytes:
        Hashes the given file using the MD5 Algorithm and returns the digest.

    Usage
    ------------
    .. code-block:: python

        # Import the class
        >>> from cryptosystems import MD5
        # Create an object of the class
        >>> md5 = MD5()
        # Hash the message
        >>> md5.hash("Hello World")
        b'\\xb1\\n\\x8d\\xb1d\\xe0uA\\x05\\xb7\\xa9\\x9b\\xe7.?\\xe5'
        >>> md5.hash_file("test.txt")
        b'\\xb1\\n\\x8d\\xb1d\\xe0uA\\x05\\xb7\\xa9\\x9b\\xe7.?\\xe5'
    """

    def __init__(self):
        """
        Usage
        ------------
        .. code-block:: python

            # Import the class
            >>> from cryptosystems import MD5
            # Create an object of the class
            >>> md5 = MD5()
        """
        pass

    def hash(self, message: int | str | bytes) -> bytes:
        """
        Hashes the given message using the MD5 Algorithm and returns the digest.

        Parameters
        ------------
        + message: int, str, bytes
            The message to be hashed.

        Returns
        ------------
        + bytes
            The digest after hashing the message.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> md5 = MD5()
            # Hash the message
            >>> md5.hash("Hello World")
            b'\\xb1\\n\\x8d\\xb1d\\xe0uA\\x05\\xb7\\xa9\\x9b\\xe7.?\\xe5'
        """
        assert isinstance(message, int) or isinstance(message, str) or isinstance(message, bytes), "message should be an integer, string, or bytes."
        if isinstance(message, str):
            message = message.encode()
        elif isinstance(message, int):
            message = int.to_bytes(message, (message.bit_length() + 7) // 8, 'big')
        return md5(message).digest()
    
    def hash_file(self, file: str) -> bytes:
        """
        Hashes the given file using the MD5 Algorithm and returns the digest.

        Parameters
        ------------
        + file: str
            The file to be hashed.

        Returns
        ------------
        + bytes
            The digest after hashing the file.

        Example
        ------------
            .. code-block:: python

            # Create an object of the class
            >>> md5 = MD5()
            # Hash the file
            >>> md5.hash_file("test.txt")
            b'\\xb1\\n\\x8d\\xb1d\\xe0uA\\x05\\xb7\\xa9\\x9b\\xe7.?\\xe5'
        """
        assert isinstance(file, str), "File path should be a string."
        return md5(open(file, 'rb').read()).digest()
    
class SHA256:
    """
    A class to hash the given message or file using the SHA-256 Algorithm.

    Methods
    ------------
    `hash(message: int | str | bytes)` -> bytes:
        Hashes the given message using the SHA-256 Algorithm and returns the digest.
    `hash_file(file: str)` -> bytes:
        Hashes the given file using the SHA-256 Algorithm and returns the digest.

    Usage
    ------------
    .. code-block:: python

        # Import the class
        >>> from cryptosystems import SHA256
        # Create an object of the class
        >>> sha256 = SHA256()
        # Hash the message
        >>> sha256.hash("Hello World!")
        b'\\x7f\\x83\\xb1e\\x7f\\xf1\\xfcS\\xb9-\\xc1\\x81H\\xa1\\xd6]\\xfc-K\\x1f\\xa3\\xd6w(J\\xdd\\xd2\\x00\\x12m\\x90i'
    """

    def __init__(self):
        """
        Usage
        ------------
        .. code-block:: python

            # Import the class
            >>> from cryptosystems import SHA256
            # Create an object of the class
            >>> sha256 = SHA256()
        """
        pass

    def hash(self, message: int | str | bytes) -> bytes:
        """
        Hashes the given message using the SHA-256 Algorithm and returns the digest.

        Parameters
        ------------
        + message: int, str, bytes
            The message to be hashed.

        Returns
        ------------
        + bytes
            The digest after hashing the message.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> sha256 = SHA256()
            # Hash the message
            >>> sha256.hash("Hello World!")
            b'\\x7f\\x83\\xb1e\\x7f\\xf1\\xfcS\\xb9-\\xc1\\x81H\\xa1\\xd6]\\xfc-K\\x1f\\xa3\\xd6w(J\\xdd\\xd2\\x00\\x12m\\x90i'
        """
        assert isinstance(message, int) or isinstance(message, str) or isinstance(message, bytes), "message should be an integer, string, or bytes."
        if isinstance(message, str):
            message = message.encode()
        elif isinstance(message, int):
            message = int.to_bytes(message, (message.bit_length() + 7) // 8, 'big')
        return sha256(message).digest()
    
    def hash_file(self, file: str) -> bytes:
        """
        Hashes the given file using the SHA-256 Algorithm and returns the digest.

        Parameters
        ------------
        + file: str
            The file to be hashed.

        Returns
        ------------
        + bytes
            The digest after hashing the file.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> sha256 = SHA256()
            # Hash the file
            >>> sha256.hash_file("test.txt")
            b'\\x7f\\x83\\xb1e\\x7f\\xf1\\xfcS\\xb9-\\xc1\\x81H\\xa1\\xd6]\\xfc-K\\x1f\\xa3\\xd6w(J\\xdd\\xd2\\x00\\x12m\\x90i'
        """
        assert isinstance(file, str), "File path should be a string."
        return sha256(open(file, 'rb').read()).digest()

class SHA512:
    """
    A class to hash the given message or file using the SHA-512 Algorithm.

    Methods
    ------------
    `hash(message: int | str | bytes)` -> bytes:
        Hashes the given message using the SHA-512 Algorithm and returns the digest.
    `hash_file(file: str)` -> bytes:
        Hashes the given file using the SHA-512 Algorithm and returns the digest.

    Usage
    ------------
    .. code-block:: python

        # Import the class
        >>> from cryptosystems import SHA512
        # Create an object of the class
        >>> sha512 = SHA512()
        # Hash the message
        >>> sha512.hash("Hello World!")
        b'\\x86\\x18D\\xd6pN\\x85s\\xfe\\xc3M\\x96~ \\xbc\\xfe\\xf3\\xd4$\\xcfH\\xbe\\x04\\xe6\\xdc\\x08\\xf2\\xbdX\\xc7)t3q\\x01^\\xad\\x89\\x1c\\xc3\\xcf\\x1c\\x9d4\\xb4\\x92d\\xb5\\x10u\\x1b\\x1f\\xf9\\xe57\\x93{\\xc4k]o\\xf4\\xec\\xc8'
    """

    def __init__(self):
        """
        Usage
        ------------
        .. code-block:: python

            # Import the class
            >>> from cryptosystems import SHA512
            # Create an object of the class
            >>> sha512 = SHA512()
        """
        pass

    def hash(self, message: int | str | bytes) -> bytes:
        """
        Hashes the given message using the SHA-512 Algorithm and returns the digest.

        Parameters
        ------------
        + message: int, str, bytes
            The message to be hashed.

        Returns
        ------------
        + bytes
            The digest after hashing the message.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> sha512 = SHA512()
            # Hash the message
            >>> sha512.hash("Hello World!")
            b'\\x86\\x18D\\xd6pN\\x85s\\xfe\\xc3M\\x96~ \\xbc\\xfe\\xf3\\xd4$\\xcfH\\xbe\\x04\\xe6\\xdc\\x08\\xf2\\xbdX\\xc7)t3q\\x01^\\xad\\x89\\x1c\\xc3\\xcf\\x1c\\x9d4\\xb4\\x92d\\xb5\\x10u\\x1b\\x1f\\xf9\\xe57\\x93{\\xc4k]o\\xf4\\xec\\xc8'
        """
        assert isinstance(message, int) or isinstance(message, str) or isinstance(message, bytes), "message should be an integer, string, or bytes."
        if isinstance(message, str):
            message = message.encode()
        elif isinstance(message, int):
            message = int.to_bytes(message, (message.bit_length() + 7) // 8, 'big')
        return sha512(message).digest()
    
    def hash_file(self, file: str) -> bytes:
        """
        Hashes the given file using the SHA-512 Algorithm and returns the digest.

        Parameters
        ------------
        + file: str
            The file to be hashed.

        Returns
        ------------
        + bytes
            The digest after hashing the file.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> sha512 = SHA512()
            # Hash the file
            >>> sha512.hash_file("test.txt")
            b'\\x86\\x18D\\xd6pN\\x85s\\xfe\\xc3M\\x96~ \\xbc\\xfe\\xf3\\xd4$\\xcfH\\xbe\\x04\\xe6\\xdc\\x08\\xf2\\xbdX\\xc7)t3q\\x01^\\xad\\x89\\x1c\\xc3\\xcf\\x1c\\x9d4\\xb4\\x92d\\xb5\\x10u\\x1b\\x1f\\xf9\\xe57\\x93{\\xc4k]o\\xf4\\xec\\xc8'
        """
        assert isinstance(file, str), "File path should be a string."
        return sha512(open(file, 'rb').read()).digest()
