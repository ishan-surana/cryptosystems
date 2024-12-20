from .functions import getPrime, getRandomRange, find_generator
from .hash_functions import SHA256, SHA512

class RSA:
    """
    A class to encrypt and decrypt the given plaintext and ciphertext using the RSA Algorithm.
    
    Attributes
    ------------
    + bits: int
        Number of bits for the modulus. Primes are generated having half the bits. Default is 2048.
    + force: bool
        Argument to force computations with higher orders of numbers, irrespective of resultant performance.

    Methods
    ------------
    + `generate_keys()` -> tuple:
        Returns a valid RSA public-private keypair, ((n, e), (n, d)).
    + `encrypt(plaintext: int | str | bytes, public_key: tuple)` -> int:
        Encrypts the given plaintext using the RSA Algorithm and returns the ciphertext.
    + `decrypt(ciphertext: int | str | bytes, private_key: tuple, return_type: str)` -> int | str | bytes:
        Decrypts the given ciphertext using the RSA Algorithm and returns the plaintext.
    + `sign(message: int | str | bytes, private_key: tuple)` -> tuple:
        Signs the given message using the RSA Algorithm and returns the signature and SHA256 hash.
    + `verify(signature: int | str | bytes, message_hash: bytes, public_key: tuple)` -> bool:
        Verifies the given signature using the RSA Algorithm and returns True or False.

    Usage
    ------------
    .. code-block:: python

        # Import the class
        >>> from cryptosystems import RSA
        # Create an object of the class
        >>> rsa = RSA()
        >>> public_key, private_key = rsa.generate_keys()
        # Encrypt the plaintext
        >>> ciphertext = rsa.encrypt("plaintext", public_key)
        123456
        # Decrypt the ciphertext
        >>> plaintext = rsa.decrypt(ciphertext, private_key, "str")
        "plaintext"
        # Sign the message
        >>> signature, message_hash = rsa.sign("plaintext", private_key)
        123456, b'\\x12\\x34\\x56\\x78\\x90'
        # Verify the signature
        >>> verification = rsa.verify(signature, message_hash, public_key)
        True
    """

    def __init__(self, bits=2048, force=False):
        """
        Parameters
        ------------
        + bits: int
            Number of bits for the modulus. Primes are generated having half the bits. Default is 2048.
        + force: bool
            Argument to force computations with higher orders of numbers, irrespective of resultant performance.
        
        Usage
        ------------
        .. code-block:: python

            # Import the class
            >>> from cryptosystems import RSA
            # Create an object of the class
            >>> rsa = RSA()
            # OR
            >>> rsa = RSA(2**20, True)
        """
        assert isinstance(bits, int), "bits should be an integer"
        assert bits >= 2, "bits should be >= 2"
        assert isinstance(force, bool), "force should be a bool"
        self.bits = bits
        self.force = force
        if bits > 2**12 and not force:
            raise Exception("Set force=True if count of bits to be used > 2^12.")

    def generate_keys(self) -> tuple:
        """
        Function to return a valid RSA public-private keypair in the form ((n, e), (n, d)).

        Returns
        ------------
        + tuple
            The public and private key tuples, in the form ((n, e), (n, d)).
        
        Usage
        ------------
        .. code-block:: python

            # Import the class
            >>> from cryptosystems import RSA
            # Create an object of the class
            >>> rsa = RSA()
            >>> public_key, private_key = rsa.generate_keys()
        """
        p = getPrime(self.bits // 2, force=self.force)
        q = getPrime(self.bits // 2, force=self.force)
        while p == q:
            q = getPrime(self.bits // 2, force=self.force)
        n = p * q
        phi = (p-1) * (q-1)
        e = 65537
        d = pow(e, -1, phi)
        return ((n, e), (n, d))

    def encrypt(self, plaintext: int | str | bytes, public_key: tuple) -> int:
        """
        Encrypts the given plaintext using the RSA Algorithm and returns the ciphertext.

        Parameters
        ------------
        + plaintext: int, str, bytes
            The plaintext to be encrypted.
        + public_key: tuple
            The public key of the intended recipent of the message, in the form of a tuple (n, e).

        Returns
        ------------
        + int
            The ciphertext after encrypting the plaintext.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> rsa = RSA()
            # Encrypt the plaintext with receiver's public key
            >>> ciphertext = rsa.encrypt("plaintext", public_key)
            123456
        """
        assert isinstance(plaintext, (int, str, bytes)), "Plaintext should be an integer, string, or bytes."
        assert isinstance(public_key, tuple) and len(public_key) == 2 and all([isinstance(x, int) for x in public_key]), "Public key should be a tuple of integers (n, e)."
        if isinstance(plaintext, str):
            plaintext = int.from_bytes(plaintext.encode(), 'big')
        elif isinstance(plaintext, bytes):
            plaintext = int.from_bytes(plaintext, 'big')
        assert plaintext.bit_length() <= self.bits, "Plaintext bits should be less than or equal to instantiated cipher bit size."
        return pow(plaintext, public_key[1], public_key[0])
    
    def decrypt(self, ciphertext: int | str | bytes, private_key: tuple, return_type='int') -> int | str | bytes:
        """
        Decrypts the given ciphertext using the RSA Algorithm and returns the plaintext.

        Parameters
        ------------
        + ciphertext: int, str, bytes
            The ciphertext to be decrypted.
        + private_key: tuple
            The private key of the intended recipent of the message, in the form of a tuple (n, d).
        + return_type: str
            The type of the plaintext to be returned. It should be either 'int', 'str', or 'bytes'. Default is 'int'.

        Returns
        ------------
        + int, str, bytes
            The plaintext after decrypting the ciphertext.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> rsa = RSA()
            # Decrypt the ciphertext with receiver's private_key
            >>> plaintext = rsa.decrypt(ciphertext, private_key, "str")
            "plaintext"
        """
        assert isinstance(ciphertext, (int, str, bytes)), "Ciphertext should be an integer, string, or bytes."
        assert return_type in ['int', 'str', 'bytes'], "return_type should be either 'int', 'str', or 'bytes'."
        assert isinstance(private_key, tuple) and len(private_key) == 2 and all([isinstance(x, int) for x in private_key]), "Private key should be a tuple of integers (n, d)."
        if isinstance(ciphertext, str):
            ciphertext = int.from_bytes(ciphertext.encode(), 'big')
        elif isinstance(ciphertext, bytes):
            ciphertext = int.from_bytes(ciphertext, 'big')
        assert ciphertext.bit_length() <= self.bits, "Ciphertext bits should be less than or equal to instantiated cipher bit size."
        plaintext = pow(ciphertext, private_key[1], private_key[0])
        if return_type == 'str':
            return plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big').decode()
        elif return_type == 'bytes':
            return plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big')
        return plaintext
    
    def sign(self, message: int | str | bytes, private_key: tuple) -> int:
        """
        Signs the given message using the RSA Algorithm and returns the signature and SHA256 hash.

        Parameters
        ------------
        + message: int, str, bytes
            The message to be signed.
        + private_key: tuple
            The private key of the sender of the message, in the form of a tuple (n, d).

        Returns
        ------------
        + signature: int
            The signature after signing the message.
        + message_hash: bytes
            The SHA256 hash of the original message.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> rsa = RSA()
            # Sign the plaintext with sender's private key
            >>> signature, message_hash = rsa.sign("plaintext", private_key)
            123456, b'\\x12\\x34\\x56\\x78\\x90'
        """
        assert isinstance(message, (int, str, bytes)), "Message should be an integer, string, or bytes."
        if isinstance(message, str):
            message = int.from_bytes(message.encode(), 'big')
        elif isinstance(message, bytes):
            message = int.from_bytes(message, 'big')
        assert isinstance(private_key, tuple) and len(private_key) == 2 and all([isinstance(x, int) for x in private_key]), "Private key should be a tuple of integers (n, d)."
        sha = SHA256()
        return (pow(int.from_bytes(sha.hash(message)), private_key[1], private_key[0]), sha.hash(message))
        
    def verify(self, signature: int | str | bytes, message_hash: bytes, public_key: tuple) -> bool:
        """
        Verifies the given signature using the RSA Algorithm and returns True or False.

        Parameters
        ------------
        + signature: int, str, bytes
            The signature to be verified.
        + message_hash: bytes
            The SHA256 hash of the original message.
        + public_key: tuple
            The public key of the sender of the message, in the form of a tuple (n, e).

        Returns
        ------------
        + bool
            If the signature is verfied or not.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> rsa = RSA()
            # Verify the signature with receiver's public key
            >>> verification = rsa.verify(signature, message_hash, public_key)
            True
        """
        assert isinstance(signature, (int, str, bytes)), "Signature should be an integer, string, or bytes."
        assert isinstance(public_key, tuple) and len(public_key) == 2 and all([isinstance(x, int) for x in public_key]), "Public key should be a tuple of integers (n, d)."
        assert isinstance(message_hash, bytes) and len(message_hash) == 32, "Message hash should be in bytes of length 256 bits."
        if isinstance(signature, str):
            signature = int.from_bytes(signature.encode(), 'big')
        elif isinstance(signature, bytes):
            signature = int.from_bytes(signature, 'big')
        int_hash = pow(signature, public_key[1], public_key[0])
        hash_message = int.to_bytes(int_hash, ((int_hash.bit_length())+7)//8)
        return hash_message == message_hash

class ElGamal:
    """
    A class to encrypt and decrypt the given plaintext and ciphertext using the ElGamal Algorithm.
    
    Attributes
    ------------
    + bits: int
        Number of bits for the prime number.
    + force: bool
        Argument to force computations with higher orders of numbers, irrespective of resultant performance.

    Methods
    ------------
    + `generate_keys(bits: int, force: bool)` -> tuple:
        Returns a valid ElGamal public-private keypair, ((p, g, h), (p, g, x)).
    + `encrypt(plaintext: int | str | bytes, public_key: tuple)` -> tuple:
        Encrypts the given plaintext using the ElGamal Algorithm and returns the ciphertext tuple (c1, c2).
    + `decrypt(ciphertext: tuple, private_key: tuple, return_type: str)` -> int | str | bytes:
        Decrypts the given ciphertext using the ElGamal Algorithm and returns the plaintext.
    + `sign(message: int | str | bytes, private_key: tuple)` -> tuple:
        Signs the given message using the ElGamal Algorithm and returns the signature and SHA256 hash.
    + `verify(signature: tuple, message_hash: bytes, public_key: tuple)` -> bool:
        Verifies the given signature using the ElGamal Algorithm and returns True or False.

    Usage
    ------------
    .. code-block:: python

        # Import the class
        >>> from cryptosystems import ElGamal
        # Create an object of the class
        >>> elgamal = ElGamal()
        >>> public_key, private_key = elgamal.generate_keys()
        # Encrypt the plaintext
        >>> ciphertext = elgamal.encrypt("plaintext", public_key)
        (123456, 654321)
        # Decrypt the ciphertext
        >>> plaintext = elgamal.decrypt(ciphertext, private_key, "str")
        "plaintext"
        # Sign the message
        >>> signature, message_hash = elgamal.sign("plaintext", private_key)
        (123456, 654321), b'\\x12\\x34\\x56\\x78\\x90'
        # Verify the signature
        >>> verification = elgamal.verify(signature, message_hash, public_key)
        True
    """

    def __init__(self, bits=2048, force=False):
        """
        Parameters
        ------------
        + bits: int
            Number of bits for the prime number.
        + force: bool
            Argument to force computations with higher orders of numbers, irrespective of resultant performance.
        
        Usage
        ------------
        .. code-block:: python

            # Import the class
            >>> from cryptosystems import ElGamal
            # Create an object of the class
            >>> elgamal = ElGamal()
            # OR
            >>> elgamal = ElGamal(2**20, True)
        """
        assert isinstance(bits, int), "bits should be an integer"
        assert bits >= 2, "bits should be >= 2"
        assert isinstance(force, bool), "force should be a bool"
        self.bits = bits
        self.force = force
        if bits > 2**11 and not force:
            raise Exception("Set force=True if count of bits to be used > 2^11.")

    def generate_keys(self) -> tuple:
        """
        Function to return a valid ElGamal public-private keypair in the form ((p, g, h), (p, g, x)).

        Returns
        ------------
        + tuple
            The public and private key tuples, in the form ((p, g, h), (p, g, x)).

        Usage
        ------------
        .. code-block:: python

            # Import the class
            >>> from cryptosystems import ElGamal
            # Create an object of the class
            >>> elgamal = ElGamal()
            >>> public_key, private_key = elgamal.generate_keys()
        """
        p = getPrime(self.bits, force=self.force)
        g = find_generator(p)
        x = getRandomRange(1, p-1, force=self.force)
        h = pow(g, x, p)
        return ((p, g, h), (p, g, x))
    
    def encrypt(self, plaintext: int | str | bytes, public_key: tuple) -> tuple:
        """
        Encrypts the given plaintext using the ElGamal Algorithm and returns the ciphertext.

        Parameters
        ------------
        + plaintext: int, str, bytes
            The plaintext to be encrypted.
        + public_key: tuple
            The public key of the intended recipent of the message, in the form of a tuple (p, g, h).

        Returns
        ------------
        + tuple
            The ciphertext tuple formed after encrypting the plaintext.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> elgamal = ElGamal()
            # Encrypt the plaintext
            >>> ciphertext = elgmal.encrypt("plaintext", public_key)
            (123456, 654321)
        """
        assert isinstance(plaintext, (int, str, bytes)), "Plaintext should be an integer, string, or bytes."
        assert isinstance(public_key, tuple) and len(public_key) == 3 and all([isinstance(x, int) for x in public_key]), "Public key should be a tuple of integers (p, g, h)."
        if isinstance(plaintext, str):
            plaintext = int.from_bytes(plaintext.encode(), 'big')
        elif isinstance(plaintext, bytes):
            plaintext = int.from_bytes(plaintext, 'big')
        assert plaintext.bit_length() <= self.bits, "Plaintext bits should be less than or equal to instantiated cipher bit size."
        p, g, h = public_key
        k = getRandomRange(1, p-1, force=self.force)
        c1 = pow(g, k, p)
        c2 = (plaintext * pow(h, k, p)) % p
        return (c1, c2)
    
    def decrypt(self, ciphertext: tuple, private_key: tuple, return_type='int') -> int | str | bytes:
        """
        Decrypts the given ciphertext using the ElGamal Algorithm and returns the plaintext.

        Parameters
        ------------
        + ciphertext: tuple
            The ciphertext to be decrypted.
        + private_key: tuple
            The private key of the intended recipent of the message, in the form of a tuple (p, g, x).
        + return_type: str
            The type of the plaintext to be returned. It should be either 'int', 'str', or 'bytes'.

        Returns
        ------------
        + int, str, bytes
            The plaintext after decrypting the ciphertext.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> elgamal = ElGamal()
            # Decrypt the ciphertext
            >>> plaintext = elgamal.decrypt(ciphertext, private_key, "str")
            "plaintext"
        """
        assert isinstance(private_key, tuple) and len(private_key) == 3 and all([isinstance(x, int) for x in private_key]), "Public key should be a tuple of integers (p, g, x)."
        assert isinstance(ciphertext, tuple) and len(ciphertext) == 2 and all([isinstance(x, int) for x in ciphertext]), "Ciphertext should be a tuple of integers (c1, c2)."
        assert all([x.bit_length() <= self.bits for x in ciphertext]), "Ciphertext tuple bits should be less than or equal to instantiated cipher bit size."
        assert return_type in ['int', 'str', 'bytes'], "return_type should be either 'int', 'str', or 'bytes'."
        c1, c2 = ciphertext
        p, g, x = private_key
        plaintext = (c2 * pow(c1, p-1-x, p)) % p
        if return_type == 'str':
            return plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big').decode()
        elif return_type == 'bytes':
            return plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big')
        return plaintext
    
    def sign(self, message: int | str | bytes, private_key: tuple) -> tuple:
        """
        Signs the given message using the ElGamal Algorithm and returns the signature and SHA256 hash.

        Parameters
        ------------
        + message: int, str, bytes
            The message to be signed.
        + private_key: tuple
            The private key of the sender of the message, in the form of a tuple (p, g, x).

        Returns
        ------------
        + signature: int
            The signature after signing the message.
        + message_hash: bytes
            The SHA256 hash of the original message.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> elgamal = ElGamal()
            # Sign the message
            >>> signature, message_hash = elgamal.sign("plaintext", private_key)
            (123456, 654321), b'\\x12\\x34\\x56\\x78\\x90'
        """
        assert isinstance(message, (int, str, bytes)), "Message should be an integer, string, or bytes."
        assert isinstance(private_key, tuple) and len(private_key) == 3 and all([isinstance(x, int) for x in private_key]), "Private key should be a tuple of integers (p, g, x)."
        if isinstance(message, str):
            message = int.from_bytes(message.encode(), 'big')
        elif isinstance(message, bytes):
            message = int.from_bytes(message, 'big')
        p, g, x = private_key
        k = getRandomRange(1, p-1, force=self.force)
        while True:
            try:
                pow(k, -1, p-1) # k and (p-1) should be coprime, ie k^-1 should exist mod (p-1)
                break
            except ValueError:
                k = getRandomRange(1, p-1, force=self.force)
        sha = SHA256()
        s1 = pow(g, k, p)
        s2 = ((int.from_bytes(sha.hash(message), 'big') - x*s1) * pow(k, -1, p-1)) % (p-1)
        return ((s1, s2), sha.hash(message))
    
    def verify(self, signature: tuple, message_hash: bytes, public_key: tuple) -> bool:
        """
        Verifies the given signature using the ElGamal Algorithm and returns True or False.

        Parameters
        ------------
        + signature: tuple
            The signature to be verified.
        + message_hash: bytes
            The SHA256 hash of the original message.
        + public_key: tuple
            The public key of the sender of the message, in the form of a tuple (p, g, h).

        Returns
        ------------
        + bool
            If the signature is verfied or not.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> elgamal = ElGamal()
            # Verify the signature
            >>> verification = elgamal.verify(signature, message_hash, public_key)
            True
        """
        assert isinstance(signature, tuple) and len(signature) == 2 and all([isinstance(x, int) for x in signature]), "Signature should be a tuple of integers (s1, s2)."
        assert isinstance(public_key, tuple) and len(public_key) == 3 and all([isinstance(x, int) for x in public_key]), "Public key should be a tuple of integers (p, g, x)."
        assert all([x.bit_length() <= self.bits for x in signature]), "Signature tuple bits should be less than or equal to instantiated cipher bit size."
        assert isinstance(message_hash, bytes) and len(message_hash) == 32, "Message hash should be in bytes of length 256 bits."
        s1, s2 = signature
        p, g, h = public_key
        v1 = pow(g, int.from_bytes(message_hash, 'big'), p)
        v2 = (pow(h, s1, p) * pow(s1, s2, p)) % p
        return v1 == v2

class Rabin:
    """
    A class to encrypt and decrypt the given plaintext and ciphertext using the Rabin Algorithm.
    
    Attributes
    ------------
    + bits: int
        Number of bits for the prime numbers.
    + force: bool
        Argument to force computations with higher orders of numbers, irrespective of resultant performance.

    Methods
    ------------
    + `generate_keys()` -> tuple:
        Returns a valid Rabin public-private keypair, (n, (p, q)).
    + `encrypt(plaintext: int | str | bytes, public_key: int)` -> int:
        Encrypts the given plaintext using the Rabin Algorithm and returns the ciphertext.
    + `decrypt(ciphertext: int | str | bytes, private_key: tuple, return_type: str)` -> list: int | str | bytes:
        Decrypts the given ciphertext using the Rabin Algorithm and returns the plaintext.
    + `sign(message: int | str | bytes, private_key: tuple)` -> tuple:
        Signs the given message using the Rabin Algorithm and returns the signature and SHA256 hash.
    + `verify(signature: int | str | bytes, message_hash: bytes, public_key: int)` -> bool:
        Verifies the given signature using the Rabin Algorithm and returns True or False.
    
    Usage
    ------------
    .. code-block:: python

        # Import the class
        >>> from cryptosystems import Rabin
        # Create an object of the class
        >>> rabin = Rabin()
        >>> public_key, private_key = rabin.generate_keys()
        # Encrypt the plaintext
        >>> ciphertext, message_hash = rabin.encrypt("plaintext", public_key)
        123456, b'\\x12\\x34\\x56\\x78\\x90'
        # Decrypt the ciphertext
        >>> plaintext = rabin.decrypt(ciphertext, message_hash, private_key, "str")
        "plaintext"
        # Sign the message
        >>> signature, message_hash = rabin.sign("plaintext", private_key)
        123456, b'\\x12\\x34\\x56\\x78\\x90'
        # Verify the signature
        >>> verification = rabin.verify(123456, message_hash, public_key)
        True
    """

    def __init__(self, bits=2048, force=False):
        """
        Parameters
        ------------
        + bits: int
            Number of bits for the modulus. Primes are generated having half the bits. Default is 2048.
        + force: bool
            Argument to force computations with higher orders of numbers, irrespective of resultant performance.

        Usage
        --------
        .. code-block:: python

            # Import the class
            >>> from cryptosystems import Rabin
            # Create an object of the class
            >>> rabin = Rabin()
            # OR
            >>> rabin = Rabin(2**20, True)
        """
        self.bits = bits
        self.force = force
        if bits > 2**12 and not force:
            raise Exception("Set force=True if count of bits to be used > 2^12.")

    def generate_keys(self) -> tuple:
        """
        Function to return a valid Rabin public-private keypair in the form (n, (p, q)).

        Parameters
        ------------
        + bits: int
            Number of bits for the modulus. Primes are generated having half the bits. Default is 2048.
        + force: bool
            Argument to force computations with higher orders of numbers, irrespective of resultant performance.

        Returns
        ------------
        + tuple
            The public and private key tuples, in the form (n, (p, q)).
        
        Usage
        ------------
        .. code-block:: python

            # Import the class
            >>> from cryptosystems import Rabin
            # Create an object of the class
            >>> rabin = RSA()
            >>> public_key, private_key = rabin.generate_keys()
            # OR
            >>> public_key, private_key = rabin.generate_keys(2048)
        """
        p = getPrime(self.bits // 2, force=self.force)
        q = getPrime(self.bits // 2, force=self.force)
        while p == q or p % 4 != 3 or q % 4 != 3:
            p = getPrime(self.bits // 2, force=self.force)
            q = getPrime(self.bits // 2, force=self.force)
        n = p * q
        return (n, (p, q))

    def encrypt(self, plaintext: int | str | bytes, public_key: int) -> tuple:
        """
        Encrypts the given plaintext using the Rabin Algorithm and returns the ciphertext and hash of plaintext.

        Parameters
        ------------
        + plaintext: int, str, bytes
            The plaintext to be encrypted.
        + public_key: int
            The public key of the intended recipent of the message, in the form of a integer n.

        Returns
        ------------
        + ciphertext: int
            The ciphertext after encrypting the plaintext.
        + message_hash: bytes
            Hash of the plaintext message

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> rabin = Rabin()
            # Encrypt the plaintext with receiver's public key
            >>> ciphertext, message_hash = rabin.encrypt("plaintext", public_key)
            123456, b'\\x12\\x34\\x56\\x78\\x90'
        """
        assert isinstance(plaintext, (int, str, bytes)), "Plaintext should be an integer, string, or bytes."
        assert isinstance(public_key, int), "Public key should be an integer n."
        # self.return_type = type(plaintext).__name__
        if isinstance(plaintext, str):
            plaintext = int.from_bytes(plaintext.encode(), 'big')
        elif isinstance(plaintext, bytes):
            plaintext = int.from_bytes(plaintext, 'big')
        assert plaintext.bit_length() <= self.bits, "Plaintext bits should be less than or equal to instantiated cipher bit size."
        sha = SHA256()
        return (pow(plaintext, 2, public_key), sha.hash(plaintext))

    def decrypt(self, ciphertext: int | str | bytes, message_hash: bytes, private_key: tuple, return_type='int', get_all=False) -> int | str | bytes:
        """
        Decrypts the given ciphertext using the Rabin Algorithm and returns the plaintext.

        Parameters
        ------------
        + ciphertext: int, str, bytes
            The ciphertext to be decrypted.
        + message_hash: bytes
            The hash of the original plaintext, used to verify the correct plaintext.
        + private_key: int
            The private key of the intended recipent of the message, in the form of a tuple (p, q).
        + return_type: str
            The type of the plaintext to be returned. It should be either 'int', 'str', or 'bytes'. If not specified, assumed same as type of plaintext argument given during encrypt.
        + get_all: bool
            Whether to return all possible plaintexts or not. Default is False. If True, it will return all possible plaintexts.

        Returns
        ------------
        + int | str | bytes OR list: int, str, bytes
            The plaintext after decrypting the ciphertext.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> rabin = Rabin()
            # Decrypt the ciphertext
            >>> plaintext = rabin.decrypt(ciphertext, message_hash, private_key, "str")
            "plaintext"
        """
        # if return_type is None:
        #     return_type = self.return_type
        # assert return_type == self.return_type, "ciphertext should be of the same type as the plaintext used for encryption."
        assert isinstance(ciphertext, (int, str, bytes)), "Ciphertext should be an integer, string, or bytes."
        if isinstance(ciphertext, str):
            ciphertext = int.from_bytes(ciphertext.encode(), 'big')
        elif isinstance(ciphertext, bytes):
            ciphertext = int.from_bytes(ciphertext, 'big')
        assert ciphertext.bit_length() <= self.bits, "Ciphertext bits should be less than or equal to instantiated cipher bit size."
        assert isinstance(message_hash, bytes) and len(message_hash) == 32, "Message hash should be in bytes of length 256 bits."
        assert isinstance(private_key, tuple) and len(private_key) == 2 and all([isinstance(x, int) for x in private_key]), "Private key should be a tuple of integers (p, q)."
        p, q = private_key
        n = p * q
        a = pow(ciphertext, (p+1)//4, p)
        b = pow(ciphertext, (q+1)//4, q)
        y_p = pow(q, -1, p)
        x_q = pow(p, -1, q)
        p1 = (a * q * y_p + b * p * x_q) % n
        p2 = (a * q * y_p - b * p * x_q) % n
        p3 = -p1 % n
        p4 = -p2 % n
        plaintexts = [p1, p2, p3, p4]
        sha = SHA256()
        if return_type == 'str':
            if not get_all:
                for plaintext in plaintexts:
                    try:
                        if sha.hash(plaintext) == message_hash:
                            return plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big').decode()
                    except:
                        pass
                raise Exception("Invalid ciphertext for 'str' format.")

        elif return_type == 'bytes':
            if not get_all:
                for plaintext in plaintexts:
                    try:
                        if sha.hash(plaintext) == message_hash:
                            return plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big')
                    except:
                        pass
                raise Exception("Invalid ciphertext for 'bytes' format.")
                    
        if not get_all:
            for plaintext in plaintexts:
                if sha.hash(plaintext) == message_hash:
                    return plaintext
        return plaintexts

    def sign(self, message: int | str | bytes, private_key: tuple) -> int:
        """
        Signs the given message using the Rabin Algorithm and returns the signature and SHA256 hash.

        Parameters
        ------------
        + message: int, str, bytes
            The message to be signed.
        + private_key: tuple
            The private key of the sender of the message, in the form of a tuple (p, q).

        Returns
        ------------
        + signature: int
            The signature after signing the message.
        + message_hash: bytes
            The SHA256 hash of the original message.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> rabin = Rabin()
            # Sign the plaintext with sender's private key
            >>> signature, hash = rabin.sign("plaintext", private_key)
            123456, b'\\x12\\x34\\x56\\x78\\x90'
        """
        assert isinstance(message, (int, str, bytes)), "Message should be an integer, string, or bytes."
        if isinstance(message, str):
            message = int.from_bytes(message.encode(), 'big')
        elif isinstance(message, bytes):
            message = int.from_bytes(message, 'big')
        assert isinstance(private_key, tuple) and len(private_key) == 2 and all([isinstance(x, int) for x in private_key]), "Private key should be a tuple of integers (p, q)."
        sha = SHA256()
        message_hash = sha.hash(message)
        p, q = private_key
        n = p * q
        y_p = pow(q, -1, p)
        x_q = pow(p, -1, q)
        residue = pow(int.from_bytes(message_hash), 2, n) # Quadratic residue of the message hash
        a = pow(residue, (p+1)//4, p) # Root of residue using Lagrange's simplified solution if p%4=3
        b = pow(residue, (q+1)//4, q)
        signature = (a * q * y_p + b * p * x_q) % n
        return (signature, message_hash)
        
    def verify(self, signature: int | str | bytes, message_hash: bytes, public_key: int) -> bool:
        """
        Verifies the given signature using the Rabin Algorithm and returns True or False.

        Parameters
        ------------
        + signature: int, str, bytes
            The signature to be verified.
        + message_hash: bytes
            The SHA256 hash of the original message.
        + public_key: int
            The public key of the sender of the message, in the form of an integer n.

        Returns
        ------------
        + bool
            If the signature is verfied or not.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> rabin = Rabin()
            # Verify the signature with receiver's public key
            >>> verification = rabin.verify(signature, message_hash, public_key)
            True
        """
        assert isinstance(signature, (int, str, bytes)), "Signature should be an integer, string, or bytes."
        assert isinstance(public_key, int), "Public key should be an integer (n, d)."
        assert isinstance(message_hash, bytes) and len(message_hash) == 32, "Message hash should be in bytes of length 256 bits."
        if isinstance(signature, str):
            signature = int.from_bytes(signature.encode(), 'big')
        elif isinstance(signature, bytes):
            signature = int.from_bytes(signature, 'big')
        hash_message = int.from_bytes(message_hash)
        n = public_key
        return pow(hash_message, 2, n) == pow(signature, 2, n)

class Paillier:
    """
    A class to encrypt and decrypt the given plaintext and ciphertext using the Paillier Cryptosystem.
    
    Attributes
    ------------
    + bits: int
        Number of bits for the modulus. Primes are generated having half the bits. Default is 2048.
    + force: bool
        Argument to force computations with higher orders of numbers, irrespective of resultant performance.

    Methods
    ------------
    + `generate_keys(bits: int, force: bool)` -> tuple:
        Returns a valid Paillier public-private keypair, ((n, g), (n, y, u)).
    + `encrypt(plaintext: int | str | bytes, public_key: tuple)` -> int:
        Encrypts the given plaintext using the Paillier Algorithm and returns the ciphertext.
    + `decrypt(ciphertext: int | str | bytes, private_key: tuple, return_type: str)` -> int | str | bytes:
        Decrypts the given ciphertext using the Paillier Algorithm and returns the plaintext.
    + `sign(message: int | str | bytes, private_key: tuple)` -> tuple:
        Signs the given message using the Paillier Algorithm and returns the signature and SHA256 hash.
    + `verify(signature: int | str | bytes, message_hash: bytes, public_key: tuple)` -> bool:
        Verifies the given signature using the Paillier Algorithm and returns True or False.
    + `homomorphic_add(ciphertext1: int | str | bytes, ciphertext2: int | str | bytes)` -> int:
        Performs homomorphic addition on the given ciphertexts and returns the result.

    Usage
    ------------
    .. code-block:: python

        # Import the class
        >>> from cryptosystems import Paillier
        # Create an object of the class
        >>> paillier = Paillier()
        >>> public_key, private_key = paillier.generate_keys()
        # Encrypt the plaintext
        >>> ciphertext = paillier.encrypt("plaintext", public_key)
        123456
        # Decrypt the ciphertext
        >>> plaintext = paillier.decrypt(123456, private_key, "str")
        "plaintext"
        # Sign the message
        >>> signature, message_hash = paillier.sign("plaintext", private_key)
        123456, b'\\x12\\x34\\x56\\x78\\x90'
        # Verify the signature
        >>> verification = paillier.verify(123456, message_hash, public_key)
        True
        >>> addition = paillier.homomorphic_add(paillier.encrypt(100, public_key), paillier.encrypt(200, public_key), public_key)
        >>> result = paillier.decrypt(addition, private_key, "int")
        300
    """

    def __init__(self, bits=2048, force=False):
        """
        Parameters
        ------------
        + bits: int
            Number of bits for the modulus. Primes are generated having half the bits. Default is 2048.
        + force: bool
            Argument to force computations with higher orders of numbers, irrespective of resultant performance.
        
        Usage
        ------------
        .. code-block:: python

            # Import the class
            >>> from cryptosystems import Paillier
            # Create an object of the class
            >>> paillier = Paillier()
            # OR
            >>> paillier = Paillier(2**20, True)
        """
        assert isinstance(bits, int), "bits should be an integer"
        assert bits >= 2, "bits should be >= 2"
        assert isinstance(force, bool), "force should be a bool"
        self.bits = bits
        self.force = force
        if bits > 2**12 and not force:
            raise Exception("Set force=True if count of bits to be used > 2^12.")

    def generate_keys(self) -> tuple:
        """
        Function to return a valid Paillier public-private keypair in the form ((n, g), (n, y, u)).

        Returns
        ------------
        + tuple
            The public and private key tuples, in the form ((n, g), (n, y, u)).
        
        Usage
        ------------
        .. code-block:: python

            # Import the class
            >>> from cryptosystems import Paillier
            # Create an object of the class
            >>> paillier = Paillier()
            >>> public_key, private_key = paillier.generate_keys()
            # OR
            >>> public_key, private_key = paillier.generate_keys(2048)
        """
        p = getPrime(self.bits // 2, force=self.force)
        q = getPrime(self.bits // 2, force=self.force)
        while p == q:
            q = getPrime(self.bits // 2, force=self.force)
        n = p * q
        g = n + 1
        y = (p - 1) * (q - 1)
        u = pow(y, -1, n)
        return ((n, g), (n, y, u))

    def encrypt(self, plaintext: int | str | bytes, public_key: tuple) -> int:
        """
        Encrypts the given plaintext using the Paillier Cryptosystem and returns the ciphertext.

        Parameters
        ------------
        + plaintext: int, str, bytes
            The plaintext to be encrypted.
        + public_key: tuple
            The public key of the intended recipent of the message, in the form of a tuple (n, g).

        Returns
        ------------
        + int
            The ciphertext after encrypting the plaintext.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> pailier = Paillier()
            # Encrypt the plaintext with receiver's public key
            >>> ciphertext = pailier.encrypt("plaintext", public_key)
            123456
        """
        assert isinstance(plaintext, (int, str, bytes)), "Plaintext should be an integer, string, or bytes."
        assert isinstance(public_key, tuple) and len(public_key) == 2 and all([isinstance(x, int) for x in public_key]), "Public key should be a tuple of integers (n, g)."
        if isinstance(plaintext, str):
            plaintext = int.from_bytes(plaintext.encode(), 'big')
        elif isinstance(plaintext, bytes):
            plaintext = int.from_bytes(plaintext, 'big')
        assert plaintext.bit_length() <= self.bits, "Plaintext bits should be less than or equal to instantiated cipher bit size."
        n, g = public_key
        r = getRandomRange(1, n, force=self.force)
        return ((pow(g, plaintext, n**2) * pow(r, n, n**2)) % (n**2))

    def decrypt(self, ciphertext: int | str | bytes, private_key: tuple, return_type='int') -> int | str | bytes:
        """
        Decrypts the given ciphertext using the Paillier Cryptosystem and returns the plaintext.

        Parameters
        ------------
        + ciphertext: int, str, bytes
            The ciphertext to be decrypted.
        + private_key: tuple
            The private key of the intended recipent of the message, in the form of a tuple (n, y, u).
        + return_type: str
            The type of the plaintext to be returned. It should be either 'int', 'str', or 'bytes'.
        
        Returns
        ------------
        + int, str, bytes
            The plaintext after decrypting the ciphertext.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> pailier = Paillier()
            # Decrypt the ciphertext with receiver's private key
            >>> plaintext = pailier.decrypt(123456, private_key, "str")
            "plaintext"
        """
        assert isinstance(ciphertext, (int, str, bytes)), "Ciphertext should be an integer, string, or bytes."
        assert return_type in ['int', 'str', 'bytes'], "return_type should be either 'int', 'str', or 'bytes'."
        assert isinstance(private_key, tuple) and len(private_key) == 3 and all([isinstance(x, int) for x in private_key])
        if isinstance(ciphertext, str):
            ciphertext = int.from_bytes(ciphertext.encode(), 'big')
        elif isinstance(ciphertext, bytes):
            ciphertext = int.from_bytes(ciphertext, 'big')
        assert ciphertext.bit_length() <= (2 * self.bits), "Ciphertext bits should be less than or equal to twice the instantiated cipher bit size."
        n, y, u = private_key
        x = (pow(ciphertext, y, n**2) - 1) // n
        plaintext = (x * u) % n
        if return_type == 'str':
            return plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big').decode()
        elif return_type == 'bytes':
            return plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big')
        return plaintext

    def sign(self, message: int | str | bytes, private_key: tuple) -> int:
        """
        Signs the given message using the Paillier Cryptosystem and returns the signature.

        Parameters
        ------------
        + message: int, str, bytes
            The message to be signed.
        + private_key: tuple
            The private key of the intended recipent of the message, in the form of a tuple (n, y, u).

        Returns
        ------------
        + int
            The signature after signing the message.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> pailier = Paillier()
            # Sign the plaintext with sender's private key
            >>> signature, hash = paillier.sign("plaintext", private_key)
            123456, b'\\x12\\x34\\x56\\x78\\x90'
        """
        raise Exception("Paillier signing NOT implemented yet!")
        pass

    def verify(self, signature: int | str | bytes, message_hash: bytes, public_key: tuple) -> int | str | bytes:
        """
        Verifies the given signature using the Paillier Cryptosystem and returns the message.

        Parameters
        ------------
        + signature: int, str, bytes
            The signature to be verified.
        + message_hash: bytes
            The SHA256 hash of the original message.
        + public_key: tuple
            The public key of the sender of the message, in the form of a tuple (n, g).

        Returns
        ------------
        + int, str, bytes
            The message after verifying the signature.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> pailier = Paillier(1024)
            # Verify the signature
            >>> verification = pailier.verify(1234567890)
            123
        """
        raise Exception("Paillier verification NOT implemented yet!")
        pass
    
    def homomorphic_add(self, ciphertext1: int | str | bytes, ciphertext2: int | str | bytes, public_key: tuple) -> int:
        """
        Performs homomorphic addition on the given ciphertexts and returns the result. Decryption will return the sum of the plaintexts.

        Parameters
        ------------
        + ciphertext1: int, str, bytes
            The first ciphertext.
        + ciphertext2: int, str, bytes
            The second ciphertext.
        + public_key: tuple
            The public key of the sender of the message, in the form of a tuple (n, g).

        Returns
        ------------
        + int
            The result of homomorphic addition on the given ciphertexts.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> pailier = Paillier()
            # Perform homomorphic addition
            >>> addition = pailier.homomorphic_add(123456, 654321, public_key) # Assume ciphertexts for 100 and 200
            567890
            >>> result = pailier.decrypt(addition, private_key)
            300
        """
        assert isinstance(ciphertext1, (int, str, bytes)), "Ciphertext1 should be an integer, string, or bytes."
        assert isinstance(ciphertext2, (int, str, bytes)), "Ciphertext2 should be an integer, string, or bytes."
        assert isinstance(public_key, tuple) and len(public_key) == 2 and all([isinstance(x, int) for x in public_key]), "Public key should be a tuple of integers (n, g)."
        if isinstance(ciphertext1, str):
            ciphertext1 = int.from_bytes(ciphertext1.encode(), 'big')
        elif isinstance(ciphertext1, bytes):
            ciphertext1 = int.from_bytes(ciphertext1, 'big')
        if isinstance(ciphertext2, str):
            ciphertext2 = int.from_bytes(ciphertext2.encode(), 'big')
        elif isinstance(ciphertext2, bytes):
            ciphertext2 = int.from_bytes(ciphertext2, 'big')
        return (ciphertext1 * ciphertext2) % (public_key[0]**2)

class ECC:
    """
    A class to encrypt and decrypt the given plaintext and ciphertext using the Elliptic Curve Cryptography.

    Attributes
    ------------
    + curve_name: str
        The name of the curve. Can currently operate only with P-256 (also known as secp256r1) [default], Curve25519, and secp256k1.
    + curve: tuple
        The parameters of the curve.
    + G: tuple
        The generator point.
    + n: int
        The order of the curve.
    + curve_type: str
        The type of elliptic curve, Montogomery, Weierstrass, Edwards, etc.

    Methods
    ------------
    `encrypt(plaintext: int | str | bytes, public_key: tuple)` -> tuple:
        Encrypts the given plaintext using the Elliptic Curve Cryptography and returns the ciphertext.
    `decrypt(ciphertext: tuple, private_key: tuple, return_type: str)` -> int | str | bytes:
        Decrypts the given ciphertext using the Elliptic Curve Cryptography and returns the plaintext.
    `sign(message: int | str | bytes, private_key: tuple)` -> tuple:
        Signs the given message using the Elliptic Curve Cryptography and returns the signature and SHA256 hash.
    `verify(signature: tuple, message_hash: bytes, public_key: tuple)` -> int | str | bytes:
        Verifies the given signature using the Elliptic Curve Cryptography and returns the message.
    `get_params()` -> tuple:
        Returns the parameters of the curve with which the object was instantiated.

    Usage
    ------------
    .. code-block:: python

        # Import the class
        >>> from cryptosystems import ECC
        # Create an object of the class
        >>> ecc = ECC()
        >>> public_key, private_key = ecc.generate_keys()
        # Encrypt the plaintext
        >>> ciphertext = ecc.encrypt("plaintext", public_key)
        ((123, 456), (654, 321))
        # Decrypt the ciphertext
        >>> plaintext = ecc.decrypt(ciphertext, private_key, "str")
        "plaintext"
        >>> signature, message_hash = ecc.sign("plaintext", private_key)
        (123456, 654321), b'\\x12\\x34\\x56\\x78\\x90'
        >>> verification = ecc.verify(signature, message_hash, public_key)
        True
    """

    def __init__(self, curve_name='P-256'):
        """
        Parameters
        -----------
        + curve_name: str
            The name of elliptic curve to be used. Options are currently limited to the list ['Curve25519', 'P-256', 'secp256k1'], with 'P-256' as default.

        Usage
        ------------
        .. code-block:: python

            # Import the class
            >>> from cryptosystems import ECC
            # Create an object of the class
            >>> ecc = ECC()
            # or using curve name specifically
            >>> ecc = ECC("secp256k1")
        """
        self.curve_choices = ['Curve25519', 'P-256', 'secp256k1']
        assert isinstance(curve_name, str) and curve_name in ["Curve25519", "P-256", "secp256k1"], f"Curve name must be a string and can only be one of the following specified options: {self.curve_choices}"
        
        G = {
            "Curve25519": (0x09, 0x20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9),
            "P-256": (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296, 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5),
            "secp256k1": (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
        }
        curve = {
            "Curve25519": (0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED, 0x76D06, 0x1),
            "P-256": (0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,  0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC, 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B),
            "secp256k1": (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F, 0x0, 0x7)
        } # curve = (p, a, b)
        n = {
            "Curve25519": 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED,
            "P-256": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
            "secp256k1": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        }
        curve_type = {
            "Curve25519": "Montgomery",
            "P-256": "Weierstrass",
            "secp256k1": "Weierstrass"
        }

        self.G = G[curve_name]
        self.curve = curve[curve_name]
        self.n = n[curve_name]
        self.curve_type = curve_type[curve_name]

    def generate_keys(self) -> tuple:
        """
        Function to return a valid ECC public-private keypair in the form (B, b).

        Returns
        ------------
        + tuple
            The public and private key tuples, in the form (B, b).
        
        Usage
        ------------
        .. code-block:: python

            # Import the class
            >>> from cryptosystems import ECC
            # Create an object of the class
            >>> ecc = ECC()
            >>> public_key, private_key = ecc.generate_keys()
        """
        b = getRandomRange(1, self.n, force=True)
        B = self.multiply(self.G, b)
        return (B, b)

    def add(self, P: tuple, Q: tuple) -> tuple:
        """
        Adds two points on the curve.

        Parameters
        ------------
        + P: tuple
            The first point.
        + Q: tuple
            The second point.

        Returns
        ------------
        + tuple
            The sum of the two points.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> ecc = ECC()
            # Add two points
            >>> ecc.add(P, Q)
            (123456, 654321)
        """
        if self.curve_type == "Weierstrass":
            if P == (0, 0):
                return Q
            if Q == (0, 0):
                return P
            x1, y1 = P
            x2, y2 = Q
            if P != Q:
                m = ((y2 - y1) * pow(x2 - x1, -1, self.curve[0])) % self.curve[0]
            else:
                m = ((3 * x1**2 + self.curve[1]) * pow(2 * y1, -1, self.curve[0])) % self.curve[0]
            x3 = (m**2 - x1 - x2) % self.curve[0]
            y3 = (m * (x1 - x3) - y1) % self.curve[0]
            return x3, y3
        elif self.curve_type == "Montgomery":
            if P == (0, 0):
                return Q
            if Q == (0, 0):
                return P
            x1, z1 = P
            x2, z2 = Q
            A = self.curve[1]
            x3 = (x1 * x2 - z1 * z2) ** 2 % self.curve[0]
            z3 = (x1 * z2 - x2 * z1) ** 2 % self.curve[0]
            return x3, z3
    
    def subtract(self, P: tuple, Q: tuple) -> tuple:
        """
        Subtracts two points on the curve.

        Parameters
        ------------
        + P: tuple
            The first point.
        + Q: tuple
            The second point.

        Returns
        ------------
        + tuple
            The difference of the two points.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> ecc = ECC()
            # Add two points
            >>> ecc.subtract(P, Q)
            (123456, 654321)
        """
        Q_neg = (Q[0], -Q[1] % self.curve[0])
        return self.add(P, Q_neg)

    def multiply(self, P: tuple, n: int) -> tuple:
        """
        Multiplies a point with a scalar.

        Parameters
        ------------
        + P: tuple
            The point.
        + n: int
            The scalar.

        Returns
        ------------
        + tuple
            The product of the point and the scalar.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> ecc = ECC()
            # Multiply a point with a scalar
            >>> ecc.multiply(P, n)
            (123456, 654321)
        """
        if self.curve_type == "Weierstrass":
            Q = (0, 0)
            p = P
            while n:
                if n & 1:
                    Q = self.add(Q, p)
                p = self.add(p, p)
                n >>= 1
            return Q
        elif self.curve_type == "Montgomery":
            X1, Z1 = P
            X2, Z2 = 1, 0
            for bit in reversed(bin(n)[2:]):
                if bit == '1':
                    X1, X2 = self.add((X1, X2), (Z1, Z2))
                else:
                    X1, X2 = self.add((X2, X1), (Z2, Z1))
            return X1, Z1

    def substitute(self, x: int) -> int:
        """
        Get the value after substituting x in the Elliptic Curve equation.

        Parameters
        ------------
        + plaintext: int
            The plaintext to get point of.

        Returns
        ------------
        + tuple
            The message point corresponding to the plaintext.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> ecc = ECC()
            # Encrypt the plaintext
            >>> ciphertext = ecc.substitute(123)
            123456
        """
        if self.curve_type == "Weierstrass":
            return (pow(x, 3) + (self.curve[1] * x) + self.curve[2])
        if self.curve_type == "Montgomery":
            return (x ** 3 + self.curve[1] * x ** 2 + x)
    
    def getPoint(self, plaintext: int) -> tuple:
        """
        Get the point on the Elliptic Curve corresponding to the plaintext.

        Parameters
        ------------
        + plaintext: int
            The plaintext to get point of.

        Returns
        ------------
        + tuple
            The message point corresponding to the plaintext.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> ecc = ECC()
            # Encrypt the plaintext
            >>> ciphertext = ecc.getPoint(123)
            (123456, 654321)
        """
        assert isinstance(plaintext, int), "Plaintext should be only of type int."
        plaintext = plaintext % self.curve[0]
        message_length = 128
        if self.curve_type == "Weierstrass":
            for i in range(2**(256 - message_length)):
                addend = i << message_length
                addition = plaintext + addend
                result = self.substitute(addition) % self.curve[0]
                if pow(result, (self.curve[0] - 1)//2, self.curve[0]) == 1:
                    return (addition, pow(result, (self.curve[0]+1)//4, self.curve[0]))
        elif self.curve_type == "Montgomery":
            for i in range(self.curve[0]):  # Iterate through possible x-coordinates
                x_candidate = (plaintext + i) % self.curve[0] # This approach is being used since using above approach will give the faulty byte in the most significant place, harder to deal with.
                u = self.substitute(x_candidate) % self.curve[0]
                if pow(u, (self.curve[0] - 1) // 2, self.curve[0]) == 1:  # Check if u is a quadratic residue
                    return (x_candidate, 1)  # Montgomery form uses z = 1 as the default

    def encrypt(self, plaintext: int | str | bytes, public_key: tuple) -> tuple:
        """
        Encrypts the given plaintext using the Elliptic Curve Cryptography and returns the ciphertext.

        Parameters
        ------------
        + plaintext: int, str, bytes
            The plaintext to be encrypted.
        + public_key: int
            The public key of the intended recipent of the message, in the form of an integer B.

        Returns
        ------------
        + tuple
            The ciphertext after encrypting the plaintext.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> ecc = ECC()
            # Encrypt the plaintext
            >>> ciphertext = ecc.encrypt("plaintext", public_key)
            ((123, 456), (654, 321))
        """
        assert isinstance(plaintext, (int, str, bytes)), "Plaintext should be an integer, string, or bytes."
        assert isinstance(public_key, tuple) and len(public_key) == 2 and all([isinstance(x, int) and x > 0 for x in public_key]), "Public key should be a tuple of integers B."
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        elif isinstance(plaintext, int):
            assert plaintext > 0, "If plaintext type is integer, it should be positive."
            plaintext = plaintext.to_bytes((plaintext.bit_length()+7)//8, 'big')
        if self.curve_type == "Montgomery" and len(plaintext) % 2 != 0: # Padding because odd length message have last character decrypted wrong (by 1 or 2 positions)
            plaintext = plaintext + b'\x00'
        plaintext = int.from_bytes(plaintext, 'big')
        assert plaintext.bit_length() <= 128, "Plaintext should be of 128 bits or less."
        message_point = self.getPoint(plaintext)
        k = getRandomRange(1, self.n, force=True)
        if self.curve_type == "Weierstrass":
            C1 = self.multiply(self.G, k)
            C2 = self.add(message_point, self.multiply(public_key, k))
        elif self.curve_type == "Montgomery":
            C1 = self.multiply(self.G, k)  # Ephemeral public key (x, z)
            shared_secret = self.multiply(public_key, k)[0]  # Shared secret (x, z)
            C2 = ((message_point[0] + shared_secret) % self.curve[0], 1)  # Encrypt using x-coordinates
        return C1, C2
    
    def decrypt(self, ciphertext: tuple, private_key: int, return_type="int") -> int | str | bytes:
        """
        Decrypts the given ciphertext using the Elliptic Curve Cryptography and returns the plaintext.

        Parameters
        ------------
        + ciphertext: tuple
            The ciphertext to be decrypted.
        + private_key: int
            The private key of the intended recipent of the message, in the form of an integer d.
        + return_type: str
            The type of the plaintext to be returned. It should be either 'int', 'str', or 'bytes'.

        Returns
        ------------
        + int, str, bytes
            The plaintext after decrypting the ciphertext.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> ecc = ECC()
            # Decrypt the ciphertext
            >>> plaintext = ecc.decrypt(ciphertext, private_key, "str")
            "plaintext"
        """
        assert isinstance(ciphertext, tuple) and len(ciphertext) == 2 and all([isinstance(x, tuple) and len(x) == 2 and all([isinstance(y, int) and y > 0 for y in x]) for x in ciphertext]), "Ciphertext should be a tuple of tuples of postive integers, (C1, C2)"
        assert return_type in ['int', 'str', 'bytes'], "return_type should be either 'int', 'str', or 'bytes'."
        assert isinstance(private_key, int) and private_key > 0, "Private key should be a positive integer b."
        C1, C2 = ciphertext
        d = private_key
        if self.curve_type == "Weierstrass":
            plaintext_point = self.subtract(C2, self.multiply(C1, d))
            plaintext = plaintext_point[0] % (2 ** 128)
            if return_type == "str":
                return plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big').decode()
            elif return_type == "bytes":
                return plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big')
            else:
                return plaintext
        elif self.curve_type == "Montgomery":
            shared_secret = self.multiply(C1, d)[0] % self.curve[0]
            plaintext = (C2[0] - shared_secret) % self.curve[0]
            plaintext_bytes = plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big')
            if self.curve_type == "Montgomery" and not chr(plaintext_bytes[-1]).isprintable(): # Remove padding byte if it exists
                plaintext_bytes = plaintext_bytes[:-1]
            if return_type == 'str':
                return plaintext_bytes.decode()
            elif return_type == 'bytes':
                return plaintext_bytes
            else:
                return plaintext
    
    def sign(self, message: int | str | bytes, private_key: int) -> tuple:
        """
        Signs the given message using the Elliptic Curve Cryptography and returns the signature.

        Parameters
        ------------
        + message: int, str, bytes
            The message to be signed.
        + private_key: int
            The private key of the intended recipent of the message, in the form of an integer b.

        Returns
        ------------
        + tuple
            The signature after signing the message.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> ecc = ECC()
            # Sign the plaintext with sender's private key
            >>> signature, message_hash = ecc.sign("plaintext", private_key)
            (123456, 654321), b'\\x12\\x34\\x56\\x78\\x90'
        """
        assert isinstance(message, (int, str, bytes)), "Message should be an integer, string, or bytes."
        assert isinstance(private_key, int) and private_key > 0, "Private key should be a positive integer b."
        if isinstance(message, str):
            message = int.from_bytes(message.encode(), 'big')
        elif isinstance(message, bytes):
            message = int.from_bytes(message, 'big')
        b = private_key
        if self.curve_type == "Weierstrass":
            sha = SHA256()
            message_hash = sha.hash(message)
            z = int.from_bytes(message_hash) >> (256 - self.n.bit_length())
            k = getRandomRange(1, self.n, force=True)
            point = self.multiply(self.G, k)
            r = point[0] % self.n
            while r == 0:
                k = getRandomRange(1, self.n, force=True)
                point = self.multiply(self.G, k)
                r = point[0] % self.n
            s = (pow(k, -1, self.n) * (z + r * b)) % self.n
        elif self.curve_type == "Montgomery":
            raise Exception("ECC Signature not yet implemented for Montgomery curves. Use Weierstrass curves instead.")
            # sha = SHA512()
            # message_hash = sha.hash(message)
            # r = int.from_bytes(message_hash[:32], 'little') % self.n
            # if r == 0:
            #     r = 1  # Ensure r is not zero
            # s = (r * b + int.from_bytes(message_hash[32:], 'little')) % self.n
        return ((r, s), message_hash)
    
    def verify(self, signature: tuple, message_hash: bytes, public_key: tuple) -> bool:
        """
        Verifies the given signature using the Elliptic Curve Cryptography and returns the message.

        Parameters
        ------------
        + signature: tuple
            The signature to be verified.
        + message_hash: bytes
            The SHA256 hash of the original message.
        + public_key: int
            The public key of the sender of the message, in the form of a tuple of integers B.

        Returns
        ------------
        + int, str, bytes
            The message after verifying the signature.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> ecc = ECC()
            # Verify the signature
            >>> verification = ecc.verify(signature, message_hash, public_key)
            True
        """
        assert isinstance(signature, tuple) and len(signature) == 2 and all([isinstance(x, int) and x > 0 for x in signature]), "Signature should be a tuple of positive integers (r, s)."
        assert isinstance(public_key, tuple) and len(public_key) == 2 and all([isinstance(x, int) and x > 0 for x in public_key]), "Public key should be a tuple of positive integers B."
        assert isinstance(message_hash, bytes)  and len(message_hash) == 32, "Message hash should be in bytes of length 256 bits."
        r, s = signature
        B = public_key
        if self.curve_type == "Weierstrass":
            z = int.from_bytes(message_hash) >> (256 - self.n.bit_length())
            s_inv = pow(s, -1, self.n)
            v1 = (s_inv * z) % self.n
            v2 = (s_inv * r) % self.n
            P = self.add(self.multiply(self.G, v1), self.multiply(B, v2))
            return r == P[0] % self.n
        elif self.curve_type == "Montgomery":
            raise Exception("ECC Verification not yet implemented for Montgomery curves. Use Weierstrass curves instead.")
            # sha = SHA512()
            # hash_message = sha.hash(message_hash + public_key[0].to_bytes((public_key[0].bit_length() + 7) // 8, 'big'))
            # left = (r * public_key[0] + s) % self.n
            # right = (r * int.from_bytes(hash_message[:32], 'little')) % self.n
            # return left == right
    
    def get_params(self) -> tuple:
        """
        Returns the parameters of the curve with which the object was instantiated.

        Returns
        ------------
        + tuple
            The parameters.
            - curve: tuple
                The parameters of the curve, in the form of tuple (p, a, b).
            - G: tuple
                The generator point.
            - n: int
                The order of the curve.
            - curve_type: str
                The type of elliptic curve, Montogomery, Weierstrass, Edwards, etc.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> ecc = ECC()
            # Get the parameters
            >>> ecc.get_params()
            ((123, 456, 789), (123456, 654321), 456, "Weierstrass")
        """
        return self.curve, self.G, self.n, self.curve_type
