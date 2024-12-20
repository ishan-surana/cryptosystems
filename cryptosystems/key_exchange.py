from .functions import isPrime, getPrime, find_generator, getRandomRange
from warnings import warn

class DiffieHellman:
    """
    A class to generate the shared secret key using the Diffie-Hellman Key Exchange Algorithm.

    Attributes
    ------------
    + p: int
        Prime number used for the Diffie Hellman instance.
    + g: int
        Generator for the prime p.
    + force: bool
        Argument to force computations with higher orders of numbers, irrespective of resultant performance.

    Methods
    ------------
    `generate_keys()` -> tuple:
        Function to return a valid Diffie-Hellman public-private keypair in the form (A, a).
    `get_shared_secret(a: int, B: int)` -> int:
        Generates the shared secret key using the Diffie-Hellman Key Exchange Algorithm.
    `get_params()` -> int:
        Returns the parameter 'p', the prime used for instantiating Diffie Hellman.
    `set_params(p: int)`:
        Sets the parameters, 'p' and 'force', as per the ones being used by other party.

    Usage
    ------------
    .. code-block:: python

        # Import the class
        >>> from cryptosystems import DiffieHellman
        # Create an object of the class
        >>> dh = DiffieHellman()
        >>> public_key, private_key = dh.generate_keys()
        # Generate the shared secret key
        >>> dh.get_shared_secret(private_key, pub_other)
        1234567890
    """

    def __init__(self, bits=2048, force=False):
        """
        Parameters
        ------------
        + bits: int
            Number of bits for the prime number to instantiate Diffie Hellman.
        + force: bool
            Argument to force computations with higher orders of numbers, irrespective of resultant performance.
        
        Usage
        ------------
        .. code-block:: python

            # Import the class
            >>> from cryptosystems import DiffieHellman
            # Create an object of the class
            >>> dh = DiffieHellman() # Default 1024 bits
            # OR
            >>> dh = DiffieHellman(2**13, True)
        """
        assert isinstance(bits, int), "bits should be an integer"
        assert isinstance(force, bool), "force should be an integer"
        self.force = force
        self.p = getPrime(bits, force=self.force)
        self.g = find_generator(self.p)

    def set_params(self, prime: int):
        """
        Parameters
        ------------
        + prime: int
            The prime number to instantiate Diffie Hellman.
        
        Usage
        ------------
        .. code-block:: python

            # Import the class
            >>> from cryptosystems import DiffieHellman
            # Create an object of the class
            >>> dh = DiffieHellman()
            >>> dh.set_params(p)
        """
        assert isPrime(prime), "Parameter p should be a prime number."
        if prime.bit_length() > 2**11:
            warn("Prime p has bits > 2**11. Paramater 'force' will be set to True, which will allow computations with higher orders of numbers, irrespective of resultant performance.")
            self.force = True
        self.p = prime
        self.g = find_generator(prime)

    def get_params(self) -> tuple:
        """
        Returns the parameters.

        Returns
        ------------
        + p: int
            The prime number to instantiate Diffie Hellman.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> dh = DiffieHellman()
            # Get the parameters
            >>> p = dh.get_params()
            1234567
        """
        return self.p

    def generate_keys(self) -> tuple:
        """
        Function to return a valid Diffie-Hellman public-private keypair in the form (A, a).

        Returns
        ------------
        + tuple
            The public and private key tuple, in the form (A, a).
        
        Usage
        ------------
        .. code-block:: python

            # Import the class
            >>> from cryptosystems import DiffieHellman
            # Create an object of the class
            >>> dh = DiffieHellman()
            >>> public_key, private_key = dh.generate_keys()
        """
        a = getRandomRange(1, self.p, force=True)
        A = pow(self.g, a, self.p)
        return (A, a)

    def get_shared_secret(self, a: int, B: int) -> int:
        """
        Generates the shared secret key using the Diffie-Hellman Key Exchange Algorithm.

        Parameters
        ------------
        + a: int
            Your private key.
        + B: int
            The public key of other party.

        Returns
        ------------
        + int
            The shared secret key.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> dh = DiffieHellman()
            # Generate the shared secret key
            >>> dh.get_shared_secret(priv, pub_other)
            1234567890
        """
        assert isinstance(a, int) and isinstance(B, int), "Private and public keys should be integers."
        return pow(B, a, self.p)

class ECDH:
    """
    A class to generate the shared secret key using the Elliptic Curve Diffie Hellman Algorithm.

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
    `get_shared_secret(a: int, B: tuple)` -> int:
        Generates the shared secret key using the Elliptic Curve Diffie-Hellman Key Exchange Algorithm.
    `generate_keys()` -> tuple:
        Function to return a valid Elliptic Curve Diffie-Hellman public-private keypair in the form (A, a).

    Usage
    ------------
    .. code-block:: python

        # Import the class
        >>> from cryptosystems import ECDH
        # Create an object of the class
        >>> ECDH = ECDH()
        >>> public_key, private_key = ECDH.generate_keys()
        >>> ciphertext = ECDH.get_shared_secret(private_key, pub_other)
        1234567890
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
            >>> from cryptosystems import ECDH
            # Create an object of the class
            >>> ECDH = ECDH()
            # or using curve name specifically
            >>> ECDH = ECDH("secp256k1")
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
        Function to return a valid ECDH public-private keypair in the form (B, b).

        Returns
        ------------
        + tuple
            The public and private key tuples, in the form (B, b).
        
        Usage
        ------------
        .. code-block:: python

            # Import the class
            >>> from cryptosystems import ECDH
            # Create an object of the class
            >>> ECDH = ECDH()
            >>> public_key, private_key = ECDH.generate_keys()
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
            >>> ECDH = ECDH()
            # Add two points
            >>> ECDH.add(P, Q)
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
            >>> ECDH = ECDH()
            # Multiply a point with a scalar
            >>> ECDH.multiply(P, n)
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
        
    def get_shared_secret(self, a: int, B: tuple) -> int:
        """
        Generates the shared secret key using the Diffie-Hellman Key Exchange Algorithm.

        Parameters
        ------------
        + a: int
            Your private key.
        + B: tuple
            The public key of other party.

        Returns
        ------------
        + int
            The shared secret key.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> ecdh = ECDH()
            # Generate the shared secret key
            >>> ecdh.get_shared_secret(priv, pub_other)
            1234567890
        """
        assert isinstance(a, int) and isinstance(B, tuple) and all([isinstance(x, int) for x in B]), "Private key should be an integer, and public key should be a tuple of integers."
        return self.multiply(B, a)[0]
