from ctypes import c_size_t, c_int, c_char_p, c_void_p, c_ubyte, CDLL, POINTER, byref, create_string_buffer, _os, _sys

if _sys.platform == "linux":
    lib = CDLL(_os.path.dirname(_os.path.abspath(__file__))+"/functions_module/functions_module.so")  # For Linux
elif _sys.platform == "darwin":
    lib = CDLL(_os.path.dirname(_os.path.abspath(__file__))+"/functions_module/functions_module.dylib")  # For macOS
else:
    lib = CDLL(_os.path.dirname(_os.path.abspath(__file__))+"/functions_module/functions_module.dll") # For Windows

# Return and argument types for the functions
lib.generate_random_sequence.restype = POINTER(c_ubyte)
lib.generate_random_sequence.argtypes = [c_size_t]
lib.getRandomInteger.restype = None
lib.getRandomInteger.argtypes = [c_void_p, c_int]
lib.getRandomRange.restype = None
lib.getRandomRange.argtypes = [c_void_p, c_void_p, c_void_p]
lib.isPrime.restype = c_int
lib.isPrime.argtypes = [c_void_p, c_int]
lib.getPrime.argtypes = [c_void_p, c_int]
lib.getPrime.restype = None
lib.find_generator.argtypes = [c_void_p, c_void_p]
lib.find_generator.restype = None
lib.import_integer.restype = None
lib.import_integer.argtypes = [c_void_p, c_char_p, c_size_t]
lib.export_integer.restype = c_int
lib.export_integer.argtypes = [c_void_p, POINTER(POINTER(c_ubyte)), POINTER(c_size_t)]

# Helper function to convert mpz_t to bytes
def export_integer(mpz_value):
    out_buffer = POINTER(c_ubyte)()
    out_size = c_size_t()
    if lib.export_integer(mpz_value, byref(out_buffer), byref(out_size)) != 0:
        raise MemoryError("Failed to export integer")
    result = int.from_bytes(bytes(out_buffer[:out_size.value]), 'big')
    return result

# Helper function to convert bytes to mpz_t
def import_integer(buffer):
    mpz_value = create_string_buffer(8)
    lib.import_integer(mpz_value, buffer, len(buffer))
    return mpz_value

def getRandomInteger(N=1024, force=False):
    """
    Return a random number exactly N bits long.

    Parameters
    ----------
    + N : int
        The maximum number of bits in the random number.

    Returns
    -------
    + int
        A random number exactly N bits long.

    Example
    -------
    .. code-block:: python

        # Get a random number of exactly 5 bits long
        >>> getRandomInteger(5)
        19
    """
    assert type(N) == int, "N must be an integer"
    assert N > 0, "N must be greater than 0"
    _max_N = 2**18
    if N > _max_N and not force:
        raise ValueError(f"It is strongly recommended to use N <= {_max_N} for performance reasons. If you still want to generate a random number of {N} bits, set force=True.")
    result = create_string_buffer(8)
    lib.getRandomInteger(result, N)
    return export_integer(result)

def getRandomRange(a, b, force=False):
    """
    Return a random number N such that a <= N < b.

    Parameters
    ----------
    + a : int
        The lower bound of the range.
    + b : int
        The upper bound of the range.

    Returns
    -------
    + int
        A random number N such that a <= N < b.

    Example
    -------
    .. code-block:: python

        # Get a random number N such that 5 <= N < 10
        >>> getRandomRange(5, 10)
        8
    """
    assert type(a) == int and type(b) == int, "a and b must be integers"
    assert a >= 0 and b >= 0, "a and b must be non-negative"
    assert a < b, "a must be less than b"
    _max_ab=2**18
    if (a.bit_length() > _max_ab or b.bit_length() > _max_ab) and not force:
        raise ValueError(f"It is strongly recommended to use a, b <= {_max_ab} for performance reasons. If you still want to generate a random number N such that {a} <= N < {b}, set force=True.")
    a_mpz = import_integer(a.to_bytes((a.bit_length() + 7) // 8, 'big'))
    b_mpz = import_integer(b.to_bytes((b.bit_length() + 7) // 8, 'big'))
    result = create_string_buffer(8)
    lib.getRandomRange(result, a_mpz, b_mpz)
    return export_integer(result)

def isPrime(N, k=10):
    """
    Test if a number is prime, using the Baillie-PSW and Miller-Rabin primality tests.

    Parameters
    ----------
    + N : int
        The number to test for primality.
    + k : int
        The number of iterations for the Miller-Rabin test. Default is 10.

    Returns
    -------
    + int : 1 or 0
        1 if the number is prime, 0 otherwise.

    Example
    -------
    .. code-block:: python

        # Test if 17 is prime
        >>> isPrime(17)
        1
    """
    assert type(N) == int, "n must be an integer"
    assert N > 0, "n must be positive"
    assert type(k) == int, "k must be an integer"
    assert k > 0, "k must be positive"
    n_mpz = import_integer(N.to_bytes((N.bit_length() + 7) // 8, 'big'))
    return lib.isPrime(n_mpz, k) == 1

def getPrime(N=1024, force=False):
    """
    Return a random N-bit prime number.

    Parameters
    ----------
    + N : int
        The number of bits in the prime number.

    Returns
    -------
    + int
        A random N-bit prime number.

    Example
    -------
    .. code-block:: python

        # Get a random 5-bit prime number
        >>> getPrime(5)
        19
    """
    assert type(N) == int, "N must be an integer"
    assert N >=2, "N must be at least 2"
    _max_N=2**11
    if N > _max_N and not force:
        raise ValueError(f"It is strongly recommended to use N <= {_max_N} for performance reasons. If you still want to generate a prime number of {N} bits, set force=True.")
    prime = create_string_buffer(8)
    lib.getPrime(prime, N)
    return export_integer(prime)

def find_generator(p: int):
    """
    Find the generator for a given prime p.

    Parameters
    ----------
    + p : int
        The prime number for which to find the generator.

    Returns
    -------
    + int
        The generator g for the prime p.

    Example
    -------
    .. code-block:: python

        # Find a generator for prime 23
        >>> find_generator(23)
        5
    """
    assert isPrime(p), "p must be a prime number"
    assert p > 0, "p must be greater than 0"
    g = create_string_buffer(8)
    p_mpz = import_integer(p.to_bytes((p.bit_length() + 7) // 8, 'big'))
    lib.find_generator(p_mpz, g)
    return export_integer(g)
