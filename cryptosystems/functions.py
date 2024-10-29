from os import urandom

def getRandomInteger(N=1024):
    """
    Return a random number at most N bits long.
    """
    mask = (1 << N) - 1
    r, q = divmod(N, 8)
    if N!=0 and q!=0:
        r += 1
    random_bytes = urandom(r)
    number = mask & int.from_bytes(random_bytes, 'big')
    number |= 1 << (N-1)
    assert number.bit_length() == N
    return number

def getRandomRange(a, b):
    """
    Return a random number N such that a <= N < b.
    """
    total_range = b-a-1
    bits = total_range.bit_length() if total_range>0 else 0
    value = getRandomInteger(bits)
    while value > total_range:
        value = getRandomInteger(bits)
    return a + value

def miller_rabin(n, rounds=10):
    """
    Miller-Rabin primality test. Return 1 if n is prime, 0 if n is composite. Code derived from Pycryptodome.
    """
    if n < 3 or (n & 1) == 0:
        return n == 2
    n_1 = n - 1
    b = 0
    m = n_1
    while (m & 1) == 0:
        b += 1
        m >>= 1
    tested = []
    for i in range(min(rounds, n-2)):
        a = getRandomRange(2, n)
        while a in tested:
            a = getRandomRange(2, n)
        tested.append (a)
        z = pow(a, m, n)
        if z == 1 or z == n_1:
            continue
        composite = 1
        for r in range(b):
            z = (z * z) % n
            if z == 1:
                return 0
            elif z == n_1:
                composite = 0
                break
        if composite:
            return 0
    return 1

def isPrime(N, k=10):
    """
    Test if a number is prime, using the Miller-Rabin test.
    """
    if N < 3 or N & 1 == 0:
        return N == 2
    return miller_rabin(N, k)
        
def getPrime(N=1024):
    """
    Return a random N-bit prime number.
    """
    assert N >= 2, "N should be >= 2"
    while True:
        integer = getRandomInteger(N)
        if isPrime(integer):
            return integer
