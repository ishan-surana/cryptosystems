isPrime
========
Check if a number is prime.

Introduction
------------

The ``isPrime`` function checks if a number is prime using the **Baillie-PSW** and **Miller-Rabin** primality tests, using the function ``mpz_probab_prime_p`` implemented in the C library ``gmp.h`` (refer `this <https://gmplib.org/manual/Number-Theoretic-Functions#index-mpz_005fprobab_005fprime_005fp>`_ for more details). The function can check for primality of a number of any size if the ``force`` parameter is set to **True**. However, for performance reasons, the function is limited to checking primality of numbers <= 2^11 if ``force=False``.

.. function:: isPrime(N, k=10, force=False)

    :param N: The number to check for primality, is asserted to be <= 2^11 if ``force=False`` for performance reasons.
    :type N: int
    :param k: The number of iterations for the Miller-Rabin primality test, defaults to 10.
    :type k: int
    :param force: If True, the function will check for primality of a number of any size, defaults to **False** for performance reasons.
    :type force: bool
    :return: True or False, based on whether the number is prime is not.
    :rtype: bool
    
Example Usage
-------------

.. code-block:: python

    # Example usage of isPrime to check if a number is prime
    from cryptosystems import isPrime
    print(isPrime(19)) # True
    print(isPrime(20)) # False