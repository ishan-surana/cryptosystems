getPrime
========
Generate a random prime number of N bits.

Introduction
-------------

The ``getPrime`` function generates a random prime number of N bits. The function uses the `isPrime <isPrime.html>`_ function to check if the generated number is prime. The function can generate a prime number of any size if the ``force`` parameter is set to **True**. However, for performance reasons, the function is limited to generating a prime number of size <= 2^11 if ``force=False``.

.. function:: getPrime(N=1024, force=False)

    :param N: The number of bits in the generated prime number, defaults to 1024. ``N`` is asserted to be <= 2^11 if ``force=False`` for performance reasons.
    :type N: int
    :param force: If True, the function will generate a prime number of any size, defaults to **False** for performance reasons.
    :type force: bool
    :return: A random prime number of N bits.
    :rtype: int

Example Usage
-------------

.. code-block:: python

    # Example usage of getPrime to generate a 5-bit prime number
    from cryptosystems import getPrime
    getPrime(5) # 19
