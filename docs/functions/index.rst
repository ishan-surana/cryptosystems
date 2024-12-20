Utility Functions
=================

This module contains cryptographic utility functions used by asymmetric ciphers. The functions are implemented in the ``functions`` submodule and can be imported directly from the package.

.. note::
    In ``cryptosystems-0.x``, the functions were implemented from scratch in Python. To make the computations faster, ``cryptosystems-1.x`` onwards, a C module utilising ``gmp`` and a Python wrapper on top of it were implemented, resulting in the increase of speed by several times.

--------------
Usage Examples
--------------

.. tab-set::

    .. tab-item:: isPrime

        .. code-block:: python
                
            # Example usage of isPrime to check if a number is prime
            from cryptosystems import isPrime
            print(isPrime(19)) # True
            print(isPrime(20)) # False
                
    .. tab-item:: getPrime
            
        .. code-block:: python
                
            # Example usage of getPrime to get a prime number
            from cryptosystems import getPrime
            print(getPrime(5)) # 19

    .. tab-item:: getRandomInteger
            
        .. code-block:: python
                
            # Example usage of getRandomInteger to get a random integer
            from cryptosystems import getRandomInteger
            print(getRandomInteger(5)) # 19

    .. tab-item:: getRandomRange
                
        .. code-block:: python
                        
            # Example usage of getRandomRange to get a random integer in a range
            from cryptosystems import getRandomRange
            print(getRandomRange(5, 25)) # 19                    

--------------
Core Functions
--------------
The core mathematical functions implemented in the ``functions`` submodule are:

.. toctree::
    :maxdepth: 1

    isPrime
    getPrime
    getRandomInteger
    getRandomRange