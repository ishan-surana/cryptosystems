getRandomRange
==============
Generate a random integer in the range [a, b).

Introduction
------------
The ``getRandomRange`` function generates a random integer in the range [a, b). The function can generate a random integer in the range [a, b) for any values of a and b if the ``force`` parameter is set to **True**. However, for performance reasons, the function is limited to generating a random integer in the range [a, b) for values of a and b <= 2^18 if ``force=False``.

.. function:: getRandomRange(a, b, force=False)

    :param a: The lower bound of the range, should be a positive integer. ``a`` is asserted to be <= 2^18 for performance reasons.
    :type a: int
    :param b: The upper bound of the range, should be a positive integer. ``b`` is asserted to be <= 2^18 for performance reasons.
    :type b: int
    :param force: If True, the function will generate a random integer in the range [a, b) for any values of a and b, defaults to **False** for performance reasons.
    :type force: bool
    :type N: int
    :return: A random integer of N bits
    :rtype: int
    
Example Usage
-------------

.. code-block:: python

    # Example usage of getRandomRange to generate a random integer in the range [5, 25)
    from cryptosystems import getRandomRange
    getRandomRange(5, 25) # 19
