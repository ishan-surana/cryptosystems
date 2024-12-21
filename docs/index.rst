Welcome to the ``cryptosystems`` documentation!
===============================================

The ``cryptosystems`` package offers a suite of classes and functions for both symmetric and asymmetric encryption, as well as hashing functionalities. Designed for seamless encryption, decryption, and cryptographic operations, this package is lightweight and efficient, relying solely on Python’s built-in libraries: ``ctypes`` and ``hashlib``. With all cryptographic logic implemented from scratch, cryptosystems provides a streamlined, dependency-free solution, ensuring consistency and reliability across different environments as well as Python versions.

.. attention::

   As of now, this library stands as a personal project of mine. It has not been audited by any authority. It also contains many basic symmetric ciphers, which should be used ONLY for educational purposes, and NOT in production. The same point stands for other cryptosystems due to appropriate padding schemes not formed yet, and the project not having been formally verified. **Please do not use this library in production until it is audited and certified.**

.. note::

   This project is under active development.

Contents
--------

.. toctree::
   :maxdepth: 1

   introduction
   standards
   classical_symmetric/index
   modern_symmetric/index
   asymmetric/index
   key_exchange/index
   hash_functions/index
   functions/index
