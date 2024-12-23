<h1 align="center">
<img src="https://ishan-surana.github.io/images/cryptosystems.png" width="300">
</h1>

<h1 align="center">𝚌𝚛𝚢𝚙𝚝𝚘𝚜𝚢𝚜𝚝𝚎𝚖𝚜</h1>

<span align="center">
  
[![Licence](https://badgen.net/github/license/ishan-surana/cryptosystems?color=DC143D)](https://github.com/ishan-surana/cryptosystems/blob/main/LICENCE)
[![Python](https://img.shields.io/badge/python-%3E=3.10-slateblue.svg)](https://www.python.org/downloads/release/python-3119/)
[![Wheel](https://img.shields.io/badge/wheel-yes-FF00C9.svg)](https://pypi.org/project/cryptosystems/#files)
[![Maintained](https://img.shields.io/badge/maintained-yes-cyan)](https://github.com/ishan-surana/MetaDataScraper/pulse)
[![OS](https://img.shields.io/badge/OS-Windows,%20Linux,%20Mac-lightgreen)](https://www.microsoft.com/software-download/windows11)
[![Documentation Status](https://readthedocs.org/projects/cryptosystems/badge/?version=latest)](https://cryptosystems.readthedocs.io/en/latest/?badge=latest)

</span>

## Overview
The `cryptosystems` package offers a suite of classes and functions for symmetric and asymmetric encryption, hashing algorithms, key exchange protocols as well as mathematical utility functions. Designed for seamless encryption, decryption, and cryptographic operations, this package is lightweight and efficient, relying solely on Python’s built-in libraries: `ctypes`, `warnings` and `hashlib`. With almost all of the cryptographic logic implemented from scratch, `cryptosystems` provides a streamlined, dependency-free solution, ensuring consistency and reliability across different environments as well as Python versions.

> [!WARNING]  
> As of now, this library stands as a personal project of mine. It has not been audited by any authority. It also contains many basic symmetric ciphers, which should be used ONLY for educational purposes, and NOT in production. The same point stands for other cryptosystems due to appropriate padding schemes not formed yet, and the project not having been formally verified. Please do not use this library in production until it is audited and certified.

## 📜 Changelog for `cryptosystems` v1.0.0 📜
- **🚀 Improved Performance with GMP 🚀:** Optimized performance using GMP for faster computations.
- **🧩 Modularized Codebase 🧩:** Refactored the codebase to be more modular for better maintainability and scalability.
- **🔄 Updated Function Interfaces for Asymmetric Cryptosystems 🔄:** Revised function interfaces, with added `generate_keys` functionality.
- **📝 API Documentation Created 📝:** Comprehensive API documentation has been created to assist with the usage of `cryptosystems`, covering cryptosystem description, mathematical details, usage examples and more.
- **🛠️ Modified Rabin implementation 🛠️:** Modified Rabin implementation with added functionality to verify plaintext using SHA-256 hash.
- **🔧 Fixed ElGamal errors 🔧:** Corrected the ElGamal implementation with a newly added `find_generator` function.
- **🌀 Extended Support for ECC Curves 🌀:** Added support for additional ECC curves, including Montgomery curves.
- **🔐 SHA-512 Wrapper Added 🔐:** Added a wrapper for the SHA-512 algorithm to the `hash_functions` submodule.

## Key Features
- **Dependency-Free** 🚫📦: Operates solely on Python's built-in modules, eliminating the need for external libraries.
- **Version Stability** 🔒📅: Crafted to maintain consistent functionality across Python versions.
- **Optimized for Performance** ⚡⚙️: Built from scratch for efficient and consistant cryptographic operations.
- **Lightweight Codebase** 🪶💻: Minimalistic design ensures a low overhead and straightforward integration.
- **Reliability and Security** 🔐🛡️: Ensures robust encryption/decryption and hashing without reliance on third-party modules.
- **Comprehensive Cryptosystem Support** 🔄🔑: Offers a full suite of symmetric, asymmetric, and hashing methods.

## Installation
To install the package, simply clone the repository and install the dependencies:
```bash
pip install cryptosystems
```

## Usage

The general structure for usage is to create an object of the respective cryptosystem, with the key as argument if required. Similar usage for the utility functions as well. See [docs](https://cryptosystems.readthedocs.io/en/latest/) for the exact reference example of a specific cryptosystem if required.

```python
from cryptosystems import SomeCryptosystem

cipher = SomeCryptosystem()
ciphertext = cipher.encrypt("Hello World")
print(ciphertext)  # Output: 'ciphertext string'
plaintext = cipher.decrypt(ciphertext)
print(plaintext)  # Output: 'Hello World'
```

## License
This project is licensed under the Apache License - see the [LICENSE](LICENCE) file for details.

## Authors
- **Ishan Surana** - *Inception, implementation and testing* - [GitHub](https://github.com/ishan-surana)

## Acknowledgments
- ~~PyCryptodome, for the logic of functions in the [functions submodule](cryptosystems/functions.py)~~ (Python-based implementation, discontinued from version v1.x onward)
- `bcrypt.h` and `gmp.h`, for functions in the [functions submodule](cryptosystems/functions.py)