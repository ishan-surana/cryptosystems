
## Overview
The `cryptosystems` package offers a robust suite of classes and functions for both symmetric and asymmetric encryption, as well as hashing functionalities. Designed for seamless encryption, decryption, and cryptographic operations, this package is lightweight and efficient, relying solely on Python’s built-in libraries: `ctypes` and `hashlib`. With all cryptographic logic implemented from scratch, cryptosystems provides a streamlined, dependency-free solution, ensuring consistency and reliability across different environments as well as Python versions.

## Key Advantages
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
This project is licensed under the Apache License - see the [LICENSE](https://github.com/ishan-surana/cryptosystems/blob/main/LICENCE) file for details.

## Authors
- **Ishan Surana** - *Inception, implementation and testing* - [GitHub](https://github.com/ishan-surana)

## Acknowledgments
- <del>PyCryptodome, for the logic of functions in the [functions submodule](https://github.com/ishan-surana/cryptosystems/blob/main/cryptosystems/functions.py)</del> (Python-based implementation, discontinued from version v1.x onward)
- `bcrypt.h` and `gmp.h`, for functions in the [functions submodule](https://github.com/ishan-surana/cryptosystems/tree/main/cryptosystems/functions.py)