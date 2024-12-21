Standards
=========

The ``cryptosystems`` library references the highest standards of security and cryptography, including those set forth by the **National Institute of Standards and Technology (NIST)**. This ensures that the implementation aims to follow the best established practices and recommendations for secure cryptographic algorithms, key exchange protocols, hash functions and mathematical utilities.

.. attention::

   As of now, this library stands as a personal project of mine. It has **not** been audited by any authority. It also contains many basic symmetric ciphers, which should be used ONLY for educational purposes, and NOT in production. The same point stands for other cryptosystems due to appropriate padding schemes not formed yet, and the project not having been formally verified. **Please do not use this library in production until it is audited and certified.**

Below is a list of key **Federal Information Processing Standard (FIPS)** and **Special Publications (SPs)** that were referred:

- **NIST FIPS 186-5:-** `Digital Signature Standard (DSS) <https://doi.org/10.6028/NIST.FIPS.186-5>`_
- **NIST FIPS PUB 140-3:-** `Security Requirements for Cryptographic Modules <https://doi.org/10.6028/NIST.FIPS.140-3>`_
- **NIST FIPS 197:-** `Advanced Encryption Standard (AES) <https://doi.org/10.6028/NIST.FIPS.197-upd1>`_
- **NIST FIPS PUB 180-4:-** `Secure Hash Standard (SHS) <http://doi.org/10.6028/NIST.FIPS.180-4>`_
- **NIST Special Publication 800-57 Part 1 (Revision 5):-** `Recommendation for Key Management: Part 1 – General <https://doi.org/10.6028/NIST.SP.800-57pt1r5>`_
- **NIST Special Publication 800-56B (Revision 2):-** `Recommendation for Pair-Wise Key Establishment Using Integer Factorization Cryptography <https://doi.org/10.6028/NIST.SP.800-56Br2>`_
- **NIST Special Publication 800-56A (Revision 3):-** `Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography <https://doi.org/10.6028/NIST.SP.800-56Ar3>`_
- **NIST Special Publication 800-186:-** `Recommendations for Discrete Logarithm-based Cryptography: Elliptic Curve Domain Parameters <https://doi.org/10.6028/NIST.SP.800-186>`_
