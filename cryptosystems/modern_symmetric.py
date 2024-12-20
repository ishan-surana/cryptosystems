class DES:
    """
    A class to encrypt and decrypt the given plaintext and ciphertext using the Data Encryption Standard (DES) Algorithm.
    Currently, the class only supports ECB mode of operation.

    Attributes
    ------------
    + key: str | bytes
        Key for the DES Algorithm. It should be of type bytes or string of 8 characters (64 bits).

    Methods
    ------------
    `encrypt(plaintext: str)` -> bytes:
        Encrypts the given plaintext using the DES Algorithm and returns the ciphertext.
    `decrypt(ciphertext: bytes)` -> str:
        Decrypts the given ciphertext using the DES Algorithm and returns the plaintext.

    Usage
    ------------
    .. code-block:: python

        # Import the class
        >>> from cryptosystems import DES
        # Create an object of the class
        >>> cipher = DES("password")
        # Encrypt the plaintext
        >>> ciphertext  = cipher.encrypt("Hello World")
        b'\\xf4\\\\V\\x1a\\xc7S\\xb7\\xdeZ\\xc1\\xe9\\x14\\n\\x15Y\\xe8'
        # Decrypt the ciphertext
        >>> cipher.decrypt(b'\\xf4\\\\V\\x1a\\xc7S\\xb7\\xdeZ\\xc1\\xe9\\x14\\n\\x15Y\\xe8')
        'Hello World'
    """
    def __init__(self, key):
        """
        Parameters
        ------------
        + key: str | bytes
            Key for the DES Algorithm. It should be a string or bytes of length 8.

        Usage
        ------------
        .. code-block:: python

            # Import the class
            >>> from cryptosystems import DES
            # Create an object of the class with 64 bit key
            >>> cipher = DES("password")
        """
        assert isinstance(key, (str, bytes)), "Key should be of type string or bytes only."
        assert len(key) == 8, "Key should be of 8 characters."
        if isinstance(key, str):
            key = key.encode()
        self.key = key

    # Initial Permutation Table
    IP = [58, 50, 42, 34, 26, 18, 10, 2,
          60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6,
          64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17, 9, 1,
          59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5,
          63, 55, 47, 39, 31, 23, 15, 7]
    
    # Final Permutation Table
    IP_INV = [40, 8, 48, 16, 56, 24, 64, 32,
              39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30,
              37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28,
              35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26,
              33, 1, 41, 9, 49, 17, 57, 25]
    
    # Expansion D-box Table
    E = [32, 1, 2, 3, 4, 5, 4, 5,
         6, 7, 8, 9, 8, 9, 10, 11,
         12, 13, 12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21, 20, 21,
         22, 23, 24, 25, 24, 25, 26, 27,
         28, 29, 28, 29, 30, 31, 32, 1]
    
    # S-boxes (8 S-boxes)
    S_BOXES = [
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
    ]
    
    # Permutation P Table
    P = [16, 7, 20, 21,
         29, 12, 28, 17,
         1, 15, 23, 26,
         5, 18, 31, 10,
         2, 8, 24, 14,
         32, 27, 3, 9,
         19, 13, 30, 6,
         22, 11, 4, 25]
    
    # Permuted Choice 1 Table
    PC1 = [57, 49, 41, 33, 25, 17, 9,
           1, 58, 50, 42, 34, 26, 18,
           10, 2, 59, 51, 43, 35, 27,
           19, 11, 3, 60, 52, 44, 36,
           63, 55, 47, 39, 31, 23, 15,
           7, 62, 54, 46, 38, 30, 22,
           14, 6, 61, 53, 45, 37, 29,
           21, 13, 5, 28, 20, 12, 4]
    
    # Permuted Choice 2 Table
    PC2 = [14, 17, 11, 24, 1, 5,
           3, 28, 15, 6, 21, 10,
           23, 19, 12, 4, 26, 8,
           16, 7, 27, 20, 13, 2,
           41, 52, 31, 37, 47, 55,
           30, 40, 51, 45, 33, 48,
           44, 49, 39, 56, 34, 53,
           46, 42, 50, 36, 29, 32]
    
    # Left Shifts Table
    SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2,
              1, 2, 2, 2, 2, 2, 2, 1]
    
    def permute(self, block, table):
        return ''.join(block[i - 1] for i in table)
    
    def left_shift(self, bits, shifts):
        return bits[shifts:] + bits[:shifts]
    
    def xor_bitstrings(self, bits1, bits2):
        return ''.join('1' if b1 != b2 else '0' for b1, b2 in zip(bits1, bits2))
    
    def generate_subkeys(self, key):
        key = self.permute(key, self.PC1)
        left, right = key[:28], key[28:]
        subkeys = []
        for shift in self.SHIFTS:
            left, right = self.left_shift(left, shift), self.left_shift(right, shift)
            subkeys.append(self.permute(left + right, self.PC2))
        return subkeys
    
    def s_box(self, bits, s_box):
        row = int(bits[0] + bits[5], 2)
        col = int(bits[1:5], 2)
        return f"{s_box[row][col]:04b}"
    
    def f_function(self, right, subkey):
        expanded = self.permute(right, self.E)
        xored = self.xor_bitstrings(expanded, subkey)
        output = ''.join(self.s_box(xored[i:i + 6], self.S_BOXES[i // 6]) for i in range(0, 48, 6))
        return self.permute(output, self.P)
    
    def des_round(self, left, right, subkey):
        new_right = self.xor_bitstrings(left, self.f_function(right, subkey))
        return right, new_right
    
    def des_block(self, block, subkeys, encrypt=True):
        block = self.permute(block, self.IP)
        left, right = block[:32], block[32:]
        for i in range(16):
            left, right = self.des_round(left, right, subkeys[i] if encrypt else subkeys[15 - i])
        return self.permute(right + left, self.IP_INV)

    def encrypt(self, plaintext: str) -> bytes:
        """
        Encrypts the given plaintext using the DES Algorithm and returns the ciphertext.

        Parameters
        ------------
        + plaintext: str
            The plaintext to be encrypted.

        Returns
        ------------
        + bytes
            The ciphertext after encrypting the plaintext.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> cipher = DES("password")
            # Encrypt the plaintext
            >>> ciphertext = cipher.encrypt("Hello World")
            b'\\xf4\\\\V\\x1a\\xc7S\\xb7\\xdeZ\\xc1\\xe9\\x14\\n\\x15Y\\xe8'
        """
        assert isinstance(plaintext, str), "Plaintext should be a string!"
        if len(plaintext) % 8 != 0:
            plaintext += chr(8 - len(plaintext) % 8) * (8 - len(plaintext) % 8)
        binary_key = ''.join(f"{char:08b}" for char in self.key)
        subkeys = self.generate_subkeys(binary_key)
        ciphertext = bytearray()
        for i in range(0, len(plaintext), 8):
            block = plaintext[i:i + 8]
            binary_block = ''.join(f"{ord(char):08b}" for char in block)
            encrypted_binary = self.des_block(binary_block, subkeys, encrypt=True)
            encrypted_bytes = int(encrypted_binary, 2).to_bytes(len(encrypted_binary) // 8, 'big')
            ciphertext += encrypted_bytes
        return bytes(ciphertext)
    
    def decrypt(self, ciphertext: bytes) -> str:
        """
        Decrypts the given ciphertext using the DES Algorithm and returns the plaintext.

        Parameters
        ------------
        + ciphertext: bytes
            The ciphertext to be decrypted.

        Returns
        ------------
        + str
            The plaintext after decrypting the ciphertext.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> cipher = DES("password")
            # Decrypt the ciphertext
            >>> plaintext = cipher.decrypt(ciphertext)
            'Hello World'
        """
        assert isinstance(ciphertext, bytes), "Ciphertext should be of bytes type!"
        binary_key = ''.join(f"{char:08b}" for char in self.key)
        subkeys = self.generate_subkeys(binary_key)
        plaintext = bytearray()
        for i in range(0, len(ciphertext), 8):
            block = ciphertext[i:i + 8]
            binary_block = ''.join(f"{byte:08b}" for byte in block)
            decrypted_binary = self.des_block(binary_block, subkeys, encrypt=False)
            decrypted_bytes = int(decrypted_binary, 2).to_bytes(len(decrypted_binary) // 8, 'big')
            plaintext += decrypted_bytes
        return plaintext.decode().rstrip(chr(plaintext[-1]))

class AES:
    """
    A class to encrypt and decrypt the given plaintext and ciphertext using the Advanced Encryption Standard (AES) Algorithm.
    Currently, the class only supports ECB mode of operation. Supports key sizes of 16, 24, and 32 bytes (AES-128, AES-192, AES-256).

    Attributes
    ------------
    + key: str | bytes
        Key for the AES Algorithm. It should be a string or bytes of length 16, 24, or 32.
    + block_size: int
        Block size for the AES algorithm, which is always 16 bytes.
    
    Methods
    ------------
    `encrypt(plaintext: str)` -> bytes:
        Encrypts the given plaintext using the AES Algorithm and returns the ciphertext.
    `decrypt(ciphertext: bytes)` -> str:
        Decrypts the given ciphertext using the AES Algorithm and returns the plaintext.

    Usage
    ------------
    .. code-block:: python

        # Import the class
        >>> from cryptosystems import AES
        # Create an object of the class
        >>> cipher = AES("passwordpassword")
        # Encrypt the plaintext
        >>> ciphertext = cipher.encrypt("Hello World")
        b"G\\xe4\\xc3\\x8b\\xd9\\x02>\\x88\\xe0)\\x94Z\\xdbE'\\x96"
        # Decrypt the ciphertext
        >>> plaintext = cipher.decrypt(ciphertext)
        'Hello World'
    """
    def __init__(self, key):
        """
        Parameters
        ------------
        + key: str
            Key for the AES Algorithm. It should be a string or bytes of length 16, 24, or 32.

        Usage
        ------------
        .. code-block:: python

            # Import the class
            >>> from cryptosystems import AES
            # Create an object of the class with key of length 16 (128 bits)
            >>> cipher = AES("passwordpassword")
        """
        assert isinstance(key, (str, bytes)) and len(key) in [16, 24, 32], "Key should be bytes or a string of length 16, 24, or 32."
        if isinstance(key, str):
            key = key.encode()
        self.key = key
        self.block_size = 16
        self.rounds = {16: 10, 24: 12, 32: 14}[len(key)]

    # S-box
    S_BOX = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ]

    # Inverse S-box
    INV_S_BOX = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]

    # Rijndael MixColumns Table
    MIX_COLUMNS = [
        [2, 3, 1, 1],
        [1, 2, 3, 1],
        [1, 1, 2, 3],
        [3, 1, 1, 2]
    ]

    # Rijndael Inverse MixColumns Table
    INV_MIX_COLUMNS = [
        [0x0e, 0x0b, 0x0d, 0x09],
        [0x09, 0x0e, 0x0b, 0x0d],
        [0x0d, 0x09, 0x0e, 0x0b],
        [0x0b, 0x0d, 0x09, 0x0e]
    ]

    # Rijndael Round Constants
    RCON = [0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000, 0x6C000000, 0xD8000000, 0xAB000000, 0x4D000000]
    
    def mix_columns(self, state):
        def galois_mul(a, b):
            result = 0
            for _ in range(8):
                if b & 1:
                    result ^= a
                hi_bit_set = a & 0x80
                a = (a << 1) & 0xFF
                if hi_bit_set:
                    a ^= 0x1B
                b >>= 1
            return result
        
        for i in range(4):
            a, b, c, d = state[0][i], state[1][i], state[2][i], state[3][i]
            state[0][i] = galois_mul(a, 2) ^ galois_mul(b, 3) ^ c ^ d
            state[1][i] = a ^ galois_mul(b, 2) ^ galois_mul(c, 3) ^ d
            state[2][i] = a ^ b ^ galois_mul(c, 2) ^ galois_mul(d, 3)
            state[3][i] = galois_mul(a, 3) ^ b ^ c ^ galois_mul(d, 2)
        return state

    def inv_mix_columns(self, state):
        def galois_mul(a, b):
            result = 0
            for _ in range(8):
                if b & 1:
                    result ^= a
                hi_bit_set = a & 0x80
                a = (a << 1) & 0xFF
                if hi_bit_set:
                    a ^= 0x1B
                b >>= 1
            return result
        
        for i in range(4):
            a, b, c, d = state[0][i], state[1][i], state[2][i], state[3][i]
            state[0][i] = galois_mul(a, 0x0e) ^ galois_mul(b, 0x0b) ^ galois_mul(c, 0x0d) ^ galois_mul(d, 0x09)
            state[1][i] = galois_mul(a, 0x09) ^ galois_mul(b, 0x0e) ^ galois_mul(c, 0x0b) ^ galois_mul(d, 0x0d)
            state[2][i] = galois_mul(a, 0x0d) ^ galois_mul(b, 0x09) ^ galois_mul(c, 0x0e) ^ galois_mul(d, 0x0b)
            state[3][i] = galois_mul(a, 0x0b) ^ galois_mul(b, 0x0d) ^ galois_mul(c, 0x09) ^ galois_mul(d, 0x0e)
        return state

    def key_expansion(self, key):
        key_symbols = [c for c in key]
        key_schedule = []
        for i in range(len(key_symbols) // 4):
            t = key_symbols[4*i] << 24 | key_symbols[4*i+1] << 16 | key_symbols[4*i+2] << 8 | key_symbols[4*i+3]
            key_schedule.append(t)

        for i in range(len(key_schedule), (self.rounds + 1) * 4):
            temp = key_schedule[i - 1]
            if i % 4 == 0:
                word = ((temp << 8) | (temp >> 24)) & 0xFFFFFFFF
                temp = ((self.S_BOX[(word >> 24) & 0xFF] << 24) |
                         (self.S_BOX[(word >> 16) & 0xFF] << 16) |
                         (self.S_BOX[(word >> 8) & 0xFF] << 8) |
                         self.S_BOX[word & 0xFF]) ^ self.RCON[i // 4]
            key_schedule.append(key_schedule[i - 4] ^ temp)

        round_keys = []
        for round in range(self.rounds + 1):
            round_key = []
            for row in range(4):
                word = key_schedule[round * 4 + row]
                bytes_in_word = [(word >> 24) & 0xFF, (word >> 16) & 0xFF, (word >> 8) & 0xFF, word & 0xFF]
                round_key.append(bytes_in_word)
            round_keys.append([[round_key[row][col] for row in range(4)] for col in range(4)])
        return round_keys

    def aes_encrypt(self, input_bytes, round_keys):
        state = [[0 for _ in range(4)] for _ in range(4)]
        for i in range(16):
            state[i % 4][i // 4] = input_bytes[i]
        state = [[state[i][j] ^ round_keys[0][i][j] for j in range(4)] for i in range(4)]
        for rnd in range(1, self.rounds):
            # SubBytes
            state = [[self.S_BOX[state[i][j]] for j in range(4)] for i in range(4)]
            # ShiftRows 
            state = [row[i:] + row[:i] for i, row in enumerate(state)]
            # MixColumns
            self.mix_columns(state)
            # AddRoundKey
            state = [[state[i][j] ^ round_keys[rnd][i][j] for j in range(4)] for i in range(4)]
        # sub_bytes(state)
        state = [[self.S_BOX[state[i][j]] for j in range(4)] for i in range(4)]
        # shift_rows(state)
        state = [row[i:] + row[:i] for i, row in enumerate(state)]
        # add_round_key(state, round_keys[self.rounds])
        state = [[state[i][j] ^ round_keys[self.rounds][i][j] for j in range(4)] for i in range(4)]
        output = [0] * 16
        for i in range(16):
            output[i] = state[i % 4][i // 4]
        return output

    def aes_decrypt(self, input_bytes, round_keys):
        state = [[0 for _ in range(4)] for _ in range(4)]
        for i in range(16):
            state[i % 4][i // 4] = input_bytes[i]
        # add_round_key(state, round_keys[self.rounds])
        state = [[state[i][j] ^ round_keys[self.rounds][i][j] for j in range(4)] for i in range(4)]
        for rnd in range(self.rounds - 1, 0, -1):
            # InvShiftRows
            state = [row[4-i:] + row[:4-i] for i, row in enumerate(state)]
            # InvSubBytes
            state = [[self.INV_S_BOX[state[i][j]] for j in range(4)] for i in range(4)]
            # AddRoundKey
            state = [[state[i][j] ^ round_keys[rnd][i][j] for j in range(4)] for i in range(4)]
            # InvMixColumns
            self.inv_mix_columns(state)
        # inv_shift_rows(state)
        state = [row[4-i:] + row[:4-i] for i, row in enumerate(state)]
        # inv_sub_bytes(state)
        state = [[self.INV_S_BOX[state[i][j]] for j in range(4)] for i in range(4)]
        # add_round_key(state, round_keys[0])
        state = [[state[i][j] ^ round_keys[0][i][j] for j in range(4)] for i in range(4)]
        output = [0] * 16
        for i in range(16):
            output[i] = state[i % 4][i // 4]
        return output

    def encrypt(self, plaintext: str) -> bytes:
        """
        Encrypts the given plaintext using the AES Algorithm and returns the ciphertext.

        Parameters
        ------------
        + plaintext: str
            The plaintext to be encrypted.

        Returns
        ------------
        + bytes
            The ciphertext after encrypting the plaintext.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> cipher = AES("passwordpassword")
            # Encrypt the plaintext
            >>> ciphertext = cipher.encrypt("Hello World")
            b"G\\xe4\\xc3\\x8b\\xd9\\x02>\\x88\\xe0)\\x94Z\\xdbE'\\x96"
        """
        plaintext = plaintext.encode()
        round_keys = self.key_expansion(list(self.key))
        padded_message = plaintext + bytes([16-(len(plaintext)%16)] * (16-(len(plaintext)%16)))
        ciphertext = b''
        for i in range(0, len(padded_message), 16):
            block = list(padded_message[i:i+16])
            encrypted_block = self.aes_encrypt(block, round_keys)
            ciphertext += bytes(encrypted_block)
        return ciphertext
    
    def decrypt(self, ciphertext: bytes) -> str:
        """
        Decrypts the given ciphertext using the AES Algorithm and returns the plaintext.

        Parameters
        ------------
        + ciphertext: bytes
            The ciphertext to be decrypted.

        Returns
        ------------
        + str
            The plaintext after decrypting the ciphertext.

        Example
        ------------
        .. code-block:: python

            # Create an object of the class
            >>> cipher = AES("passwordpassword")
            # Decrypt the ciphertext
            >>> cipher.decrypt(ciphertext)
            'Hello World'
        """
        key = list(self.key)
        round_keys = self.key_expansion(key)
        plaintext = bytearray()
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i + 16]
            decrypted_block = self.aes_decrypt(list(block), round_keys)
            plaintext += bytes(decrypted_block)
        return plaintext.decode().rstrip(chr(plaintext[-1]))
