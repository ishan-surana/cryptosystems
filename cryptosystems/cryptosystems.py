from hashlib import sha256, md5
from .functions import *

class AffineCipher:
    """
    A class to encrypt and decrypt the given plaintext and ciphertext using the Affine Cipher.

    Attributes
    ------------
    + a: int
        First key for the affine cipher. It should be an integer. It should also be coprime with 26.
    + b: int
        Second key for the affine cipher. It should be an integer.

    Methods
    ------------
    `encrypt(plaintext: str)` -> str:
        Encrypts the given plaintext using the affine cipher and returns the ciphertext.
    `decrypt(ciphertext: str)` -> str:
        Decrypts the given ciphertext using the affine cipher and returns the plaintext.
    
    Usage
    ------------
    ```python
    # Import the class
    >>> from cryptosystems import AffineCipher
    # Create an object of the class
    >>> cipher = AffineCipher(5, 8)
    # Encrypt the plaintext
    >>> cipher.encrypt("Hello World")
    'Rclla Oaplx'
    # Decrypt the ciphertext
    >>> cipher.decrypt("Rclla Oaplx")
    'Hello World'
    ```
    """
    
    def __init__(self, a, b):
        """
        Parameters
        ------------
        + a: int
            First key for the affine cipher. It should be an integer. It should also be coprime with 26.
        + b: int
            Second key for the affine cipher. It should be an integer.

        Usage
        ------------
        ```python
        # Import the class
        >>> from cryptosystems import AffineCipher
        # Create an object of the class
        >>> cipher = AffineCipher(5, 8)
        # Encrypt the plaintext
        >>> cipher.encrypt("Hello World")
        'Rclla Oaplx'
        # Decrypt the ciphertext
        >>> cipher.decrypt("Rclla Oaplx")
        'Hello World'
        ```
        """
        assert isinstance(a, int) and isinstance(b, int), "Keys should be integers."
        assert a % 2 != 0 and a % 13 != 0, "Key 'a' should be coprime with 26."
        self.a = a
        self.b = b

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypts the given plaintext using the affine cipher and returns the ciphertext.

        Parameters
        ------------
        + plaintext: str
            The plaintext to be encrypted.

        Returns
        ------------
        + str
            The ciphertext after encrypting the plaintext.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> cipher = AffineCipher(5, 8)
        # Encrypt the plaintext
        >>> cipher.encrypt("Hello World")
        'Rclla Oaplx'
        ```
        """

        ciphertext = ""
        for i in plaintext:
            if i.isalpha():
                if i.islower():
                    ciphertext += chr(((self.a * (ord(i) - 97) + self.b) % 26) + 97)
                else:
                    ciphertext += chr(((self.a * (ord(i) - 65) + self.b) % 26) + 65)
            else:
                ciphertext += i
        return ciphertext

    def decrypt(self, ciphertext) -> str:
        """
        Decrypts the given ciphertext using the affine cipher and returns the plaintext.
        
        Parameters
        ------------
        + ciphertext: str
            The ciphertext to be decrypted.

        Returns
        ------------
        + str
            The plaintext after decrypting the ciphertext.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> cipher = AffineCipher(5, 8)
        # Decrypt the ciphertext
        >>> cipher.decrypt("Rclla Oaplx") 
        'Hello World'
        ```
        """
        self.inv_a = pow(self.a, -1, 26)
        plaintext = ""
        for i in ciphertext:
            if i.isalpha():
                if i.islower():
                    plaintext += chr(((self.inv_a * (ord(i) - 97 - self.b)) % 26) + 97)
                else:
                    plaintext += chr(((self.inv_a * (ord(i) - 65 - self.b)) % 26) + 65)
            else:
                plaintext += i
        return plaintext
    
class AdditiveCipher(AffineCipher):
    """
    A class to encrypt and decrypt the given plaintext and ciphertext using the Additive Cipher.

    Attributes
    ------------
    + k: int
        Key for the additive cipher. It should be an integer.

    Methods
    ------------
    `encrypt(plaintext: str)` -> str:
        Encrypts the given plaintext using the additive cipher and returns the ciphertext.
    `decrypt(ciphertext: str)` -> str:
        Decrypts the given ciphertext using the additive cipher and returns the plaintext.
        
    Usage
    ------------
    ```python
    # Import the class
    >>> from cryptosystems import AdditiveCipher
    # Create an object of the class
    >>> cipher = AdditiveCipher(3)
    # Encrypt the plaintext
    >>> cipher.encrypt("Hello World")
    'Khoor Zruog'
    # Decrypt the ciphertext
    >>> cipher.decrypt("Khoor Zruog")
    'Hello World'
    ```
    """
    
    def __init__(self, k):
        """
        Parameters
        ------------
        + k: int
            Key for the additive cipher. It should be an integer.

        Usage
        ------------
        ```python
        # Import the class
        >>> from cryptosystems import AdditiveCipher
        # Create an object of the class
        >>> cipher = AdditiveCipher(3)
        # Encrypt the plaintext
        >>> cipher.encrypt("Hello World")
        'Khoor Zruog'
        # Decrypt the ciphertext
        >>> cipher.decrypt("Khoor Zruog")
        'Hello World'
        ```
        """
        super().__init__(1, k)

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypts the given plaintext using the additive cipher and returns the ciphertext.

        Parameters
        ------------
        + plaintext: str
            The plaintext to be encrypted.

        Returns
        ------------
        + str
            The ciphertext after encrypting the plaintext.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> cipher = AdditiveCipher(3)
        # Encrypt the plaintext
        >>> cipher.encrypt("Hello World")
        'Khoor Zruog'
        ```
        """
        return super().encrypt(plaintext)
    
    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypts the given ciphertext using the additive cipher and returns the plaintext.

        Parameters
        ------------
        + ciphertext: str
            The ciphertext to be decrypted.

        Returns
        ------------
        + str
            The plaintext after decrypting the ciphertext.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> cipher = AdditiveCipher(3)
        # Decrypt the ciphertext
        >>> cipher.decrypt("Khoor Zruog")
        'Hello World'
        ```
        """
        return super().decrypt(ciphertext)
    
class MultiplicativeCipher(AffineCipher):
    """
    A class to encrypt and decrypt the given plaintext and ciphertext using the Multiplicative Cipher.

    Attributes
    ------------
    + k: int
        Key for the multiplicative cipher. It should be an integer.

    Methods
    ------------
    `encrypt(plaintext: str)` -> str:
        Encrypts the given plaintext using the multiplicative cipher and returns the ciphertext.
    `decrypt(ciphertext: str)` -> str:
        Decrypts the given ciphertext using the multiplicative cipher and returns the plaintext.
    
    Usage
    ------------
    ```python
    # Import the class
    >>> from cryptosystems import MultiplicativeCipher
    # Create an object of the class
    >>> cipher = MultiplicativeCipher(5)
    # Encrypt the plaintext
    >>> cipher.encrypt("Hello World")
    'Czggj Rjmgy'
    # Decrypt the ciphertext
    >>> cipher.decrypt("Judds Gshdp")
    'Hello World'
    ```
    """
    
    def __init__(self, k):
        """
        Parameters
        ------------
        + k: int
            Key for the multiplicative cipher. It should be an integer.

        Usage
        ------------
        ```python
        # Import the class
        >>> from cryptosystems import MultiplicativeCipher
        # Create an object of the class
        >>> cipher = MultiplicativeCipher(5)
        # Encrypt the plaintext
        >>> cipher.encrypt("Hello World")
        'Czggj Rjmgy'
        # Decrypt the ciphertext
        >>> cipher.decrypt("Judds Gshdp")
        'Hello World'
        ```
        """
        super().__init__(k, 0)

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypts the given plaintext using the multiplicative cipher and returns the ciphertext.

        Parameters
        ------------
        + plaintext: str
            The plaintext to be encrypted.

        Returns
        ------------
        + str
            The ciphertext after encrypting the plaintext.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> cipher = MultiplicativeCipher(5)
        # Encrypt the plaintext
        >>> cipher.encrypt("Hello World")
        'Judds Gshdp'
        ```
        """
        return super().encrypt(plaintext)
    
    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypts the given ciphertext using the multiplicative cipher and returns the plaintext.

        Parameters
        ------------
        + ciphertext: str
            The ciphertext to be decrypted.

        Returns
        ------------
        + str
            The plaintext after decrypting the ciphertext.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> cipher = MultiplicativeCipher(5)
        # Decrypt the ciphertext
        >>> cipher.decrypt("Judds Gshdp")
        'Hello World'
        ```
        """
        return super().decrypt(ciphertext)
    
class VigenereCipher:
    """
    A class to encrypt and decrypt the given plaintext and ciphertext using the Vigenere Cipher.

    Attributes
    ------------
    + key: str
        Key for the Vigenere cipher. It should be a string of alphabets.

    Methods
    ------------
    `encrypt(plaintext: str)` -> str:
        Encrypts the given plaintext using the Vigenere cipher and returns the ciphertext.
    `decrypt(ciphertext: str)` -> str:
        Decrypts the given ciphertext using the Vigenere cipher and returns the plaintext.
            
    Usage
    ------------
    ```python
    # Import the class
    >>> from cryptosystems import VigenereCipher
    # Create an object of the class
    >>> cipher = VigenereCipher("key")
    # Encrypt the plaintext
    >>> cipher.encrypt("Hello World")
    'Rijvs Uyvjk'
    # Decrypt the ciphertext
    >>> cipher.decrypt("Rijvs Uyvjk")
    'Hello World'
    ```
    """
    
    def __init__(self, key):
        """
        Parameters
        ------------
        + key: str
            Key for the Vigenere cipher. It should be a string of alphabets.
        
        Usage
        ------------
        ```python
        # Import the class
        >>> from cryptosystems import VigenereCipher
        # Create an object of the class
        >>> cipher = VigenereCipher("key")
        # Encrypt the plaintext
        >>> cipher.encrypt("Hello World")
        'Rijvs Uyvjk'
        # Decrypt the ciphertext
        >>> cipher.decrypt("Rijvs Uyvjk")
        'Hello World'
        ```
        """
        self.key = key

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypts the given plaintext using the Vigenere cipher and returns the ciphertext.

        Parameters
        ------------
        + plaintext: str
            The plaintext to be encrypted.

        Returns
        ------------
        + str
            The ciphertext after encrypting the plaintext.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> cipher = VigenereCipher("key")
        # Encrypt the plaintext
        >>> cipher.encrypt("Hello World")
        'Rijvs Uyvjk'
        ```
        """
        assert all(i.isalpha() for i in self.key), "Key should contain only alphabets."
        # assert (all(i.islower() for i in self.key) and all(i.islower() for i in plaintext if i.isalpha())) or (all(i.isupper() for i in self.key) and all(i.isupper() for i in plaintext if i.isalpha())), "Key and plaintext should be in the same case."
        ciphertext = ""
        key = self.key
        while len(key) < len(plaintext):
            key += self.key
        key = key[:len(plaintext)]
        for i in range(len(plaintext)):
            if plaintext[i].isalpha():
                if plaintext[i].islower():
                    ciphertext += chr(((ord(plaintext[i]) - 97 + ord(key[i].lower()) - 97) % 26) + 97)
                else:
                    ciphertext += chr(((ord(plaintext[i]) - 65 + ord(key[i].upper()) - 65) % 26) + 65)
            else:
                ciphertext += plaintext[i]
        return ciphertext
    
    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypts the given ciphertext using the Vigenere cipher and returns the plaintext.

        Parameters
        ------------
        + ciphertext: str
            The ciphertext to be decrypted.

        Returns
        ------------
        + str
            The plaintext after decrypting the ciphertext.

        Example
        ------------
        ```python
        # Create an object of the class
        >>>
        cipher = VigenereCipher("key")
        # Decrypt the ciphertext
        >>> cipher.decrypt("Rijvs Uyvjk")
        'Hello World'
        ```
        """
        assert all(i.isalpha() for i in self.key), "Key should contain only alphabets."
        plaintext = ""
        key = self.key
        while len(key) < len(ciphertext):
            key += self.key
        key = key[:len(ciphertext)]
        for i in range(len(ciphertext)):
            if ciphertext[i].isalpha():
                if ciphertext[i].islower():
                    plaintext += chr(((ord(ciphertext[i]) - 97 - (ord(key[i].lower()) - 97)) % 26) + 97)
                else:
                    plaintext += chr(((ord(ciphertext[i]) - 65 - (ord(key[i].upper()) - 65)) % 26) + 65)
            else:
                plaintext += ciphertext[i]
        return plaintext

class AutoKeyCipher:
    """
    A class to encrypt and decrypt the given plaintext and ciphertext using the Auto-Key Cipher.

    Attributes
    ------------
    + key: str
        Key for the Auto-Key cipher. It should be a string of alphabets.

    Methods
    ------------
    `encrypt(plaintext: str)` -> str:
        Encrypts the given plaintext using the Auto-Key cipher and returns the ciphertext.
    `decrypt(ciphertext: str)` -> str:
        Decrypts the given ciphertext using the Auto-Key cipher and returns the plaintext.

    Usage
    ------------
    ```python
    # Import the class
    >>> from cryptosystems import AutoKeyCipher
    # Create an object of the class
    >>> cipher = AutoKeyCipher("key")
    # Encrypt the plaintext
    >>> cipher.encrypt("Hello World")
    'Rijss Hzfhr'
    # Decrypt the ciphertext
    >>> cipher.decrypt("Rijss Hzfhr")
    'Hello World'
    ```
    """
    
    def __init__(self, key):
        """
        Parameters
        ------------
        + key: int, str
            Key for the Auto-Key cipher. It can either be an integer, an alphabet, or a string of alphabets. The integer key should be in the range [0, 25], corresponding to the index of the alphabet.
        """
        self.key = key

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypts the given plaintext using the Auto-Key cipher and returns the ciphertext.

        Parameters
        ------------
        + plaintext: str
            The plaintext to be encrypted.

        Returns
        ------------
        + str
            The ciphertext after encrypting the plaintext.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> cipher = AutoKeyCipher("key")
        # Encrypt the plaintext
        >>> cipher.encrypt("Hello World")
        'Rijss Hzfhr'
        ```
        """
        assert all(i.isalpha() for i in self.key), "Multi-character key should contain only alphabets."
        assert len(plaintext) > len(self.key), "Key length should be smaller than plaintext."
        if isinstance(self.key, int) and self.key < 26:
            self.key = chr(int(self.key) + 65)

        ciphertext = ""
        key = (self.key + plaintext)[:len(plaintext)]
        message_pos = 0
        key_pos = 0
        while message_pos < len(plaintext):
            if plaintext[message_pos].isalpha() and key[key_pos].isalpha():
                if plaintext[message_pos].islower():
                    ciphertext += chr(((ord(plaintext[message_pos]) - 97 + ord(key[key_pos].lower()) - 97) % 26) + 97)
                else:
                    ciphertext += chr(((ord(plaintext[message_pos]) - 65 + ord(key[key_pos].upper()) - 65) % 26) + 65)
                key_pos += 1
                message_pos += 1
            elif key[key_pos].isalpha():
                ciphertext += plaintext[message_pos]
                message_pos += 1
            else:
                key_pos += 1
        return ciphertext
    
    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypts the given ciphertext using the Auto-Key cipher and returns the plaintext.

        Parameters
        ------------
        + ciphertext: str
            The ciphertext to be decrypted.

        Returns
        ------------
        + str
            The plaintext after decrypting the ciphertext.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> cipher = AutoKeyCipher("key")
        # Decrypt the ciphertext
        >>> cipher.decrypt("Rijss Hzfhr")
        'Hello World'
        """
        assert all(i.isalpha() for i in self.key), "Multi-character key should contain only alphabets."
        assert len(ciphertext) > len(self.key), "Key length should be smaller than ciphertext."
        if isinstance(self.key, int) and self.key < 26:
            self.key = chr(int(self.key) + 65)

        plaintext = ""
        key = self.key
        message_pos = 0
        key_pos = 1
        while message_pos < len(ciphertext):
            if ciphertext[message_pos].isalpha():
                if ciphertext[message_pos].islower():
                    key += chr(((ord(ciphertext[message_pos]) - ord(key[key_pos-1].lower()) + 26) % 26) + 97)
                else:
                    key += chr(((ord(ciphertext[message_pos]) - ord(key[key_pos-1].upper()) + 26) % 26) + 65)
                plaintext += key[key_pos+len(self.key)-1]
                key_pos += 1
                message_pos += 1
            elif key[key_pos-1].isalpha():
                plaintext += ciphertext[message_pos]
                message_pos += 1
        return plaintext
    
class PlayfairCipher:
    """
    A class to encrypt and decrypt the given plaintext and ciphertext using the Playfair Cipher.

    Attributes
    ------------
    + key: str
        Key for the Playfair cipher. It should be a string of alphabets. It should not contain 'J'.

    Methods
    ------------
    `encrypt(plaintext: str)` -> str:
        Encrypts the given plaintext using the Playfair cipher and returns the ciphertext.
    `decrypt(ciphertext: str)` -> str:
        Decrypts the given ciphertext using the Playfair cipher and returns the plaintext.

    Usage
    ------------
    ```python
    # Import the class
    >>> from cryptosystems import PlayfairCipher
    # Create an object of the class
    >>> cipher = PlayfairCipher("key")
    # Encrypt the plaintext
    >>> cipher.encrypt("Hello World")
    'Dahak Ldskn'
    # Decrypt the ciphertext
    >>> cipher.decrypt("Dahak Ldskn")
    'Hello World'
    ```
    """

    def __init__(self, key):
        """
        Parameters
        ------------
        + key: str
            Key for the Playfair cipher. It should be a string of alphabets. It should not contain 'J'.

        Usage
        ------------
        ```python
        # Import the class
        >>> from cryptosystems import PlayfairCipher
        # Create an object of the class
        >>> cipher = PlayfairCipher("key")
        # Encrypt the plaintext
        >>> cipher.encrypt("Test Input")
        'QbtpLouksZ'
        # Decrypt the ciphertext
        >>> cipher.decrypt("QbtpLouksZ")
        'TestInputX'
        ```
        """
        assert all(i.isalpha() for i in key), "Key should contain only alphabets."
        assert 'J' not in key, "Key should not contain 'J'."
        self.key = key

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypts the given plaintext using the Playfair cipher and returns the ciphertext.

        Parameters
        ------------
        + plaintext: str
            The plaintext to be encrypted.

        Returns
        ------------
        + str
            The ciphertext after encrypting the plaintext.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> cipher = PlayfairCipher("key")
        # Encrypt the plaintext
        >>> cipher.encrypt("Test Input")
        'QbtpLouksZ'
        ```
        """

        def generate_matrix(key):
            matrix = []
            key = key.replace("J", "I")
            for i in key:
                if i not in matrix:
                    matrix.append(i)
            for i in range(65, 91):
                if chr(i) not in matrix and chr(i) != "J":
                    matrix.append(chr(i))
            matrix = [matrix[i:i+5] for i in range(0, 25, 5)]
            return matrix

        def find_position(matrix, letter):
            for i, j in enumerate(matrix):
                for k, l in enumerate(j):
                    if l == letter:
                        return i, k

        def encrypt_pair(matrix, pair):
            a, b = pair
            a_lower = (a == a.lower())
            b_lower = (b == b.lower())
            row_a, col_a = find_position(matrix, a.upper())
            row_b, col_b = find_position(matrix, b.upper())
            if row_a == row_b:
                c1 = matrix[row_a][(col_a + 1) % 5]
                c2 = matrix[row_b][(col_b + 1) % 5]
            if col_a == col_b:
                c1 = matrix[(row_a + 1) % 5][col_a]
                c2 = matrix[(row_b + 1) % 5][col_b]
            if row_a != row_b and col_a != col_b:
                c1 = matrix[row_a][col_b]
                c2 = matrix[row_b][col_a]
            if a_lower:
                c1 = c1.lower()
            if b_lower:
                c2 = c2.lower()
            return c1 + c2

        matrix = generate_matrix(self.key.upper())
        plaintext = plaintext.replace("J", "I")
        # add X between double letters
        plaintext = [plaintext[i] if plaintext[i] != plaintext[i+1] else plaintext[i] + "X" for i in range(len(plaintext)-1)] + [plaintext[-1]]
        plaintext = "".join([i for i in plaintext if i.isalpha()])
        if len(plaintext) % 2 != 0:
            plaintext += "X"
        pairs = [plaintext[i:i+2] for i in range(0, len(plaintext), 2)]
        ciphertext = ""
        for pair in pairs:
            ciphertext += encrypt_pair(matrix, pair)
        return ciphertext

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypts the given ciphertext using the Playfair cipher and returns the plaintext.

        Parameters
        ------------
        + ciphertext: str
            The ciphertext to be decrypted.

        Returns
        ------------
        + str
            The plaintext after decrypting the ciphertext.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> cipher = PlayfairCipher("key")
        # Decrypt the ciphertext
        >>> cipher.decrypt("QbtpLouksZ")
        'TestInputX'
        """
        def generate_matrix(key):
            matrix = []
            key = key.replace("J", "I")
            for i in key:
                if i not in matrix:
                    matrix.append(i)
            for i in range(65, 91):
                if chr(i) not in matrix and chr(i) != "J":
                    matrix.append(chr(i))
            matrix = [matrix[i:i+5] for i in range(0, 25, 5)]
            return matrix

        def find_position(matrix, letter):
            for i, j in enumerate(matrix):
                for k, l in enumerate(j):
                    if l == letter:
                        return i, k

        def decrypt_pair(matrix, pair):
            a, b = pair
            a_lower = (a == a.lower())
            b_lower = (b == b.lower())
            row_a, col_a = find_position(matrix, a.upper())
            row_b, col_b = find_position(matrix, b.upper())
            if row_a == row_b:
                c1 = matrix[row_a][(col_a - 1) % 5]
                c2 = matrix[row_b][(col_b - 1) % 5]
            if col_a == col_b:
                c1 = matrix[(row_a - 1) % 5][col_a]
                c2 = matrix[(row_b - 1) % 5][col_b]
            if row_a != row_b and col_a != col_b:
                c1 = matrix[row_a][col_b]
                c2 = matrix[row_b][col_a]
            if a_lower:
                c1 = c1.lower()
            if b_lower:
                c2 = c2.lower()
            return c1 + c2

        matrix = generate_matrix(self.key.upper())
        ciphertext = ciphertext.replace("J", "I")
        ciphertext = "".join([i for i in ciphertext if i.isalpha()])
        if len(ciphertext) % 2 != 0:
            ciphertext += "X"
        pairs = [ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)]
        plaintext = ""
        for pair in pairs:
            plaintext += decrypt_pair(matrix, pair)
        return plaintext

class HillCipher:
    """
    A class to encrypt and decrypt the given plaintext and ciphertext using the Hill Cipher.

    Attributes
    ------------
    + key: list
        Key for the Hill cipher. It should be a 2x2 matrix.

    Methods
    ------------
    `encrypt(plaintext: str)` -> str:
        Encrypts the given plaintext using the Hill cipher and returns the ciphertext.
    `decrypt(ciphertext: str)` -> str:
        Decrypts the given ciphertext using the Hill cipher and returns the plaintext.

    Usage
    ------------
    ```python
    # Import the class
    >>> from cryptosystems import HillCipher
    # Create an object of the class
    >>> cipher = HillCipher([[3, 3], [2, 5]])
    # Encrypt the plaintext
    >>> cipher.encrypt("HelloWorld")
    'HiozeIpjql'
    # Decrypt the ciphertext
    >>> cipher.decrypt("HiozeIpjql")
    'HelloWorld'
    ```
    """

    def __init__(self, key):
        """
        Parameters
        ------------
        + key: list
            Key for the Hill cipher. It should be a 2x2 matrix.

        Usage
        ------------
        ```python
        # Import the class
        >>> from cryptosystems import HillCipher
        # Create an object of the class
        >>> cipher = HillCipher([[3, 3], [2, 5]])
        # Encrypt the plaintext
        >>> cipher.encrypt("HelloWorld")
        'HiozeIpjql'
        # Decrypt the ciphertext
        >>> cipher.decrypt("HiozeIpjql")
        'HelloWorld'
        ```
        """
        self.key = key

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypts the given plaintext using the Hill cipher and returns the ciphertext.

        Parameters
        ------------
        + plaintext: str
            The plaintext to be encrypted.

        Returns
        ------------
        + str
            The ciphertext after encrypting the plaintext.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> cipher = HillCipher([[3, 3], [2, 5]])
        # Encrypt the plaintext
        >>> cipher.encrypt("HelloWorld")
        'HiozeIpjql'
        ```
        """
        ct_pair = ""
        ciphertext = ""
        if len(plaintext) % 2 != 0:
            plaintext += "X"
        for i in range(0, len(plaintext), 2):
            a_lower, b_lower = plaintext[i].islower(), plaintext[i+1].islower()
            plaintext = plaintext[0:i] + plaintext[i].upper() + plaintext[i+1].upper() + plaintext[i+2:]
            pair = [ord(plaintext[i]) - 65, ord(plaintext[i+1]) - 65]
            pair = [sum([self.key[i][j] * pair[j] for j in range(2)]) % 26 for i in range(2)]
            ct_pair = "".join([chr(pair[i] + 65) for i in range(2)])
            ciphertext += ct_pair[0].lower() if a_lower else ct_pair[0]
            ciphertext += ct_pair[1].lower() if b_lower else ct_pair[1]
        return ciphertext

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypts the given ciphertext using the Hill cipher and returns the plaintext.

        Parameters
        ------------
        + ciphertext: str
            The ciphertext to be decrypted.

        Returns
        ------------
        + str
            The plaintext after decrypting the ciphertext.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> cipher = HillCipher([[3, 3], [2, 5]])
        # Decrypt the ciphertext
        >>> cipher.decrypt("HiozeIpjql")
        'Hello World'
        """
        if len(ciphertext) % 2 != 0:
            ciphertext += "X"
        self.inv_key = [[self.key[1][1], -self.key[0][1]], [-self.key[1][0], self.key[0][0]]]
        det = (self.key[0][0] * self.key[1][1] - self.key[0][1] * self.key[1][0]) % 26
        assert det % 2 != 0 and det % 13 != 0, "Determinant is not coprime with 26. Please provide another key."
        det_inv = pow(det, -1, 26)
        self.inv_key = [[(det_inv * self.inv_key[i][j]) % 26 for j in range(2)] for i in range(2)]
        pt_pair = ""
        plaintext = ""
        for i in range(0, len(ciphertext), 2):
            a_lower, b_lower = ciphertext[i].islower(), ciphertext[i+1].islower()
            ciphertext = ciphertext[0:i] + ciphertext[i].upper() + ciphertext[i+1].upper() + ciphertext[i+2:]
            pair = [ord(ciphertext[i]) - 65, ord(ciphertext[i+1]) - 65]
            pair = [sum([self.inv_key[i][j] * pair[j] for j in range(2)]) % 26 for i in range(2)]
            pt_pair = "".join([chr(pair[i] + 65) for i in range(2)])
            plaintext += pt_pair[0].lower() if a_lower else pt_pair[0]
            plaintext += pt_pair[1].lower() if b_lower else pt_pair[1]
        return plaintext

class DES:
    """
    A class to encrypt and decrypt the given plaintext and ciphertext using the Data Encryption Standard (DES) Algorithm.
    Currently, the class only supports ECB mode of operation.

    Attributes
    ------------
    + key: str
        Key for the DES Algorithm. It should be a string of 8 characters.

    Methods
    ------------
    `encrypt(plaintext: str)` -> bytes:
        Encrypts the given plaintext using the DES Algorithm and returns the ciphertext.
    `decrypt(ciphertext: bytes)` -> str:
        Decrypts the given ciphertext using the DES Algorithm and returns the plaintext.

    Usage
    ------------
    ```python
    # Import the class
    >>> from cryptosystems import DES
    # Create an object of the class
    >>> cipher = DES("password")
    # Encrypt the plaintext
    >>> cipher.encrypt("Hello World")
    b'\\xf4\\\\V\\x1a\\xc7S\\xb7\\xdeZ\\xc1\\xe9\\x14\\n\\x15Y\\xe8'
    # Decrypt the ciphertext
    >>> cipher.decrypt(b'\\xf4\\\\V\\x1a\\xc7S\\xb7\\xdeZ\\xc1\\xe9\\x14\\n\\x15Y\\xe8')
    'Hello World'
    ```
    """
    def __init__(self, key):
        """
        Parameters
        ------------
        + key: str
            Key for the DES Algorithm. It should be a string of 8 characters.

        Usage
        ------------
        ```python
        # Import the class
        >>> from cryptosystems import DES
        # Create an object of the class
        >>> cipher = DES("password")
        # Encrypt the plaintext
        >>> cipher.encrypt("Hello World")
        'Q1kq6jQxH4c='
        # Decrypt the ciphertext
        >>> cipher.decrypt("Q1kq6jQxH4c=")
        'Hello World'
        ```
        """
        assert len(key) == 8, "Key should be of 8 characters."
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
    
    def permute(block, table):
        return ''.join(block[i - 1] for i in table)
    
    def left_shift(bits, shifts):
        return bits[shifts:] + bits[:shifts]
    
    def xor_bitstrings(bits1, bits2):
        return ''.join('1' if b1 != b2 else '0' for b1, b2 in zip(bits1, bits2))
    
    def generate_subkeys(key):
        key = DES.permute(key, DES.PC1)
        left, right = key[:28], key[28:]
        subkeys = []
        for shift in DES.SHIFTS:
            left, right = DES.left_shift(left, shift), DES.left_shift(right, shift)
            subkeys.append(DES.permute(left + right, DES.PC2))
        return subkeys
    
    def s_box(bits, s_box):
        row = int(bits[0] + bits[5], 2)
        col = int(bits[1:5], 2)
        return f"{s_box[row][col]:04b}"
    
    def f_function(right, subkey):
        expanded = DES.permute(right, DES.E)
        xored = DES.xor_bitstrings(expanded, subkey)
        output = ''.join(DES.s_box(xored[i:i + 6], DES.S_BOXES[i // 6]) for i in range(0, 48, 6))
        return DES.permute(output, DES.P)
    
    def des_round(left, right, subkey):
        new_right = DES.xor_bitstrings(left, DES.f_function(right, subkey))
        return right, new_right
    
    def des_block(block, subkeys, encrypt=True):
        block = DES.permute(block, DES.IP)
        left, right = block[:32], block[32:]
        for i in range(16):
            left, right = DES.des_round(left, right, subkeys[i] if encrypt else subkeys[15 - i])
        return DES.permute(right + left, DES.IP_INV)

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
        ```python
        # Create an object of the class
        >>> cipher = DES("password")
        # Encrypt the plaintext
        >>> cipher.encrypt("Hello World")
        'Q1kq6jQxH4c='
        ```
        """
        if len(plaintext) % 8 != 0:
            plaintext += chr(8 - len(plaintext) % 8) * (8 - len(plaintext) % 8)
        binary_key = ''.join(f"{ord(char):08b}" for char in self.key)
        subkeys = DES.generate_subkeys(binary_key)
        ciphertext = bytearray()
        for i in range(0, len(plaintext), 8):
            block = plaintext[i:i + 8]
            binary_block = ''.join(f"{ord(char):08b}" for char in block)
            encrypted_binary = DES.des_block(binary_block, subkeys, encrypt=True)
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
        ```python
        # Create an object of the class
        >>> cipher = DES("password")
        # Decrypt the ciphertext
        >>> cipher.decrypt("Q1kq6jQxH4c=")
        'Hello World'
        """
        binary_key = ''.join(f"{ord(char):08b}" for char in self.key)
        subkeys = DES.generate_subkeys(binary_key)
        plaintext = bytearray()
        for i in range(0, len(ciphertext), 8):
            block = ciphertext[i:i + 8]
            binary_block = ''.join(f"{byte:08b}" for byte in block)
            decrypted_binary = DES.des_block(binary_block, subkeys, encrypt=False)
            decrypted_bytes = int(decrypted_binary, 2).to_bytes(len(decrypted_binary) // 8, 'big')
            plaintext += decrypted_bytes
        return plaintext.decode().rstrip(chr(plaintext[-1]))

class AES:
    """
    A class to encrypt and decrypt the given plaintext and ciphertext using the Advanced Encryption Standard (AES) Algorithm.
    Currently, the class only supports ECB mode of operation. Supports key sizes of 16, 24, and 32 bytes (AES-128, AES-192, AES-256).

    Attributes
    ------------
    + key: str
        Key for the AES Algorithm. It should be a string of 16, 24, or 32 characters.
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
    ```python
    # Import the class
    >>> from cryptosystems import AES
    # Create an object of the class
    >>> cipher = AES("passwordpassword")
    # Encrypt the plaintext
    >>> cipher.encrypt("Hello World")
    b'\\x9cHS\\xc2\\x00\\x0c\\xba\\x82Bj\\x90\\xc3t|4}'
    # Decrypt the ciphertext
    >>> cipher.decrypt(b'\\x9cHS\\xc2\\x00\\x0c\\xba\\x82Bj\\x90\\xc3t|4}')
    'Hello World'
    ```
    """
    def __init__(self, key):
        """
        Parameters
        ------------
        + key: str
            Key for the AES Algorithm. It should be a string of 16, 24, or 32 characters.

        Usage
        ------------
        ```python
        # Import the class
        >>> from cryptosystems import AES
        # Create an object of the class
        >>> cipher = AES("passwordpassword")
        # Encrypt the plaintext
        >>> cipher.encrypt("Hello World")
        b'\\x9cHS\\xc2\\x00\\x0c\\xba\\x82Bj\\x90\\xc3t|4}'
        # Decrypt the ciphertext
        >>> cipher.decrypt(b'\\x9cHS\\xc2\\x00\\x0c\\xba\\x82Bj\\x90\\xc3t|4}')
        'Hello World'
        ```
        """
        assert len(key) in [16, 24, 32], "Key should be of 16, 24, or 32 characters."
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
    RCON = [0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000]
    
    def mix_columns(state):
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

    def inv_mix_columns(state):
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
                temp = ((AES.S_BOX[(word >> 24) & 0xFF] << 24) |
                         (AES.S_BOX[(word >> 16) & 0xFF] << 16) |
                         (AES.S_BOX[(word >> 8) & 0xFF] << 8) |
                         AES.S_BOX[word & 0xFF]) ^ AES.RCON[i // 4]
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
            state = [[AES.S_BOX[state[i][j]] for j in range(4)] for i in range(4)]
            # ShiftRows 
            state = [row[i:] + row[:i] for i, row in enumerate(state)]
            AES.mix_columns(state)
            # AddRoundKey
            state = [[state[i][j] ^ round_keys[rnd][i][j] for j in range(4)] for i in range(4)]
        # sub_bytes(state)
        state = [[AES.S_BOX[state[i][j]] for j in range(4)] for i in range(4)]
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
            state = [[AES.INV_S_BOX[state[i][j]] for j in range(4)] for i in range(4)]
            # AddRoundKey
            state = [[state[i][j] ^ round_keys[rnd][i][j] for j in range(4)] for i in range(4)]
            # InvMixColumns
            AES.inv_mix_columns(state)
        # inv_shift_rows(state)
        state = [row[4-i:] + row[:4-i] for i, row in enumerate(state)]
        # inv_sub_bytes(state)
        state = [[AES.INV_S_BOX[state[i][j]] for j in range(4)] for i in range(4)]
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
        ```python
        # Create an object of the class
        >>> cipher = AES("passwordpassword")
        # Encrypt the plaintext
        >>> cipher.encrypt("Hello World")
        b'\\x9cHS\\xc2\\x00\\x0c\\xba\\x82Bj\\x90\\xc3t|4}'
        ```
        """
        plaintext = plaintext.encode()
        if type(self.key) == str:
            round_keys = AES.key_expansion(list(self.key.encode('utf-8')))
        elif type(self.key) == bytes:
            round_keys = AES.key_expansion(list(self.key))
        padded_message = plaintext + bytes([16-(len(plaintext)%16)] * (16-(len(plaintext)%16)))
        ciphertext = b''
        for i in range(0, len(padded_message), 16):
            block = list(padded_message[i:i+16])
            encrypted_block = AES.aes_encrypt(block, round_keys)
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
        ```python
        # Create an object of the class
        >>> cipher = AES("passwordpassword")
        # Decrypt the ciphertext
        >>> cipher.decrypt(b'\\x9cHS\\xc2\\x00\\x0c\\xba\\x82Bj\\x90\\xc3t|4}')
        'Hello World'
        """
        if type(self.key) == str:
            key = [ord(char) for char in self.key]
        elif type(self.key) == bytes:
            key = list(self.key)
        round_keys = AES.key_expansion(key)
        plaintext = bytearray()
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i + 16]
            decrypted_block = AES.aes_decrypt(list(block), round_keys)
            plaintext += bytes(decrypted_block)
        return plaintext.decode().rstrip(chr(plaintext[-1]))

class RSA:
    """
    A class to encrypt and decrypt the given plaintext and ciphertext using the RSA Algorithm.

    Attributes
    ------------
    + p: int
        First prime number.
    + q: int
        Second prime number.
    + e: int
        Public exponent.
    + d: int
        Private exponent.
    + n: int
        Modulus.
    + phi: int
        Euler's totient function.

    Methods
    ------------
    `encrypt(plaintext: int | str | bytes)` -> int:
        Encrypts the given plaintext using the RSA Algorithm and returns the ciphertext.
    `decrypt(ciphertext: int | str | bytes, return_type: str)` -> int | str | bytes:
        Decrypts the given ciphertext using the RSA Algorithm and returns the plaintext.
    `sign(message: int | str | bytes)` -> int:
        Signs the given message using the RSA Algorithm and returns the signature.
    `verify(signature: int | str | bytes, return_type: str)` -> int | str | bytes:
        Verifies the given signature using the RSA Algorithm and returns the message.
    `getPublicKey()` -> tuple:
        Returns the public key.
    `getPrivateKey()` -> tuple:
        Returns the private key.
    `getFactors()` -> tuple:
        Returns the prime factors of the modulus.

    Usage
    ------------
    ```python
    # Import the class
    >>> from cryptosystems import RSA
    # Create an object of the class
    >>> rsa = RSA(1024)
    # Encrypt the plaintext
    >>> rsa.encrypt(123)
    1234567890
    # Decrypt the ciphertext
    >>> rsa.decrypt(1234567890)
    123
    # Sign the message
    >>> rsa.sign(123)
    1234567890
    # Verify the signature
    >>> rsa.verify(1234567890)
    123
    ```
    """

    def __init__(self, bits=1024):
        """
        Parameters
        ------------
        + bits: int
            Number of bits for the prime numbers.

        Usage
        ------------
        ```python
        # Import the class
        >>> from cryptosystems import RSA
        # Create an object of the class
        >>> rsa = RSA()
        ```
        """
        assert isinstance(bits, int), "bits should be an integer"
        assert bits >= 2, "bits should be >= 2"
        # assert bits.bit_length()%2==0, "bits should be an even number"
        self.p = getPrime(bits)
        self.q = getPrime(bits)
        while self.p == self.q:
            self.q = getPrime(bits)
        self.n = self.p * self.q
        self.phi = (self.p-1) * (self.q-1)
        self.e = 65537
        self.d = pow(self.e, -1, self.phi)

    def encrypt(self, plaintext: int | str | bytes) -> int:
        """
        Encrypts the given plaintext using the RSA Algorithm and returns the ciphertext.

        Parameters
        ------------
        + plaintext: int, str, bytes
            The plaintext to be encrypted.

        Returns
        ------------
        + int
            The ciphertext after encrypting the plaintext.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> rsa = RSA(1024)
        # Encrypt the plaintext
        >>> rsa.encrypt(123)
        1234567890
        ```
        """
        assert isinstance(plaintext, int) or isinstance(plaintext, str) or isinstance(plaintext, bytes), "plaintext should be an integer, string, or bytes."
        if isinstance(plaintext, str):
            plaintext = int.from_bytes(plaintext.encode(), 'big')
        elif isinstance(plaintext, bytes):
            plaintext = int.from_bytes(plaintext, 'big')
        try:
            return pow(plaintext, self.e, self.n)
        except:
            print("Invalid plaintext.")
    
    def decrypt(self, ciphertext: int | str | bytes, return_type='int') -> int | str | bytes:
        """
        Decrypts the given ciphertext using the RSA Algorithm and returns the plaintext.

        Parameters
        ------------
        + ciphertext: int, str, bytes
            The ciphertext to be decrypted.
        + return_type: str
            The type of the plaintext to be returned. It should be either 'int', 'str', or 'bytes'.

        Returns
        ------------
        + int, str, bytes
            The plaintext after decrypting the ciphertext.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> rsa = RSA(1024)
        # Decrypt the ciphertext
        >>> rsa.decrypt(1234567890)
        123
        ```
        """
        assert isinstance(ciphertext, int) or isinstance(ciphertext, str) or isinstance(ciphertext, bytes), "ciphertext should be an integer, string, or bytes."
        assert return_type in ['int', 'str', 'bytes'], "return_type should be either 'int', 'str', or 'bytes'."

        if isinstance(ciphertext, str):
            ciphertext = int.from_bytes(ciphertext.encode(), 'big')
        elif isinstance(ciphertext, bytes):
            ciphertext = int.from_bytes(ciphertext, 'big')
        try:
            plaintext = pow(ciphertext, self.d, self.n)
            if return_type == 'str':
                return plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big').decode()
            elif return_type == 'bytes':
                return plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big')
            return plaintext
        except:
            print("Invalid ciphertext")
    
    def sign(self, message: int | str | bytes) -> int:
        """
        Signs the given message using the RSA Algorithm and returns the signature.

        Parameters
        ------------
        + message: int, str, bytes
            The message to be signed.

        Returns
        ------------
        + int
            The signature after signing the message.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> rsa = RSA(1024)
        # Sign the message
        >>> rsa.sign(123)
        1234567890
        ```
        """
        assert isinstance(message, int) or isinstance(message, str) or isinstance(message, bytes), "message should be an integer, string, or bytes."
        if isinstance(message, str):
            message = int.from_bytes(message.encode(), 'big')
        elif isinstance(message, bytes):
            message = int.from_bytes(message, 'big')
        try:
            return pow(message, self.d, self.n)
        except:
            print("Invalid message.")
    
    def verify(self, signature: int | str | bytes, return_type='int') -> int | str | bytes:
        """
        Verifies the given signature using the RSA Algorithm and returns the message.

        Parameters
        ------------
        + signature: int, str, bytes
            The signature to be verified.
        + return_type: str
            The type of the message to be returned. It should be either 'int', 'str', or 'bytes'.

        Returns
        ------------
        + int, str, bytes
            The message after verifying the signature.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> rsa = RSA(1024)
        # Verify the signature
        >>> rsa.verify(1234567890)
        123
        ```
        """
        assert isinstance(signature, int) or isinstance(signature, str) or isinstance(signature, bytes), "signature should be an integer, string, or bytes."
        assert return_type in ['int', 'str', 'bytes'], "return_type should be either 'int', 'str', or 'bytes'."
        if isinstance(signature, str):
            signature = int.from_bytes(signature.encode(), 'big')
        elif isinstance(signature, bytes):
            signature = int.from_bytes(signature, 'big')
        try:
            message = pow(signature, self.e, self.n)
            if return_type == 'str':
                return message.to_bytes((message.bit_length() + 7) // 8, 'big').decode()
            elif return_type == 'bytes':
                return message.to_bytes((message.bit_length() + 7) // 8, 'big')
            return message
        except:
            print("Invalid signature.")

    def getPublicKey(self) -> tuple:
        """
        Returns the public key.

        Returns
        ------------
        + tuple
            The public key.
            - e: int
                Public exponent.
            - n: int
                Modulus.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> rsa = RSA(1024)
        # Get the public key
        >>> rsa.getPublicKey()
        (65537, 123)
        ```
        """
        return self.e, self.n
    
    def getPrivateKey(self) -> tuple:
        """
        Returns the private key.

        Returns
        ------------
        + tuple
            The private key.
            - d: int
                Private exponent.
            - n: int
                Modulus.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> rsa = RSA(1024)
        # Get the private key
        >>> rsa.getPrivateKey()
        (123, 123)
        ```
        """
        return self.d, self.n
    
    def getFactors(self) -> tuple:
        """
        Returns the prime factors of the modulus.

        Returns
        ------------
        + tuple
            The prime factors of the modulus.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> rsa = RSA(1024)
        # Get the prime factors
        >>> rsa.getFactors()
        (123, 123)
        ```
        """
        return self.p, self.q
    
class ElGamal:
    """
    A class to encrypt and decrypt the given plaintext and ciphertext using the ElGamal Algorithm.

    Attributes
    ------------
    + p: int
        Prime number.
    + g: int
        Generator.
    + x: int
        Private key.
    + y: int
        Public key.

    Methods
    ------------
    `encrypt(plaintext: int | str | bytes)` -> tuple:
        Encrypts the given plaintext using the ElGamal Algorithm and returns the ciphertext.
    `decrypt(ciphertext: tuple, return_type: str)` -> int | str | bytes:
        Decrypts the given ciphertext using the ElGamal Algorithm and returns the plaintext.
    `sign(message: int | str | bytes)` -> tuple:
        Signs the given message using the ElGamal Algorithm and returns the signature.
    `verify(signature: tuple, return_type: str)` -> int | str | bytes:
        Verifies the given signature using the ElGamal Algorithm and returns the message
    `getPublicKey()` -> tuple:
        Returns the public key.
    `getPrivateKey()` -> int:
        Returns the private key.

    Usage
    ------------
    ```python
    # Import the class
    >>> from cryptosystems import ElGamal
    # Create an object of the class
    >>> elgamal = ElGamal(1024)
    # Encrypt the plaintext
    >>> elgamal.encrypt(123)
    (123, 123)
    # Decrypt the ciphertext
    >>> elgamal.decrypt((123, 123))
    123
    ```
    """

    def __init__(self, bits=1024):
        """
        Parameters
        ------------
        + bits: int
            Number of bits for the prime number.

        Usage
        ------------
        ```python
        # Import the class
        >>> from cryptosystems import ElGamal
        # Create an object of the class
        >>> elgamal = ElGamal()
        ```
        """
        assert isinstance(bits, int), "bits should be an integer"
        assert bits >= 2, "bits should be >= 2"
        # assert bits.bit_length()%2==0, "bits should be a power of 2"
        self.p = getPrime(bits)
        self.g = 2
        self.x = getRandomRange(1, self.p-1)
        self.y = pow(self.g, self.x, self.p)

    def encrypt(self, plaintext: int | str | bytes) -> tuple:
        """
        Encrypts the given plaintext using the ElGamal Algorithm and returns the ciphertext.

        Parameters
        ------------
        + plaintext: int, str, bytes
            The plaintext to be encrypted.

        Returns
        ------------
        + tuple
            The ciphertext after encrypting the plaintext.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> elgamal = ElGamal(1024)
        # Encrypt the plaintext
        >>> elgamal.encrypt(123)
        (123, 123)
        ```
        """
        assert isinstance(plaintext, int) or isinstance(plaintext, str) or isinstance(plaintext, bytes), "plaintext should be an integer, string, or bytes."
        if isinstance(plaintext, str):
            plaintext = int.from_bytes(plaintext.encode(), 'big')
        elif isinstance(plaintext, bytes):
            plaintext = int.from_bytes(plaintext, 'big')
        k = getRandomRange(1, self.p-1)
        a = pow(self.g, k, self.p)
        b = (plaintext * pow(self.y, k, self.p)) % self.p
        return a, b
    
    def decrypt(self, ciphertext: tuple, return_type='int') -> int | str | bytes:
        """
        Decrypts the given ciphertext using the ElGamal Algorithm and returns the plaintext.

        Parameters
        ------------
        + ciphertext: tuple
            The ciphertext to be decrypted.
        + return_type: str
            The type of the plaintext to be returned. It should be either 'int', 'str', or 'bytes'.

        Returns
        ------------
        + int, str, bytes
            The plaintext after decrypting the ciphertext.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> elgamal = ElGamal(1024)
        # Decrypt the ciphertext
        >>> elgamal.decrypt((123, 123))
        123
        ```
        """
        assert isinstance(ciphertext, tuple), "ciphertext should be a tuple."
        assert return_type in ['int', 'str', 'bytes'], "return_type should be either 'int', 'str', or 'bytes'."
        a, b = ciphertext
        plaintext = (b * pow(a, self.p-1-self.x, self.p)) % self.p
        if return_type == 'str':
            return plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big').decode()
        elif return_type == 'bytes':
            return plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big')
        return plaintext
    
    def sign(self, message: int | str | bytes) -> tuple:
        """
        Signs the given message using the ElGamal Algorithm and returns the signature.

        Parameters
        ------------
        + message: int, str, bytes
            The message to be signed.

        Returns
        ------------
        + tuple
            The signature after signing the message.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> elgamal = ElGamal(1024)
        # Sign the message
        >>> elgamal.sign(123)
        (123, 123)
        ```
        """
        assert isinstance(message, int) or isinstance(message, str) or isinstance(message, bytes), "message should be an integer, string, or bytes."
        if isinstance(message, str):
            message = int.from_bytes(message.encode(), 'big')
        elif isinstance(message, bytes):
            message = int.from_bytes(message, 'big')
        k = getRandomRange(1, self.p-1)
        a = pow(self.g, k, self.p)
        b = ((message - self.x*a) * pow(k, -1, self.p-1)) % (self.p-1)
        return a, b
    
    def verify(self, signature: tuple, return_type='int') -> int | str | bytes:
        """
        Verifies the given signature using the ElGamal Algorithm and returns the message.

        Parameters
        ------------
        + signature: tuple
            The signature to be verified.
        + return_type: str
            The type of the message to be returned. It should be either 'int', 'str', or 'bytes'.

        Returns
        ------------
        + int, str, bytes
            The message after verifying the signature.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> elgamal = ElGamal(1024)
        # Verify the signature
        >>> elgamal.verify((123, 123))
        123
        ```
        """
        assert isinstance(signature, tuple), "signature should be a tuple."
        assert return_type in ['int', 'str', 'bytes'], "return_type should be either 'int', 'str', or 'bytes'."
        a, b = signature
        message = (pow(self.y, a, self.p) * pow(a, b, self.p)) % self.p
        if return_type == 'str':
            return message.to_bytes((message.bit_length() + 7) // 8, 'big').decode()
        elif return_type == 'bytes':
            return message.to_bytes((message.bit_length() + 7) // 8, 'big')
        return message

    def getPublicKey(self) -> tuple:
        """
        Returns the public key.

        Returns
        ------------
        + tuple
            The public key.
            - y: int
                Public key.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> elgamal = ElGamal(1024)
        # Get the public key
        >>> elgamal.getPublicKey()
        123
        ```
        """
        return self.y

    def getPrivateKey(self) -> int:
        """
        Returns the private key.

        Returns
        ------------
        + int
            The private key.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> elgamal = ElGamal(1024)
        # Get the private key
        >>> elgamal.getPrivateKey()
        123
        ```
        """
        return self.x

class Rabin:
    """
    A class to encrypt and decrypt the given plaintext and ciphertext using the Rabin Cryptosystem.

    Attributes
    ------------
    + p: int
        Prime number.
    + q: int
        Prime number.

    Methods
    ------------
    `encrypt(plaintext: int | str | bytes)` -> int:
        Encrypts the given plaintext using the Rabin Cryptosystem and returns the ciphertext.
    `decrypt(ciphertext: int | str | bytes, return_type: str)` -> list: int | str | bytes:
        Decrypts the given ciphertext using the Rabin Cryptosystem and returns the plaintext.
    `sign(message: int | str | bytes)` -> int:
        Signs the given message using the Rabin Cryptosystem and returns the signature.
    `verify(signature: int | str | bytes, return_type: str)` -> int | str | bytes:
        Verifies the given signature using the Rabin Cryptosystem and returns the message.
    `getPublicKey()` -> tuple:
        Returns the public key.
    `getPrivateKey()` -> tuple:
        Returns the private key.

    Usage
    ------------
    ```python
    # Import the class
    >>> from cryptosystems import Rabin
    # Create an object of the class
    >>> rabin = Rabin(1024)
    # Encrypt the plaintext
    >>> rabin.encrypt(123)
    1234567890
    # Decrypt the ciphertext
    >>> rabin.decrypt(1234567890)
    123
    ```
    """

    def __init__(self, bits=1024):
        """
        Parameters
        ------------
        + bits: int
            Number of bits for the prime numbers.

        Usage
        ------------
        ```python
        # Import the class
        >>> from cryptosystems import Rabin
        # Create an object of the class
        >>> rabin = Rabin()
        ```
        """
        assert isinstance(bits, int), "bits should be an integer"
        assert bits >= 2, "bits should be >= 2"
        # assert bits.bit_length()%2==0, "bits should be a power of 2"
        self.p = getPrime(bits)
        self.q = getPrime(bits)
        while self.p == self.q or self.p % 4 != 3 or self.q % 4 != 3:
            self.p = getPrime(bits)
            self.q = getPrime(bits)

    def encrypt(self, plaintext: int | str | bytes) -> int:
        """
        Encrypts the given plaintext using the Rabin Cryptosystem and returns the ciphertext.

        Parameters
        ------------
        + plaintext: int, str, bytes
            The plaintext to be encrypted.

        Returns
        ------------
        + int
            The ciphertext after encrypting the plaintext.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> rabin = Rabin(1024)
        # Encrypt the plaintext
        >>> rabin.encrypt(1234567890)
        123
        ```
        """
        assert isinstance(plaintext, int) or isinstance(plaintext, str) or isinstance(plaintext, bytes), "plaintext should be an integer, string, or bytes."
        self.return_type = type(plaintext).__name__
        self.message_hash = sha256(plaintext.encode()).digest()
        if isinstance(plaintext, str):
            plaintext = int.from_bytes(plaintext.encode(), 'big')
        elif isinstance(plaintext, bytes):
            plaintext = int.from_bytes(plaintext, 'big')
        return pow(plaintext, 2, self.p * self.q)

    def decrypt(self, ciphertext: int | str | bytes, return_type=None, get_all=False) -> int | str | bytes:
        """
        Decrypts the given ciphertext using the Rabin Cryptosystem and returns the plaintext.

        Parameters
        ------------
        + ciphertext: int, str, bytes
            The ciphertext to be decrypted.
        + return_type: str
            The type of the plaintext to be returned. It should be either 'int', 'str', or 'bytes'.
        + get_all: bool
            Whether to return all possible plaintexts or not. Default is False. If True, it will return all possible plaintexts.

        Returns
        ------------
        + list: int, str, bytes
            The plaintext after decrypting the ciphertext.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> rabin = Rabin(1024)
        # Decrypt the ciphertext
        >>> rabin.decrypt(1234567890)
        123
        ```
        """
        if return_type is None:
            return_type = self.return_type
        assert return_type == self.return_type, "ciphertext should be of the same type as the plaintext used for encryption."
        if isinstance(ciphertext, str):
            ciphertext = int.from_bytes(ciphertext.encode(), 'big')
        elif isinstance(ciphertext, bytes):
            ciphertext = int.from_bytes(ciphertext, 'big')
        n = self.p * self.q
        a = pow(ciphertext, (self.p+1)//4, self.p)
        b = pow(ciphertext, (self.q+1)//4, self.q)
        y_p = pow(self.q, -1, self.p)
        x_q = pow(self.p, -1, self.q)
        p1 = (a * self.q * y_p + b * self.p * x_q) % n
        p2 = (a * self.q * y_p - b * self.p * x_q) % n
        p3 = -p1 % n
        p4 = -p2 % n
        plaintexts = [p1, p2, p3, p4]
        if return_type == 'str':
            if not get_all:
                for plaintext in plaintexts:
                    try:
                        if sha256(plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big').decode().encode()).digest() == self.message_hash:
                            return plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big').decode()
                    except:
                        pass
            else:
                try:
                    return (plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big').decode() for plaintext in plaintexts)
                except:
                    print("Invalid ciphertext for 'str' format.")

        elif return_type == 'bytes':
            if not get_all:
                for plaintext in plaintexts:
                    try:
                        if plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big') == self.message_hash:
                            return plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big')
                    except:
                        pass
            else:
                try:
                    return (plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big') for plaintext in plaintexts)
                except:
                    print("Invalid ciphertext for 'bytes' format.")
                    
        if not get_all:
            for plaintext in plaintexts:
                if plaintext == self.message_hash:
                    return plaintext
        return plaintexts

    def sign(self, message: int | str | bytes) -> int:
        """
        Signs the given message using the Rabin Cryptosystem and returns the signature.

        Parameters
        ------------
        + message: int, str, bytes
            The message to be signed.

        Returns
        ------------
        + int
            The signature after signing the message.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> rabin = Rabin(1024)
        # Sign the message
        >>> rabin.sign(123)
        1234567890
        ```
        """
        assert isinstance(message, int) or isinstance(message, str) or isinstance(message, bytes), "message should be an integer, string, or bytes."
        if isinstance(message, str):
            message = int.from_bytes(message.encode(), 'big')
        elif isinstance(message, bytes):
            message = int.from_bytes(message, 'big')
        return pow(message, 2, self.p * self.q)

    def verify(self, signature: int | str | bytes, return_type='int') -> int | str | bytes:
        """
        Verifies the given signature using the Rabin Cryptosystem and returns the message.

        Parameters
        ------------
        + signature: int, str, bytes
            The signature to be verified.
        + return_type: str
            The type of the message to be returned. It should be either 'int', 'str', or 'bytes'.

        Returns
        ------------
        + int, str, bytes
            The message after verifying the signature.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> rabin = Rabin(1024)
        # Verify the signature
        >>> rabin.verify(1234567890)
        123
        ```
        """
        assert isinstance(signature, int) or isinstance(signature, str) or isinstance(signature, bytes), "signature should be an integer, string, or bytes."
        assert return_type in ['int', 'str', 'bytes'], "return_type should be either 'int', 'str', or 'bytes'."
        if isinstance(signature, str):
            signature = int.from_bytes(signature.encode(), 'big')
        elif isinstance(signature, bytes):
            signature = int.from_bytes(signature, 'big')
        n = self.p * self.q
        r = pow(signature, (self.p+1)//4, self.p)
        s = pow(signature, (self.q+1)//4, self.q)
        y_p = pow(self.q, -1, self.p)
        x_q = pow(self.p, -1, self.q)
        messages = [(r * self.q * y_p + s * self.p * x_q) % n, (r * self.q * y_p - s * self.p * x_q) % n, -r * self.q * y_p + s * self.p * x_q, -r * self.q * y_p - s * self.p * x_q]
        if return_type == 'str':
            try:
                return (message.to_bytes((message.bit_length() + 7) // 8, 'big').decode() for message in messages)
            except:
                print("Invalid signature for 'str' format.")
        elif return_type == 'bytes':
            try:
                return (message.to_bytes((message.bit_length() + 7) // 8, 'big') for message in messages)
            except:
                print("Invalid signature for 'bytes' format.")
        return messages

    def getPublicKey(self) -> tuple:
        """
        Returns the public key.

        Returns
        ------------
        + tuple
            The public key.
            - p: int
                Prime number.
            - q: int
                Prime number.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> rabin = Rabin(1024)
        # Get the public key
        >>> rabin.getPublicKey()
        (123, 123)
        ```
        """
        return self.p * self.q

    def getPrivateKey(self) -> tuple:
        """
        Returns the private key.

        Returns
        ------------
        + tuple
            The private key.
            - p: int
                Prime number.
            - q: int
                Prime number.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> rabin = Rabin(1024)
        # Get the private key
        >>> rabin.getPrivateKey()
        (123, 123)
        ```
        """
        return self.p, self.q
    
    # def rabin(self, message: int | str | bytes) -> int:
    #     """
    #     Due to high failure rate, the helper function rabin() checks key_pairs until a valid one is found.
    #     """
    #     assert isinstance(message, int) or isinstance(message, str) or isinstance(message, bytes), "message should be an integer, string, or bytes."
    #     if isinstance(message, str):
    #         message = int.from_bytes(message.encode(), 'big')
    #     elif isinstance(message, bytes):
    #         message = int.from_bytes(message, 'big')
    #     while True:
    #         rabin = Rabin()
    #         ciphertext = rabin.encrypt(message)
    #         plaintext = rabin.decrypt(ciphertext)
    #         if plaintext == message:
    #             return ciphertext, self
    def rabin_helper(self, message: int | str | bytes) -> int:
            """
            Due to high failure rate, the helper function rabin() checks key_pairs until a valid one is found.

            Usage
            ------------
            ```python
            # Import the function
            >>> from cryptosystems import Rabin
            # Generate Rabin key pairs
            >>> rabin = Rabin()
            >>> rabin = rabin.rabin_helper("test")
            >>> rabin_ciphertext = rabin.encrypt("test")
            >>> rabin_ciphertext
            123
            >>> rabin_plaintext = rabin.decrypt(rabin_ciphertext)
            >>> rabin_plaintexts
            [1234567, 123, 1234567, 1234567]
            ```
            """
            assert isinstance(message, int) or isinstance(message, str) or isinstance(message, bytes), "message should be an integer, string, or bytes."
            if isinstance(message, str):
                message = int.from_bytes(message.encode(), 'big')
            elif isinstance(message, bytes):
                message = int.from_bytes(message, 'big')
            while True:
                print("Generating Rabin key pairs...", end='\r')
                rabin = Rabin()
                ciphertext = rabin.encrypt(message)
                plaintexts = rabin.decrypt(ciphertext)
                for i in plaintexts:
                    if i == message:
                        print(" "*50, end='\r')
                        print(plaintexts)
                        return self

class Paillier:
    """
    A class to encrypt and decrypt the given plaintext and ciphertext using the Paillier Cryptosystem.

    Attributes
    ------------
    + p: int
        Prime number.
    + q: int
        Prime number.
    + n: int
        Modulus.
    + g: int
        Generator.

    Methods
    ------------
    `encrypt(plaintext: int | str | bytes)` -> int:
        Encrypts the given plaintext using the Paillier Cryptosystem and returns the ciphertext.
    `decrypt(ciphertext: int | str | bytes, return_type: str)` -> int | str | bytes:
        Decrypts the given ciphertext using the Paillier Cryptosystem and returns the plaintext.
    `sign(message: int | str | bytes)` -> int:
        Signs the given message using the Paillier Cryptosystem and returns the signature.
    `verify(signature: int | str | bytes, return_type: str)` -> int | str | bytes:
        Verifies the given signature using the Paillier Cryptosystem and returns the message.
    `homeomorphicAddition(ciphertext1: int | str | bytes, ciphertext2: int | str | bytes)` -> int:
        Performs homomorphic addition on the given ciphertexts and returns the result.
    `getPublicKey()` -> tuple:
        Returns the public key.
    `getPrivateKey()` -> tuple:
        Returns the private key.

    Usage
    ------------
    ```python
    # Import the class
    >>> from cryptosystems import Paillier
    # Create an object of the class
    >>> pailier = Paillier(1024)
    # Encrypt the plaintext
    >>> pailier.encrypt(123)
    1234567890
    # Decrypt the ciphertext
    >>> pailier.decrypt(1234567890)
    123
    ```
    """

    def __init__(self, bits=1024):
        """
        Parameters
        ------------
        + bits: int
            Number of bits for the prime numbers.

        Usage
        ------------
        ```python
        # Import the class
        >>> from cryptosystems import Paillier
        # Create an object of the class
        >>> pailier = Paillier()
        ```
        """
        assert isinstance(bits, int), "bits should be an integer"
        assert bits >= 2, "bits should be >= 2"
        # assert bits.bit_length()%2==0, "bits should be a power of 2"
        self.p = getPrime(bits)
        self.q = getPrime(bits)
        while self.p == self.q:
            self.q = getPrime(bits)
        self.n = self.p * self.q
        self.g = self.n + 1

    def encrypt(self, plaintext: int | str | bytes) -> int:
        """
        Encrypts the given plaintext using the Paillier Cryptosystem and returns the ciphertext.

        Parameters
        ------------
        + plaintext: int, str, bytes
            The plaintext to be encrypted.

        Returns
        ------------
        + int
            The ciphertext after encrypting the plaintext.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> pailier = Paillier(1024)
        # Encrypt the plaintext
        >>> pailier.encrypt(123)
        1234567890
        ```
        """
        assert isinstance(plaintext, int) or isinstance(plaintext, str) or isinstance(plaintext, bytes), "plaintext should be an integer, string, or bytes."
        if isinstance(plaintext, str):
            plaintext = int.from_bytes(plaintext.encode(), 'big')
        elif isinstance(plaintext, bytes):
            plaintext = int.from_bytes(plaintext, 'big')
        r = getRandomRange(1, self.n - 1)
        c = (pow(self.g, plaintext, self.n**2) * pow(r, self.n, self.n**2)) % (self.n**2)
        return c

    def decrypt(self, ciphertext: int | str | bytes, return_type='int') -> int | str | bytes:
        """
        Decrypts the given ciphertext using the Paillier Cryptosystem and returns the plaintext.

        Parameters
        ------------
        + ciphertext: int, str, bytes
            The ciphertext to be decrypted.
        + return_type: str
            The type of the plaintext to be returned. It should be either 'int', 'str', or 'bytes'.
        
        Returns
        ------------
        + int, str, bytes
            The plaintext after decrypting the ciphertext.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> pailier = Paillier(1024)
        # Decrypt the ciphertext
        >>> pailier.decrypt(1234567890)
        123
        ```
        """
        assert isinstance(ciphertext, int) or isinstance(ciphertext, str) or isinstance(ciphertext, bytes), "ciphertext should be an integer, string, or bytes."
        assert return_type in ['int', 'str', 'bytes'], "return_type should be either 'int', 'str', or 'bytes'."
        if isinstance(ciphertext, str):
            ciphertext = int.from_bytes(ciphertext.encode(), 'big')
        elif isinstance(ciphertext, bytes):
            ciphertext = int.from_bytes(ciphertext, 'big')
        lambda_n = (self.p-1) * (self.q-1)
        mu = pow(lambda_n, -1, self.n)
        x = (pow(ciphertext, lambda_n, self.n**2) - 1) // self.n
        plaintext = (x * mu) % self.n
        if return_type == 'str':
            return plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big').decode()
        elif return_type == 'bytes':
            return plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big')
        return plaintext

    def sign(self, message: int | str | bytes) -> int:
        """
        Signs the given message using the Paillier Cryptosystem and returns the signature.

        Parameters
        ------------
        + message: int, str, bytes
            The message to be signed.

        Returns
        ------------
        + int
            The signature after signing the message.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> pailier = Paillier(1024)
        # Sign the message
        >>> pailier.sign(123)
        1234567890
        ```
        """
        assert isinstance(message, int) or isinstance(message, str) or isinstance(message, bytes), "message should be an integer, string, or bytes."
        if isinstance(message, str):
            message = int.from_bytes(message.encode(), 'big')
        elif isinstance(message, bytes):
            message = int.from_bytes(message, 'big')
        r = getRandomRange(1, self.n)
        s = (pow(self.g, message, self.n**2) * pow(r, self.n, self.n**2)) % (self.n**2)
        return s

    def verify(self, signature: int | str | bytes, return_type='int') -> int | str | bytes:
        """
        Verifies the given signature using the Paillier Cryptosystem and returns the message.

        Parameters
        ------------
        + signature: int, str, bytes
            The signature to be verified.
        + return_type: str
            The type of the message to be returned. It should be either 'int', 'str', or 'bytes'.

        Returns
        ------------
        + int, str, bytes
            The message after verifying the signature.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> pailier = Paillier(1024)
        # Verify the signature
        >>> pailier.verify(1234567890)
        123
        ```
        """
        assert isinstance(signature, int) or isinstance(signature, str) or isinstance(signature, bytes), "signature should be an integer, string, or bytes."
        assert return_type in ['int', 'str', 'bytes'], "return_type should be either 'int', 'str', or 'bytes'."
        if isinstance(signature, str):
            signature = int.from_bytes(signature.encode(), 'big')
        elif isinstance(signature, bytes):
            signature = int.from_bytes(signature, 'big')
        x = pow(signature, self.p-1, self.n)
        l = (x - 1) // self.n
        message = (l * pow(self.q, -1, self.p) * self.q) % self.n
        if return_type == 'str':
            return message.to_bytes((message.bit_length() + 7) // 8, 'big').decode()
        elif return_type == 'bytes':
            return message.to_bytes((message.bit_length() + 7) // 8, 'big')
        return message
    
    def homeomorphicAddition(self, ciphertext1: int | str | bytes, ciphertext2: int | str | bytes) -> int:
        """
        Performs homomorphic addition on the given ciphertexts and returns the result. Decryption will return the sum of the plaintexts.

        Parameters
        ------------
        + ciphertext1: int, str, bytes
            The first ciphertext.
        + ciphertext2: int, str, bytes
            The second ciphertext.

        Returns
        ------------
        + int
            The result of homomorphic addition on the given ciphertexts.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> pailier = Paillier(1024)
        # Perform homomorphic addition
        >>> pailier.homeomorphicAddition(123, 123)
        1234567890
        >>> pailier.decrypt(1234567890)
        246
        ```
        """
        assert isinstance(ciphertext1, int) or isinstance(ciphertext1, str) or isinstance(ciphertext1, bytes), "ciphertext1 should be an integer, string, or bytes."
        assert isinstance(ciphertext2, int) or isinstance(ciphertext2, str) or isinstance(ciphertext2, bytes), "ciphertext2 should be an integer, string, or bytes."
        if isinstance(ciphertext1, str):
            ciphertext1 = int.from_bytes(ciphertext1.encode(), 'big')
        elif isinstance(ciphertext1, bytes):
            ciphertext1 = int.from_bytes(ciphertext1, 'big')
        if isinstance(ciphertext2, str):
            ciphertext2 = int.from_bytes(ciphertext2.encode(), 'big')
        elif isinstance(ciphertext2, bytes):
            ciphertext2 = int.from_bytes(ciphertext2, 'big')
        return (ciphertext1 * ciphertext2) % (self.n**2)

    def getPublicKey(self) -> tuple:
        """
        Returns the public key.

        Returns
        ------------
        + tuple
            The public key.
            - n: int
                Modulus.
            - g: int
                Generator.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> pailier = Paillier(1024)
        # Get the public key
        >>> pailier.getPublicKey()
        (123, 123)
        ```
        """
        return self.n, self.g

    def getPrivateKey(self) -> tuple:
        """
        Returns the private key.

        Returns
        ------------
        + tuple
            The private key.
            - p: int
                Prime number.
            - q: int
                Prime number.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> pailier = Paillier(1024)
        # Get the private key
        >>> pailier.getPrivateKey()
        (123, 123)
        ```
        """
        return self.p, self.q

class DiffieHellman:
    """
    A class to generate the shared secret key using the Diffie-Hellman Key Exchange Algorithm.

    Attributes
    ------------
    + p: int
        Prime number.
    + g: int
        Generator.
    + a: int
        Private key of Alice.
    + A: int
        Public key of Alice.
    + b: int
        Private key of Bob.
    + B: int
        Public key of Bob.

    Methods
    ------------
    `getSharedSecret()` -> int:
        Generates the shared secret key using the Diffie-Hellman Key Exchange Algorithm.
    `getKeyA()` -> tuple:
        Returns the key of Alice.
        - A: int
            Public key of Alice.
        - a: int
            Private key of Alice.
    `getKeyB()` -> tuple:
        Returns the key of Bob.
        - B: int
            Public key of Alice.
        - b: int
            Private key of Bob.
    `getParams()` -> tuple:
        Returns the parameters.
        - p: int
            Prime number.
        - g: int
            Generator.

    Usage
    ------------
    ```python
    # Import the class
    >>> from cryptosystems import DiffieHellman
    # Create an object of the class
    >>> diffiehellman = DiffieHellman()
    # Generate the shared secret key
    >>> diffiehellman.getSharedSecret()
    1234567890
    ```
    """

    def __init__(self, bits=1024):
        """
        Usage
        ------------
        ```python
        # Import the class
        >>> from cryptosystems import DiffieHellman
        # Create an object of the class
        >>> diffiehellman = DiffieHellman()
        ```
        """
        self.p = getPrime(bits)
        self.g = 2
        self.a = getRandomRange(1, self.p-1)
        self.A = pow(self.g, self.a, self.p)
        self.b = getRandomRange(1, self.p-1)
        self.B = pow(self.g, self.b, self.p)

    def getSharedSecret(self) -> int:
        """
        Generates the shared secret key using the Diffie-Hellman Key Exchange Algorithm.

        Returns
        ------------
        + int
            The shared secret key.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> diffiehellman = DiffieHellman()
        # Generate the shared secret key
        >>> diffiehellman.getSharedSecret()
        1234567890
        ```
        """
        s1 = pow(self.B, self.a, self.p)
        s2 = pow(self.A, self.b, self.p)
        assert s1 == s2, "Shared secret key is not equal."
        return s1
    
    def getKeyA(self) -> tuple:
        """
        Returns the key of Alice.

        Returns
        ------------
        + tuple
            The key of Alice.
            - A: int
                Public key of Alice.
            - a: int
                Private key of Alice.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> diffiehellman = DiffieHellman()
        # Get the public key
        >>> diffiehellman.getKeyA()
        (123, 123)
        ```
        """
        return self.A, self.a
    
    def getKeyB(self) -> tuple:
        """
        Returns the key of Bob.
        
        Returns
        ------------
        + tuple
            The key of Bob.
            - B: int
                Public key of Bob.
            - b: int
                Private key of Bob.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> diffiehellman = DiffieHellman()
        # Get the private key
        >>> diffiehellman.getKeyB()
        (123, 123)
        ```
        """
        return self.B, self.b
    
    def getParams(self) -> tuple:
        """
        Returns the parameters.

        Returns
        ------------
        + tuple
            The parameters.
            - p: int
                Prime number.
            - g: int
                Generator.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> diffiehellman = DiffieHellman()
        # Get the parameters
        >>> diffiehellman.getParams()
        (123, 123)
        ```
        """
        return self.p, self.g

class ECC:
    """
    A class to encrypt and decrypt the given plaintext and ciphertext using the Elliptic Curve Cryptography.

    Attributes
    ------------
    + curve: tuple
        The parameters of the curve.
    + G: tuple
        The generator point.
    + n: int
        The order of the curve.
    + d: int
        The private key.
    + Q: tuple
        The public key.

    Methods
    ------------
    `encrypt(plaintext: int | str | bytes)` -> tuple:
        Encrypts the given plaintext using the Elliptic Curve Cryptography and returns the ciphertext.
    `decrypt(ciphertext: tuple, return_type: str)` -> int | str | bytes:
        Decrypts the given ciphertext using the Elliptic Curve Cryptography and returns the plaintext.
    `sign(message: int | str | bytes)` -> tuple:
        Signs the given message using the Elliptic Curve Cryptography and returns the signature.
    `verify(signature: tuple, return_type: str)` -> int | str | bytes:
        Verifies the given signature using the Elliptic Curve Cryptography and returns the message.
    `getPublicKey()` -> tuple:
        Returns the public key.
    `getPrivateKey()` -> int:
        Returns the private key.

    Usage
    ------------
    ```python
    # Import the class
    >>> from cryptosystems import ECC
    # Create an object of the class
    >>> ecc = ECC()
    # Encrypt the plaintext
    >>> ecc.encrypt(123)
    (123, 123)
    # Decrypt the ciphertext
    >>> ecc.decrypt((123, 123))
    123
    ```
    """

    def __init__(self):
        """
        Usage
        ------------
        ```python
        # Import the class
        >>> from cryptosystems import ECC
        # Create an object of the class
        >>> ecc = ECC()
        ```
        """
        self.G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
        self.curve = (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F, 0, 7)
        self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        self.d = getRandomRange(1, self.n)
        self.Q = self.multiply(self.G, self.d)

    def add(self, P: tuple, Q: tuple) -> tuple:
        """
        Adds two points on the curve.

        Parameters
        ------------
        + P: tuple
            The first point.
        + Q: tuple
            The second point.

        Returns
        ------------
        + tuple
            The sum of the two points.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> ecc = ECC()
        # Add two points
        >>> ecc.add((123, 123), (123, 123))
        (123, 123)
        ```
        """
        if P == (0, 0):
            return Q
        if Q == (0, 0):
            return P
        x1, y1 = P
        x2, y2 = Q
        if P != Q:
            m = (y2 - y1) * pow(x2 - x1, self.curve[0] - 2, self.curve[0])
        else:
            m = (3 * x1**2) * pow(2 * y1, self.curve[0] - 2, self.curve[0])
        x3 = (m**2 - x1 - x2) % self.curve[0]
        y3 = (m * (x1 - x3) - y1) % self.curve[0]
        return x3, y3
    
    def multiply(self, P: tuple, n: int) -> tuple:
        """
        Multiplies a point with a scalar.

        Parameters
        ------------
        + P: tuple
            The point.
        + n: int
            The scalar.

        Returns
        ------------
        + tuple
            The product of the point and the scalar.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> ecc = ECC()
        # Multiply a point with a scalar
        >>> ecc.multiply((123, 123), 123)
        (123, 123)
        ```
        """
        Q = (0, 0)
        p = P
        while n:
            if n & 1:
                Q = self.add(Q, p)
            p = self.add(p, p)
            n >>= 1
        return Q
    
    def encrypt(self, plaintext: int | str | bytes) -> tuple:
        """
        Encrypts the given plaintext using the Elliptic Curve Cryptography and returns the ciphertext.

        Parameters
        ------------
        + plaintext: int, str, bytes
            The plaintext to be encrypted.

        Returns
        ------------
        + tuple
            The ciphertext after encrypting the plaintext.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> ecc = ECC()
        # Encrypt the plaintext
        >>> ecc.encrypt(123)
        (123, 123)
        ```
        """
        assert isinstance(plaintext, int) or isinstance(plaintext, str) or isinstance(plaintext, bytes), "plaintext should be an integer, string, or bytes."
        if isinstance(plaintext, str):
            plaintext = int.from_bytes(plaintext.encode(), 'big')
        elif isinstance(plaintext, bytes):
            plaintext = int.from_bytes(plaintext, 'big')
        C1 = self.multiply(self.G, self.d)
        dQ = self.multiply(self.Q, self.d)
        C2 = (plaintext + dQ[0]) % self.n
        return C1, C2
    
    def decrypt(self, ciphertext: tuple, return_type='int') -> int | str | bytes:
        """
        Decrypts the given ciphertext using the Elliptic Curve Cryptography and returns the plaintext.

        Parameters
        ------------
        + ciphertext: tuple
            The ciphertext to be decrypted.
        + return_type: str
            The type of the plaintext to be returned. It should be either 'int', 'str', or 'bytes'.

        Returns
        ------------
        + int, str, bytes
            The plaintext after decrypting the ciphertext.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> ecc = ECC()
        # Decrypt the ciphertext
        >>> ecc.decrypt((123, 123))
        123
        ```
        """
        assert isinstance(ciphertext, tuple), "ciphertext should be a tuple."
        assert return_type in ['int', 'str', 'bytes'], "return_type should be either 'int', 'str', or 'bytes'."
        C1, C2 = ciphertext
        dQ = self.multiply(C1, self.d)
        plaintext = (C2 - dQ[0]) % self.n
        if return_type == 'str':
            return plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big').decode()
        elif return_type == 'bytes':
            return plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big')
        return plaintext
    
    def sign(self, message: int | str | bytes) -> tuple:
        """
        Signs the given message using the Elliptic Curve Cryptography and returns the signature.

        Parameters
        ------------
        + message: int, str, bytes
            The message to be signed.

        Returns
        ------------
        + tuple
            The signature after signing the message.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> ecc = ECC()
        # Sign the message
        >>> ecc.sign(123)
        (123, 123)
        ```
        """
        assert isinstance(message, int) or isinstance(message, str) or isinstance(message, bytes), "message should be an integer, string, or bytes."
        if isinstance(message, str):
            message = int.from_bytes(message.encode(), 'big')
        elif isinstance(message, bytes):
            message = int.from_bytes(message, 'big')
        k = getRandomRange(1, self.n - 1)
        C1 = self.multiply(self.G, k)
        dQ = self.multiply(self.Q, k)
        r = (message + dQ[0]) % self.n
        s = pow(k, -1, self.n) * (r * self.d) % self.n
        return r, s
    
    def verify(self, signature: tuple, return_type='int') -> int | str | bytes:
        """
        Verifies the given signature using the Elliptic Curve Cryptography and returns the message.

        Parameters
        ------------
        + signature: tuple
            The signature to be verified.
        + return_type: str
            The type of the message to be returned. It should be either 'int', 'str', or 'bytes'.

        Returns
        ------------
        + int, str, bytes
            The message after verifying the signature.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> ecc = ECC()
        # Verify the signature
        >>> ecc.verify((123, 123))
        123
        ```
        """
        assert isinstance(signature, tuple), "signature should be a tuple."
        assert return_type in ['int', 'str', 'bytes'], "return_type should be either 'int', 'str', or 'bytes'."
        r, s = signature
        w = pow(s, -1, self.n)
        u1 = (w * r) % self.n
        u2 = (w * s) % self.n
        P = self.add(self.multiply(self.G, u1), self.multiply(self.Q, u2))
        if r == P[0] % self.n:
            return True
        return False
    
    def getPublicKey(self) -> tuple:
        """
        Returns the public key.

        Returns
        ------------
        + tuple
            The public key.
            - Q: tuple
                The public key.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> ecc = ECC()
        # Get the public key
        >>> ecc.getPublicKey()
        (123, 123)
        ```
        """
        return self.Q
    
    def getPrivateKey(self) -> int:
        """
        Returns the private key.

        Returns
        ------------
        + int
            The private key.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> ecc = ECC()
        # Get the private key
        >>> ecc.getPrivateKey()
        123
        ```
        """
        return self.d
    
    def getParams(self) -> tuple:
        """
        Returns the parameters.

        Returns
        ------------
        + tuple
            The parameters.
            - curve: tuple
                The parameters of the curve.
            - G: tuple
                The generator point.
            - n: int
                The order of the curve.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> ecc = ECC()
        # Get the parameters
        >>> ecc.getParams()
        (123, 123, 123)
        ```
        """
        return self.curve, self.G, self.n

class MD5:
    """
    A class to hash the given message or file using the MD5 Algorithm.

    Methods
    ------------
    `hash(message: int | str | bytes)` -> str:
        Hashes the given message using the MD5 Algorithm and returns the digest.
    `hash_file(file: str)` -> str:
        Hashes the given file using the MD5 Algorithm and returns the digest.

    Usage
    ------------
    ```python
    # Import the class
    >>> from cryptosystems import MD5
    # Create an object of the class
    >>> md5 = MD5()
    # Hash the message
    >>> md5.hash("Hello World")
    'b10a8db164e0754105b7a99be72e3fe5'
    ```
    """

    def __init__(self):
        """
        Usage
        ------------
        ```python
        # Import the class
        >>> from cryptosystems import MD5
        # Create an object of the class
        >>> md5 = MD5()
        ```
        """
        pass

    def hash(self, message: int | str | bytes) -> str:
        """
        Hashes the given message using the MD5 Algorithm and returns the digest.

        Parameters
        ------------
        + message: int, str, bytes
            The message to be hashed.

        Returns
        ------------
        + str
            The digest after hashing the message.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> md5 = MD5()
        # Hash the message
        >>> md5.hash("Hello World")
        'b10a8db164e0754105b7a99be72e3fe5'
        ```
        """
        assert isinstance(message, int) or isinstance(message, str) or isinstance(message, bytes), "message should be an integer, string, or bytes."
        if isinstance(message, str):
            message = message.encode()
        elif isinstance(message, int):
            message = int.to_bytes(message, (message.bit_length() + 7) // 8, 'big')
        return md5(message).hexdigest()
    
    def hash_file(self, file: str) -> str:
        """
        Hashes the given file using the MD5 Algorithm and returns the digest.

        Parameters
        ------------
        + file: str
            The file to be hashed.

        Returns
        ------------
        + str
            The digest after hashing the file.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> md5 = MD5()
        # Hash the file
        >>> md5.hash_file("test.txt")
        'b10a8db164e0754105b7a99be72e3fe5'
        ```
        """
        return md5(open(file, 'rb').read()).hexdigest()
    
class SHA256:
    """
    A class to hash the given message or file using the SHA-256 Algorithm.

    Methods
    ------------
    `hash(message: int | str | bytes)` -> str:
        Hashes the given message using the SHA-256 Algorithm and returns the digest.
    `hash_file(file: str)` -> str:
        Hashes the given file using the SHA-256 Algorithm and returns the digest.

    Usage
    ------------
    ```python
    # Import the class
    >>> from cryptosystems import SHA256
    # Create an object of the class
    >>> sha256 = SHA256()
    # Hash the message
    >>> sha256.hash("Hello World")
    'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e'
    ```
    """

    def __init__(self):
        """
        Usage
        ------------
        ```python
        # Import the class
        >>> from cryptosystems import SHA256
        # Create an object of the class
        >>> sha256 = SHA256()
        ```
        """
        pass

    def hash(self, message: int | str | bytes) -> str:
        """
        Hashes the given message using the SHA-256 Algorithm and returns the digest.

        Parameters
        ------------
        + message: int, str, bytes
            The message to be hashed.

        Returns
        ------------
        + str
            The digest after hashing the message.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> sha256 = SHA256()
        # Hash the message
        >>> sha256.hash("Hello World")
        'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e'
        ```
        """
        assert isinstance(message, int) or isinstance(message, str) or isinstance(message, bytes), "message should be an integer, string, or bytes."
        if isinstance(message, str):
            message = message.encode()
        elif isinstance(message, int):
            message = int.to_bytes(message, (message.bit_length() + 7) // 8, 'big')
        return sha256(message).hexdigest()
    
    def hash_file(self, file: str) -> str:
        """
        Hashes the given file using the SHA-256 Algorithm and returns the digest.

        Parameters
        ------------
        + file: str
            The file to be hashed.

        Returns
        ------------
        + str
            The digest after hashing the file.

        Example
        ------------
        ```python
        # Create an object of the class
        >>> sha256 = SHA256()
        # Hash the file
        >>> sha256.hash_file("test.txt")
        'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e'
        ```
        """
        return sha256(open(file, 'rb').read()).hexdigest()
