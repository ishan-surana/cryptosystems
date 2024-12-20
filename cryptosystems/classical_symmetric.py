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
    .. code-block:: python
    
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
        .. code-block:: python

            # Import the class
            >>> from cryptosystems import AffineCipher
            # Create an object of the class
            >>> cipher = AffineCipher(5, 8)
        """
        assert isinstance(a, int) and isinstance(b, int), "Keys should be integers."
        assert a % 2 != 0 and a % 13 != 0, "Key 'a' should be coprime with 26."
        self.a = a % 26
        self.b = b % 26

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
        .. code-block:: python

            # Create an object of the class
            >>> cipher = AffineCipher(5, 8)
            # Encrypt the plaintext
            >>> cipher.encrypt("Hello World")
            'Rclla Oaplx'
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
        .. code-block:: python

            # Create an object of the class
            >>> cipher = AffineCipher(5, 8)
            # Decrypt the ciphertext
            >>> cipher.decrypt("Rclla Oaplx") 
            'Hello World'
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
    .. code-block:: python

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
    """
    
    def __init__(self, k):
        """
        Parameters
        ------------
        + k: int
            Key for the additive cipher. It should be an integer.

        Usage
        ------------
        .. code-block:: python

            # Import the class
            >>> from cryptosystems import AdditiveCipher
            # Create an object of the class
            >>> cipher = AdditiveCipher(3)
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
        .. code-block:: python

            # Create an object of the class
            >>> cipher = AdditiveCipher(3)
            # Encrypt the plaintext
            >>> cipher.encrypt("Hello World")
            'Khoor Zruog'
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
        .. code-block:: python

            # Create an object of the class
            >>> cipher = AdditiveCipher(3)
            # Decrypt the ciphertext
            >>> cipher.decrypt("Khoor Zruog")
            'Hello World'
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
    .. code-block:: python

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
    """
    
    def __init__(self, k):
        """
        Parameters
        ------------
        + k: int
            Key for the multiplicative cipher. It should be an integer.

        Usage
        ------------
        .. code-block:: python

            # Import the class
            >>> from cryptosystems import MultiplicativeCipher
            # Create an object of the class
            >>> cipher = MultiplicativeCipher(5)
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
        .. code-block:: python

            # Create an object of the class
            >>> cipher = MultiplicativeCipher(5)
            # Encrypt the plaintext
            >>> cipher.encrypt("Hello World")
            'Judds Gshdp'
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
        .. code-block:: python

            # Create an object of the class
            >>> cipher = MultiplicativeCipher(5)
            # Decrypt the ciphertext
            >>> cipher.decrypt("Judds Gshdp")
            'Hello World'
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
    .. code-block:: python

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
    """
    
    def __init__(self, key):
        """
        Parameters
        ------------
        + key: str
            Key for the Vigenere cipher. It should be a string of alphabets.
        
        Usage
        ------------
        .. code-block:: python

            # Import the class
            >>> from cryptosystems import VigenereCipher
            # Create an object of the class
            >>> cipher = VigenereCipher("key")
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
        .. code-block:: python

            # Create an object of the class
            >>> cipher = VigenereCipher("key")
            # Encrypt the plaintext
            >>> cipher.encrypt("Hello World")
            'Rijvs Uyvjk'
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
        .. code-block:: python

            # Create an object of the class
            >>>
            cipher = VigenereCipher("key")
            # Decrypt the ciphertext
            >>> cipher.decrypt("Rijvs Uyvjk")
            'Hello World'
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
    .. code-block:: python

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
    """
    
    def __init__(self, key):
        """
        Parameters
        ------------
        + key: int, str
            Key for the Auto-Key cipher. It can either be an integer, an alphabet, or a string of alphabets. The integer key should be in the range [0, 25], corresponding to the index of the alphabet.

        Usage
        ------------
        .. code-block:: python

            # Import the class
            >>> from cryptosystems import AutoKeyCipher
            # Create an object of the class
            >>> cipher = AutoKeyCipher("key")
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
        .. code-block:: python

            # Create an object of the class
            >>> cipher = AutoKeyCipher("key")
            # Encrypt the plaintext
            >>> cipher.encrypt("Hello World")
            'Rijss Hzfhr'
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
        .. code-block:: python

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
    .. code-block:: python

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
    """

    def __init__(self, key):
        """
        Parameters
        ------------
        + key: str
            Key for the Playfair cipher. It should be a string of alphabets. It should not contain 'J'.

        Usage
        ------------
        .. code-block:: python

            # Import the class
            >>> from cryptosystems import PlayfairCipher
            # Create an object of the class
            >>> cipher = PlayfairCipher("key")
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
        .. code-block:: python

            # Create an object of the class
            >>> cipher = PlayfairCipher("key")
            # Encrypt the plaintext
            >>> cipher.encrypt("Test Input")
            'QbtpLouksZ'
        """
        def generate_matrix(key):
            matrix = []
            key = key.replace("J", "I")
            for i in key:
                if i not in matrix:
                    matrix.append(i)
            for i in range(65, 91):
                if chr(i) not in matrix and chr(i).upper() != "J":
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
        plaintext = plaintext.replace("j", "i")
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
        .. code-block:: python

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
    .. code-block:: python

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
    """

    def __init__(self, key):
        """
        Parameters
        ------------
        + key: list
            Key for the Hill cipher. It should be a 2x2 matrix.

        Usage
        ------------
        .. code-block:: python

            # Import the class
            >>> from cryptosystems import HillCipher
            # Create an object of the class
            >>> cipher = HillCipher([[3, 3], [2, 5]])
        """
        assert isinstance(key, list) and all(isinstance(row, list) and len(row) == len(key) and all(isinstance(x, int) for x in row) for row in key), "Key should be a square matrix of integers."

        def cofactor(matrix, row, col):
            return ((-1) ** (row + col)) * determinant([row[:col] + row[col + 1:] for row in (matrix[:row] + matrix[row + 1:])])

        def determinant(matrix):
            if len(matrix) == 1:
                return matrix[0][0]
            if len(matrix) == 2:
                return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]
            det = 0
            for col in range(len(matrix)):
                det += matrix[0][col] * cofactor(matrix, 0, col)
            return det
        
        assert determinant(key)%2 != 0 and determinant(key)%13 != 0, "Determinant of the key should be coprime with 26." 
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
        .. code-block:: python

            # Create an object of the class
            >>> cipher = HillCipher([[3, 3], [2, 5]])
            # Encrypt the plaintext
            >>> cipher.encrypt("HelloWorld")
            'HiozeIpjql'
        """
        ciphertext = ""
        if len(plaintext) % len(self.key) != 0:
            plaintext += "X" * (len(self.key) - len(plaintext) % len(self.key))
        for i in range(0, len(plaintext), len(self.key)):
            islower = [plaintext[j].islower() for j in range(i, i + len(self.key))]
            block = [ord(plaintext[j].upper()) - 65 for j in range(i, i + len(self.key))]
            encrypted_block = [(sum(self.key[row][col] * block[col] for col in range(len(self.key))) % 26) for row in range(len(self.key))]
            ciphertext += ''.join(chr(num + 97) if islower[j] else chr(num + 65) for j, num in enumerate(encrypted_block))
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
        .. code-block:: python

            # Create an object of the class
            >>> cipher = HillCipher([[3, 3], [2, 5]])
            # Decrypt the ciphertext
            >>> cipher.decrypt("HiozeIpjql")
            'Hello World'
        """
        def mod_inverse(a, m):
            m0, x0, x1 = m, 0, 1
            if m == 1:
                return 0
            while a > 1:
                q = a // m
                m, a = a % m, m
                x0, x1 = x1 - q * x0, x0
            if x1 < 0:
                x1 += m0
            return x1

        def matrix_mod_inverse(matrix, modulus):
            n = len(matrix)
            adjugate = [[0] * n for _ in range(n)]
            determinant = 0
            for i in range(n):
                determinant += (matrix[0][i] * cofactor(matrix, 0, i))
            determinant = determinant % modulus
            determinant_inv = mod_inverse(determinant, modulus)
            # Calculate the adjugate matrix
            for i in range(n):
                for j in range(n):
                    adjugate[j][i] = (cofactor(matrix, i, j) * determinant_inv) % modulus
            return adjugate

        def cofactor(matrix, row, col):
            sub_matrix = [row[:col] + row[col + 1:] for row in (matrix[:row] + matrix[row + 1:])]
            return ((-1) ** (row + col)) * determinant(sub_matrix)

        def determinant(matrix):
            if len(matrix) == 1:
                return matrix[0][0]
            if len(matrix) == 2:
                return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]
            det = 0
            for col in range(len(matrix)):
                det += matrix[0][col] * cofactor(matrix, 0, col)
            return det

        inv_key = matrix_mod_inverse(self.key, 26)
        plaintext = ""
        for i in range(0, len(ciphertext), len(self.key)):
            islower = [ciphertext[j].islower() for j in range(i, i + len(self.key))]
            block = [ord(ciphertext[j].upper()) - 65 for j in range(i, i + len(self.key))]
            decrypted_block = [(sum(inv_key[row][col] * block[col] for col in range(len(self.key))) % 26) for row in range(len(self.key))]
            plaintext += ''.join(chr(num + 97) if islower[j] else chr(num + 65) for j, num in enumerate(decrypted_block))
        return plaintext
