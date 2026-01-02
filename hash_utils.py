"""
Password Hashing Module
Provides password hashing functions using MD5 and MD4 algorithms.

SECURITY WARNING: MD5 and MD4 are cryptographically broken and should NOT be 
used for security-critical applications. They are vulnerable to collision attacks.
This implementation is for EDUCATIONAL PURPOSES ONLY.

IMPORTANT CONCEPTS FOR UNDERSTANDING:

1. HASHING vs ENCRYPTION:
   - Hashing is ONE-WAY: password -> hash (cannot be reversed)
   - Encryption is TWO-WAY: plaintext <-> ciphertext (can be reversed with key)
   - Password storage MUST use hashing, NOT encryption
   - Why? So even administrators cannot see user passwords

2. Why MD5/MD4 are INSECURE:
   - Fast computation allows billions of hashes per second
   - Collision vulnerabilities (two inputs produce same hash)
   - No built-in salt or iteration count
   - GPU/ASIC hardware can crack quickly

3. What PRODUCTION systems should use:
   - bcrypt: Adaptive, deliberately slow, built-in salt
   - scrypt: Memory-hard, resistant to hardware attacks
   - Argon2: Modern, winner of Password Hashing Competition
   - NEVER use MD5, MD4, SHA-1, or plain SHA-256 for passwords

Additionally, even with salting, these algorithms remain insecure for password 
storage. In production, use modern algorithms like bcrypt, scrypt, or Argon2.
"""

import hashlib
import os


# Minimum salt length in bytes for security
MIN_SALT_LENGTH = 8


def hash_password(password, algorithm='md5', salt=None):
    """
    Hash a password using the specified algorithm with optional salt.
    
    EDUCATIONAL NOTE: This demonstrates the concept of password hashing.
    In a real system:
    - The password should be hashed immediately upon entry
    - The hash is stored in the database
    - The original password is never stored
    - To verify: hash the input and compare with stored hash
    
    This function uses Python's secrets module which is designed for generating
    cryptographically strong random numbers suitable for managing secrets such
    as passwords. Unlike random.random(), secrets generates unpredictable values.
    
    Args:
        password: The password to hash (must be non-empty string)
        algorithm: Hashing algorithm to use ('md5' or 'md4')
        salt: Optional salt bytes to add before hashing (for educational purposes)
        
    Returns:
        str: Hexadecimal hash string
        
    Raises:
        ValueError: If password is empty, algorithm is unsupported, or MD4 is unavailable
        TypeError: If password is not a string
        
    Educational Note:
        Salting prevents rainbow table attacks by ensuring the same password
        produces different hashes for different users. However, even salted
        MD5/MD4 hashes remain vulnerable to brute force attacks.
    """
    # Input validation
    if not isinstance(password, str):
        raise TypeError(f"Password must be a string, got {type(password).__name__}")
    
    if not password or password.strip() == '':
        raise ValueError("Password cannot be empty or whitespace only")
    
    # Convert password to bytes
    password_bytes = password.encode('utf-8')
    
    # Prepend salt if provided (educational demonstration)
    # In production, bcrypt/scrypt handle salting automatically
    if salt is not None:
        if not isinstance(salt, (bytes, str)):
            raise TypeError(f"Salt must be bytes or string, got {type(salt).__name__}")
        if isinstance(salt, str):
            salt = salt.encode('utf-8')
        password_bytes = salt + password_bytes
    
    # Create hash based on algorithm
    if algorithm == 'md5':
        # MD5: Fast but insecure (collision attacks exist since 1996)
        hash_obj = hashlib.md5(password_bytes)
    elif algorithm == 'md4':
        # MD4: Even weaker than MD5 (completely broken)
        # May not be available in all Python installations
        try:
            hash_obj = hashlib.new('md4', password_bytes)
        except ValueError:
            # MD4 might not be available in all Python installations
            raise ValueError(
                "MD4 is not available. This may require OpenSSL with MD4 support. "
                "Try using MD5 instead with --algorithm md5"
            )
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}. Use 'md5' or 'md4'.")
    
    # Return hexadecimal digest
    return hash_obj.hexdigest()


# Keep legacy name for backwards compatibility
hash_word = hash_password


def generate_salt(length=16):
    """
    Generate a random salt for educational purposes.
    
    EDUCATIONAL NOTE: Salts serve several purposes:
    1. Prevent rainbow table attacks (pre-computed hash tables)
    2. Ensure same password produces different hashes for different users
    3. Force attackers to crack each password individually
    
    In this educational implementation, we generate salt manually.
    Production systems (bcrypt, scrypt, Argon2) handle salting automatically.
    
    Args:
        length: Length of salt in bytes (default: 16)
        
    Returns:
        bytes: Random salt
        
    Raises:
        ValueError: If length is less than MIN_SALT_LENGTH
        
    Note:
        This uses os.urandom() which provides cryptographically secure random
        bytes from the operating system's random source (/dev/urandom on Unix).
        
        In production, use proper key derivation functions (KDF) like PBKDF2,
        bcrypt, scrypt, or Argon2 instead of manual salting with MD5/MD4.
    """
    if length < MIN_SALT_LENGTH:
        raise ValueError(f"Salt length should be at least {MIN_SALT_LENGTH} bytes")
    return os.urandom(length)

