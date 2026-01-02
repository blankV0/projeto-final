"""
Hash Utilities Module
Provides hashing functions for words using MD5 and MD4 algorithms.

SECURITY WARNING: MD5 and MD4 are cryptographically broken and should NOT be 
used for security-critical applications. They are vulnerable to collision attacks.
This implementation is for educational purposes only.

Additionally, even with salting, these algorithms remain insecure for password 
storage. In production, use modern algorithms like bcrypt, scrypt, or Argon2.
"""

import hashlib
import os


# Minimum salt length in bytes for security
MIN_SALT_LENGTH = 8


def hash_word(word, algorithm='md5', salt=None):
    """
    Hash a word using the specified algorithm with optional salt.
    
    Args:
        word: The word to hash (must be non-empty string)
        algorithm: Hashing algorithm to use ('md5' or 'md4')
        salt: Optional salt bytes to add before hashing (for educational purposes)
        
    Returns:
        str: Hexadecimal hash string
        
    Raises:
        ValueError: If word is empty, algorithm is unsupported, or MD4 is unavailable
        TypeError: If word is not a string
    """
    # Input validation
    if not isinstance(word, str):
        raise TypeError(f"Word must be a string, got {type(word).__name__}")
    
    if not word or word.strip() == '':
        raise ValueError("Word cannot be empty or whitespace only")
    
    # Convert word to bytes
    word_bytes = word.encode('utf-8')
    
    # Prepend salt if provided (educational demonstration)
    if salt is not None:
        if not isinstance(salt, (bytes, str)):
            raise TypeError(f"Salt must be bytes or string, got {type(salt).__name__}")
        if isinstance(salt, str):
            salt = salt.encode('utf-8')
        word_bytes = salt + word_bytes
    
    # Create hash based on algorithm
    if algorithm == 'md5':
        hash_obj = hashlib.md5(word_bytes)
    elif algorithm == 'md4':
        # MD4 hashing (requires OpenSSL support)
        try:
            hash_obj = hashlib.new('md4', word_bytes)
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


def generate_salt(length=16):
    """
    Generate a random salt for educational purposes.
    
    Args:
        length: Length of salt in bytes (default: 16)
        
    Returns:
        bytes: Random salt
        
    Raises:
        ValueError: If length is less than MIN_SALT_LENGTH
        
    Note:
        In production, use proper key derivation functions (KDF) like PBKDF2,
        bcrypt, scrypt, or Argon2 instead of manual salting with MD5/MD4.
    """
    if length < MIN_SALT_LENGTH:
        raise ValueError(f"Salt length should be at least {MIN_SALT_LENGTH} bytes")
    return os.urandom(length)
