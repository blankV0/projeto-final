"""
Hash Utilities Module
Provides hashing functions for words using MD5 and MD4 algorithms.

SECURITY WARNING: MD5 and MD4 are cryptographically broken and should NOT be 
used for security-critical applications. They are vulnerable to collision attacks.
This implementation is for educational purposes only.
"""

import hashlib


def hash_word(word, algorithm='md5'):
    """
    Hash a word using the specified algorithm.
    
    Args:
        word: The word to hash
        algorithm: Hashing algorithm to use ('md5' or 'md4')
        
    Returns:
        str: Hexadecimal hash string
        
    Raises:
        ValueError: If unsupported algorithm is specified
    """
    # Convert word to bytes
    word_bytes = word.encode('utf-8')
    
    if algorithm == 'md5':
        # MD5 hashing
        hash_obj = hashlib.md5(word_bytes)
    elif algorithm == 'md4':
        # MD4 hashing (requires OpenSSL support)
        try:
            hash_obj = hashlib.new('md4', word_bytes)
        except ValueError:
            # MD4 might not be available in all Python installations
            raise ValueError(
                "MD4 is not available. This may require OpenSSL with MD4 support. "
                "Try using MD5 instead with --algo md5"
            )
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}. Use 'md5' or 'md4'.")
    
    # Return hexadecimal digest
    return hash_obj.hexdigest()
