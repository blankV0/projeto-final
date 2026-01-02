"""
Password Generator Module
Generates secure random passwords for the educational password manager.

EDUCATIONAL NOTE: This module demonstrates how to create strong random passwords
using Python's secrets module, which is cryptographically secure. The generated
passwords are strong because they:
1. Use a large character space (uppercase, lowercase, digits, symbols)
2. Have sufficient length (default 12-16 characters)
3. Use cryptographically secure random number generation (not predictable)

For production systems, consider using established password managers like
1Password, LastPass, or Bitwarden which provide additional security features.
"""

import secrets
import string


# Character sets for password generation
UPPERCASE = string.ascii_uppercase  # A-Z
LOWERCASE = string.ascii_lowercase  # a-z
DIGITS = string.digits              # 0-9
SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"  # Special characters


def generate_password(length=16, use_uppercase=True, use_lowercase=True, 
                     use_digits=True, use_symbols=True):
    """
    Generate a cryptographically secure random password.
    
    This function uses Python's secrets module which is designed for generating
    cryptographically strong random numbers suitable for managing secrets such
    as passwords. Unlike random.random(), secrets generates unpredictable values.
    
    Args:
        length: Password length (default: 16, minimum: 8)
        use_uppercase: Include uppercase letters A-Z
        use_lowercase: Include lowercase letters a-z
        use_digits: Include digits 0-9
        use_symbols: Include special characters
        
    Returns:
        str: Generated password
        
    Raises:
        ValueError: If length < 8 or no character sets selected
        
    Educational Note:
        Why these passwords are strong:
        - Length: Longer passwords are exponentially harder to crack
        - Character diversity: More character types = larger keyspace
        - Randomness: Cryptographically secure randomness prevents prediction
        - No patterns: Randomly generated passwords avoid dictionary attacks
        
        Example keyspace calculation:
        - Lowercase only (26 chars): 26^12 = 9.5 x 10^16 combinations
        - All character types (95 chars): 95^12 = 5.4 x 10^23 combinations
    """
    # Input validation
    if length < 8:
        raise ValueError("Password length must be at least 8 characters for security")
    
    # Build character set based on options
    characters = ""
    if use_uppercase:
        characters += UPPERCASE
    if use_lowercase:
        characters += LOWERCASE
    if use_digits:
        characters += DIGITS
    if use_symbols:
        characters += SYMBOLS
    
    if not characters:
        raise ValueError("At least one character set must be enabled")
    
    # Generate password using cryptographically secure random selection
    # secrets.choice() is preferred over random.choice() for security
    password = ''.join(secrets.choice(characters) for _ in range(length))
    
    # Ensure password contains at least one character from each enabled set
    # This prevents edge cases where a password might only contain one type
    has_required = True
    if use_uppercase and not any(c in UPPERCASE for c in password):
        has_required = False
    if use_lowercase and not any(c in LOWERCASE for c in password):
        has_required = False
    if use_digits and not any(c in DIGITS for c in password):
        has_required = False
    if use_symbols and not any(c in SYMBOLS for c in password):
        has_required = False
    
    # Regenerate if requirements not met (rare with sufficient length)
    if not has_required and length >= 4:
        return generate_password(length, use_uppercase, use_lowercase, 
                                use_digits, use_symbols)
    
    return password


def estimate_password_strength(password):
    """
    Estimate password strength based on length and character diversity.
    
    This is a simplified educational demonstration. Real password strength
    estimation should also consider:
    - Dictionary words
    - Common patterns
    - Personal information
    - Previously breached passwords
    
    Args:
        password: Password to evaluate
        
    Returns:
        tuple: (strength_score, description)
        
    Educational Note:
        Password strength is primarily determined by:
        1. Length (most important factor)
        2. Character diversity (uppercase, lowercase, digits, symbols)
        3. Unpredictability (no common patterns or dictionary words)
        
        This function provides a basic assessment for educational purposes.
    """
    if not password:
        return (0, "Empty password")
    
    length = len(password)
    has_upper = any(c in UPPERCASE for c in password)
    has_lower = any(c in LOWERCASE for c in password)
    has_digit = any(c in DIGITS for c in password)
    has_symbol = any(c in SYMBOLS for c in password)
    
    # Count character types
    char_types = sum([has_upper, has_lower, has_digit, has_symbol])
    
    # Calculate basic strength score
    if length < 8:
        return (1, "Very Weak - Too short (< 8 characters)")
    elif length < 12:
        if char_types <= 2:
            return (2, "Weak - Short with limited character types")
        else:
            return (3, "Fair - Decent length but could be longer")
    elif length < 16:
        if char_types <= 2:
            return (3, "Fair - Good length but limited character types")
        else:
            return (4, "Strong - Good length and character diversity")
    else:
        if char_types >= 3:
            return (5, "Very Strong - Excellent length and character diversity")
        else:
            return (4, "Strong - Excellent length, add more character types")


def generate_passphrase(num_words=4, separator="-"):
    """
    Generate a memorable passphrase using random words.
    
    Educational Note:
        Passphrases (like "correct-horse-battery-staple") can be:
        - Easier to remember than random characters
        - Still cryptographically strong with enough words
        - More user-friendly for manual entry
        
        This is a simplified demonstration. Production passphrases should use
        a proper word list (like EFF's diceware list) with at least 7776 words.
    
    Args:
        num_words: Number of words (default: 4, minimum: 3)
        separator: Character between words (default: "-")
        
    Returns:
        str: Generated passphrase
        
    Raises:
        ValueError: If num_words < 3
    """
    if num_words < 3:
        raise ValueError("Passphrase must have at least 3 words")
    
    # Simplified word list for demonstration
    # Production systems should use comprehensive word lists
    word_list = [
        "apple", "bridge", "cloud", "dragon", "eagle", "forest", "galaxy",
        "harbor", "island", "jungle", "knight", "lantern", "mountain", "ninja",
        "ocean", "planet", "quasar", "river", "summit", "tiger", "umbrella",
        "valley", "wizard", "xenon", "yellow", "zebra", "anchor", "beacon",
        "castle", "desert", "empire", "falcon", "garden", "horizon", "iron",
        "jewel", "kingdom", "legend", "marble", "noble", "oracle", "phoenix"
    ]
    
    # Select random words using cryptographically secure random
    selected_words = [secrets.choice(word_list) for _ in range(num_words)]
    
    return separator.join(selected_words)
