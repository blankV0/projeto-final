"""
Test Suite for Password Manager Application

Tests for password_manager.py, security features, and GUI functionality.
Uses pytest framework for comprehensive testing.
"""

import pytest
import os
import tempfile
from hash_utils import (
    hash_password,
    generate_salt,
    secure_compare,
    validate_password_strength,
    get_password_strength_description
)
from database import Database, DatabaseError
from password_generator import generate_password


# ============================================================================
# Security Features Tests
# ============================================================================

class TestSecureCompare:
    """Tests for secure_compare function."""
    
    def test_equal_strings(self):
        """Test that equal strings return True."""
        assert secure_compare("abc123", "abc123") is True
    
    def test_different_strings(self):
        """Test that different strings return False."""
        assert secure_compare("abc123", "def456") is False
    
    def test_equal_hashes(self):
        """Test comparison of equal hashes."""
        hash1 = hash_password("password", "md5")
        hash2 = hash_password("password", "md5")
        assert secure_compare(hash1, hash2) is True
    
    def test_different_hashes(self):
        """Test comparison of different hashes."""
        hash1 = hash_password("password1", "md5")
        hash2 = hash_password("password2", "md5")
        assert secure_compare(hash1, hash2) is False
    
    def test_empty_strings(self):
        """Test with empty strings."""
        assert secure_compare("", "") is False
        assert secure_compare("abc", "") is False
        assert secure_compare("", "abc") is False
    
    def test_none_values(self):
        """Test with None values."""
        assert secure_compare(None, None) is False
        assert secure_compare("abc", None) is False
        assert secure_compare(None, "abc") is False


class TestPasswordStrengthValidation:
    """Tests for password strength validation."""
    
    def test_strong_password(self):
        """Test a strong password."""
        is_valid, errors, score = validate_password_strength("Test123!@#")
        assert is_valid is True
        assert len(errors) == 0
        assert score >= 4
    
    def test_short_password(self):
        """Test password too short."""
        is_valid, errors, score = validate_password_strength("Test1!")
        assert is_valid is False
        assert any("8 characters" in error for error in errors)
    
    def test_no_uppercase(self):
        """Test password without uppercase."""
        is_valid, errors, score = validate_password_strength("test123!")
        assert is_valid is False
        assert any("uppercase" in error.lower() for error in errors)
    
    def test_no_lowercase(self):
        """Test password without lowercase."""
        is_valid, errors, score = validate_password_strength("TEST123!")
        assert is_valid is False
        assert any("lowercase" in error.lower() for error in errors)
    
    def test_no_digits(self):
        """Test password without digits."""
        is_valid, errors, score = validate_password_strength("TestTest!")
        assert is_valid is False
        assert any("digit" in error.lower() for error in errors)
    
    def test_no_symbols(self):
        """Test password without symbols."""
        is_valid, errors, score = validate_password_strength("Test1234")
        assert is_valid is False
        assert any("symbol" in error.lower() for error in errors)
    
    def test_minimum_valid_password(self):
        """Test minimum valid password."""
        is_valid, errors, score = validate_password_strength("Test123!")
        assert is_valid is True
        assert len(errors) == 0
    
    def test_very_strong_password(self):
        """Test very strong password."""
        is_valid, errors, score = validate_password_strength("VeryStr0ng!P@ssw0rd2024")
        assert is_valid is True
        assert score == 5
    
    def test_non_string_input(self):
        """Test with non-string input."""
        is_valid, errors, score = validate_password_strength(123)
        assert is_valid is False
        assert any("string" in error.lower() for error in errors)
    
    def test_password_score_levels(self):
        """Test different password strength levels."""
        # Very weak - doesn't meet requirements
        _, _, score1 = validate_password_strength("test")
        assert score1 <= 1  # Gets 1 point for length < 8
        
        # Good - meets basic requirements
        _, _, score2 = validate_password_strength("Test123!")
        assert score2 >= 3
        
        # Strong - good length and diversity
        _, _, score3 = validate_password_strength("VeryStr0ng!Password")
        assert score3 >= 4


class TestPasswordStrengthDescription:
    """Tests for password strength description."""
    
    def test_all_score_descriptions(self):
        """Test that all scores have descriptions."""
        for score in range(6):
            desc = get_password_strength_description(score)
            assert isinstance(desc, str)
            assert len(desc) > 0
    
    def test_unknown_score(self):
        """Test unknown score."""
        desc = get_password_strength_description(10)
        assert desc == "Unknown"


# ============================================================================
# Integration Tests with Database
# ============================================================================

class TestPasswordManagerIntegration:
    """Integration tests for password manager with new security features."""
    
    @pytest.fixture
    def temp_db(self):
        """Create a temporary database for testing."""
        fd, path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        
        db = Database(path)
        yield db
        
        db.close()
        if os.path.exists(path):
            os.unlink(path)
    
    def test_add_entry_with_unique_salt(self, temp_db):
        """Test adding entries with unique salts."""
        # Add two entries with same password
        password = "Test123!"
        salt1 = generate_salt()
        salt2 = generate_salt()
        
        hash1 = hash_password(password, "md5", salt1)
        hash2 = hash_password(password, "md5", salt2)
        
        # Salts should be different
        assert salt1 != salt2
        # Hashes should be different due to different salts
        assert hash1 != hash2
        
        # Add both entries
        id1 = temp_db.add_entry("Gmail", "user1", hash1, "md5", salt1)
        id2 = temp_db.add_entry("GitHub", "user2", hash2, "md5", salt2)
        
        assert id1 is not None
        assert id2 is not None
    
    def test_verify_password_with_secure_compare(self, temp_db):
        """Test password verification using secure comparison."""
        password = "Test123!"
        salt = generate_salt()
        password_hash = hash_password(password, "md5", salt)
        
        # Add entry
        temp_db.add_entry("Service", "user", password_hash, "md5", salt)
        
        # Retrieve and verify
        entry = temp_db.get_entry("Service", "user")
        assert entry is not None
        
        _, _, _, stored_hash, _, salt_hex, _ = entry
        stored_salt = bytes.fromhex(salt_hex)
        
        # Verify correct password
        test_hash = hash_password(password, "md5", stored_salt)
        assert secure_compare(test_hash, stored_hash) is True
        
        # Verify incorrect password
        wrong_hash = hash_password("WrongPass123!", "md5", stored_salt)
        assert secure_compare(wrong_hash, stored_hash) is False
    
    def test_password_change_workflow(self, temp_db):
        """Test changing a password."""
        service = "TestService"
        username = "testuser"
        old_password = "OldPass123!"
        new_password = "NewPass456!"
        
        # Add initial entry
        salt1 = generate_salt()
        hash1 = hash_password(old_password, "md5", salt1)
        temp_db.add_entry(service, username, hash1, "md5", salt1)
        
        # Simulate password change
        # 1. Verify old password
        entry = temp_db.get_entry(service, username)
        _, _, _, stored_hash, _, salt_hex, _ = entry
        stored_salt = bytes.fromhex(salt_hex)
        current_hash = hash_password(old_password, "md5", stored_salt)
        assert secure_compare(current_hash, stored_hash) is True
        
        # 2. Delete old entry and add new one
        temp_db.delete_entry(service, username)
        salt2 = generate_salt()
        hash2 = hash_password(new_password, "md5", salt2)
        new_id = temp_db.add_entry(service, username, hash2, "md5", salt2)
        assert new_id is not None
        
        # 3. Verify new password works
        entry = temp_db.get_entry(service, username)
        _, _, _, stored_hash, _, salt_hex, _ = entry
        stored_salt = bytes.fromhex(salt_hex)
        new_hash = hash_password(new_password, "md5", stored_salt)
        assert secure_compare(new_hash, stored_hash) is True
        
        # 4. Verify old password doesn't work
        old_hash_test = hash_password(old_password, "md5", stored_salt)
        assert secure_compare(old_hash_test, stored_hash) is False


# ============================================================================
# Password Generation Tests
# ============================================================================

class TestPasswordGeneration:
    """Tests for password generation with strength validation."""
    
    def test_generated_password_meets_requirements(self):
        """Test that generated passwords meet strength requirements."""
        for _ in range(10):  # Test multiple generated passwords
            password = generate_password(length=16)
            is_valid, errors, score = validate_password_strength(password)
            assert is_valid is True
            assert len(errors) == 0
            assert score >= 4
    
    def test_various_lengths(self):
        """Test password generation with various lengths."""
        for length in [8, 12, 16, 24, 32]:
            password = generate_password(length=length)
            is_valid, errors, score = validate_password_strength(password)
            assert is_valid is True
            assert len(password) == length


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
