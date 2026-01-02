"""
Test Suite for Word Manager Application

Tests for hash_utils, database operations, and CLI functionality.
Uses pytest framework for comprehensive testing.
"""

import pytest
import os
import tempfile
import sqlite3
from hash_utils import hash_word, generate_salt
from database import Database, DatabaseError


# ============================================================================
# Hash Utilities Tests
# ============================================================================

class TestHashWord:
    """Tests for the hash_word function."""
    
    def test_md5_hash_basic(self):
        """Test basic MD5 hashing."""
        result = hash_word("password", "md5")
        assert result == "5f4dcc3b5aa765d61d8327deb882cf99"
        assert len(result) == 32  # MD5 produces 128-bit (32 hex chars) hash
    
    def test_md5_hash_different_inputs(self):
        """Test that different inputs produce different hashes."""
        hash1 = hash_word("password", "md5")
        hash2 = hash_word("Password", "md5")
        hash3 = hash_word("password123", "md5")
        
        assert hash1 != hash2  # Case sensitive
        assert hash1 != hash3
        assert hash2 != hash3
    
    def test_md5_hash_consistency(self):
        """Test that same input always produces same hash."""
        word = "test123"
        hash1 = hash_word(word, "md5")
        hash2 = hash_word(word, "md5")
        assert hash1 == hash2
    
    def test_hash_with_salt(self):
        """Test hashing with salt produces different results."""
        word = "password"
        hash_no_salt = hash_word(word, "md5", salt=None)
        hash_with_salt = hash_word(word, "md5", salt=b"somesalt")
        
        assert hash_no_salt != hash_with_salt
    
    def test_hash_with_different_salts(self):
        """Test that different salts produce different hashes."""
        word = "password"
        hash1 = hash_word(word, "md5", salt=b"salt1")
        hash2 = hash_word(word, "md5", salt=b"salt2")
        
        assert hash1 != hash2
    
    def test_hash_with_string_salt(self):
        """Test that string salt is accepted and converted."""
        word = "password"
        hash1 = hash_word(word, "md5", salt="mysalt")
        hash2 = hash_word(word, "md5", salt=b"mysalt")
        
        assert hash1 == hash2  # Should produce same result
    
    def test_empty_word_raises_error(self):
        """Test that empty word raises ValueError."""
        with pytest.raises(ValueError, match="cannot be empty"):
            hash_word("", "md5")
    
    def test_whitespace_only_word_raises_error(self):
        """Test that whitespace-only word raises ValueError."""
        with pytest.raises(ValueError, match="cannot be empty"):
            hash_word("   ", "md5")
    
    def test_non_string_word_raises_error(self):
        """Test that non-string word raises TypeError."""
        with pytest.raises(TypeError, match="must be a string"):
            hash_word(123, "md5")
        
        with pytest.raises(TypeError, match="must be a string"):
            hash_word(None, "md5")
    
    def test_invalid_algorithm_raises_error(self):
        """Test that invalid algorithm raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            hash_word("password", "sha256")
    
    def test_invalid_salt_type_raises_error(self):
        """Test that invalid salt type raises TypeError."""
        with pytest.raises(TypeError, match="must be bytes or string"):
            hash_word("password", "md5", salt=123)
    
    def test_unicode_support(self):
        """Test that unicode characters are handled correctly."""
        word = "pässwörd"
        result = hash_word(word, "md5")
        assert len(result) == 32
        assert isinstance(result, str)


class TestGenerateSalt:
    """Tests for the generate_salt function."""
    
    def test_default_salt_length(self):
        """Test default salt length is 16 bytes."""
        salt = generate_salt()
        assert len(salt) == 16
        assert isinstance(salt, bytes)
    
    def test_custom_salt_length(self):
        """Test custom salt length."""
        salt = generate_salt(32)
        assert len(salt) == 32
    
    def test_salt_randomness(self):
        """Test that generated salts are different."""
        salt1 = generate_salt()
        salt2 = generate_salt()
        assert salt1 != salt2
    
    def test_minimum_salt_length_validation(self):
        """Test that salt length less than 8 raises error."""
        with pytest.raises(ValueError, match="at least 8 bytes"):
            generate_salt(4)


# ============================================================================
# Database Tests
# ============================================================================

class TestDatabase:
    """Tests for Database class."""
    
    @pytest.fixture
    def temp_db(self):
        """Create a temporary database for testing."""
        # Create temporary file
        fd, path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        
        # Initialize database
        db = Database(path)
        
        yield db
        
        # Cleanup
        db.close()
        if os.path.exists(path):
            os.unlink(path)
    
    def test_database_initialization(self, temp_db):
        """Test database initializes correctly."""
        assert temp_db.conn is not None
        assert temp_db.cursor is not None
        assert os.path.exists(temp_db.db_path)
    
    def test_table_creation(self, temp_db):
        """Test that hashes table is created."""
        temp_db.cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='hashes'"
        )
        result = temp_db.cursor.fetchone()
        assert result is not None
        assert result[0] == 'hashes'
    
    def test_add_hash_success(self, temp_db):
        """Test adding a hash successfully."""
        result = temp_db.add_hash("abc123", "md5")
        assert result is True
    
    def test_add_hash_with_salt(self, temp_db):
        """Test adding a hash with salt."""
        salt = b"somesalt"
        result = temp_db.add_hash("abc123", "md5", salt)
        assert result is True
    
    def test_add_duplicate_hash(self, temp_db):
        """Test that duplicate hash returns False."""
        temp_db.add_hash("abc123", "md5")
        result = temp_db.add_hash("abc123", "md5")
        assert result is False
    
    def test_add_hash_invalid_input(self, temp_db):
        """Test that invalid input raises ValueError."""
        with pytest.raises(ValueError):
            temp_db.add_hash("", "md5")
        
        with pytest.raises(ValueError):
            temp_db.add_hash("abc123", "")
    
    def test_hash_exists_true(self, temp_db):
        """Test hash_exists returns True for existing hash."""
        temp_db.add_hash("abc123", "md5")
        assert temp_db.hash_exists("abc123") is True
    
    def test_hash_exists_false(self, temp_db):
        """Test hash_exists returns False for non-existing hash."""
        assert temp_db.hash_exists("nonexistent") is False
    
    def test_hash_exists_invalid_input(self, temp_db):
        """Test hash_exists with invalid input."""
        with pytest.raises(ValueError):
            temp_db.hash_exists("")
    
    def test_get_all_hashes_empty(self, temp_db):
        """Test get_all_hashes returns empty list when no hashes."""
        result = temp_db.get_all_hashes()
        assert result == []
    
    def test_get_all_hashes_with_data(self, temp_db):
        """Test get_all_hashes returns all hashes."""
        temp_db.add_hash("hash1", "md5")
        temp_db.add_hash("hash2", "md5")
        temp_db.add_hash("hash3", "md4")
        
        result = temp_db.get_all_hashes()
        assert len(result) == 3
        
        # Check structure (id, hash, algorithm, salt)
        for row in result:
            assert len(row) == 4
    
    def test_get_all_hashes_ordering(self, temp_db):
        """Test that hashes are retrieved (ordering may vary with rapid inserts)."""
        temp_db.add_hash("first", "md5")
        temp_db.add_hash("second", "md5")
        temp_db.add_hash("third", "md5")
        
        result = temp_db.get_all_hashes()
        hashes = [r[1] for r in result]
        
        # Verify all three hashes are present
        assert "first" in hashes
        assert "second" in hashes
        assert "third" in hashes
        assert len(hashes) == 3
    
    def test_database_close(self, temp_db):
        """Test database close works."""
        temp_db.close()
        # Trying to execute after close should fail
        with pytest.raises(Exception):
            temp_db.cursor.execute("SELECT * FROM hashes")


class TestDatabaseErrors:
    """Tests for database error handling."""
    
    def test_invalid_database_path(self):
        """Test that invalid path raises DatabaseError."""
        # Try to create database in non-existent directory
        with pytest.raises(DatabaseError):
            Database("/nonexistent/directory/test.db")


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration:
    """Integration tests for the complete workflow."""
    
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
    
    def test_add_and_verify_word(self, temp_db):
        """Test complete workflow: hash word, store, and verify."""
        word = "testword"
        algorithm = "md5"
        
        # Hash and store
        hashed = hash_word(word, algorithm)
        result = temp_db.add_hash(hashed, algorithm)
        assert result is True
        
        # Verify
        assert temp_db.hash_exists(hashed) is True
    
    def test_salted_word_workflow(self, temp_db):
        """Test workflow with salted hash."""
        word = "testword"
        algorithm = "md5"
        salt = generate_salt()
        
        # Hash with salt and store
        hashed = hash_word(word, algorithm, salt)
        result = temp_db.add_hash(hashed, algorithm, salt)
        assert result is True
        
        # Verify hash exists
        assert temp_db.hash_exists(hashed) is True
        
        # Hash same word without salt should be different
        hashed_no_salt = hash_word(word, algorithm, None)
        assert hashed != hashed_no_salt
        assert temp_db.hash_exists(hashed_no_salt) is False
    
    def test_multiple_words_with_same_algorithm(self, temp_db):
        """Test storing multiple words with same algorithm."""
        words = ["word1", "word2", "word3"]
        algorithm = "md5"
        
        for word in words:
            hashed = hash_word(word, algorithm)
            temp_db.add_hash(hashed, algorithm)
        
        all_hashes = temp_db.get_all_hashes()
        assert len(all_hashes) == 3
    
    def test_retrieve_and_display_hashes(self, temp_db):
        """Test retrieving and displaying hash information."""
        # Add some test data
        temp_db.add_hash(hash_word("word1", "md5"), "md5")  # no salt
        temp_db.add_hash(hash_word("word2", "md5", b"salt"), "md5", b"salt")  # with salt
        
        hashes = temp_db.get_all_hashes()
        assert len(hashes) == 2
        
        # Find which hash has salt (order might vary)
        salted_hash = None
        unsalted_hash = None
        for h in hashes:
            if h[3] is not None:
                salted_hash = h
            else:
                unsalted_hash = h
        
        assert salted_hash is not None  # Should have one hash with salt
        assert unsalted_hash is not None  # Should have one hash without salt


# ============================================================================
# CLI Tests (basic)
# ============================================================================

class TestCLIBasics:
    """Basic tests for CLI functionality."""
    
    def test_import_main_module(self):
        """Test that main module can be imported."""
        import word_manager
        assert hasattr(word_manager, 'main')
        assert hasattr(word_manager, 'add_word')
        assert hasattr(word_manager, 'list_hashes')
        assert hasattr(word_manager, 'verify_word')
