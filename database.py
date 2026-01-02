"""
Database Module
Handles all database operations for storing and retrieving hashed words.
Uses SQLite for simplicity and portability.
"""

import sqlite3
import os


class Database:
    """Database handler for word hashes."""
    
    def __init__(self, db_path='words.db'):
        """
        Initialize database connection and create table if not exists.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self._create_table()
    
    def _create_table(self):
        """Create the hashes table if it doesn't exist."""
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS hashes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash TEXT NOT NULL UNIQUE,
                algorithm TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.conn.commit()
    
    def add_hash(self, hash_value, algorithm):
        """
        Add a hash to the database.
        
        Args:
            hash_value: The hash string to store
            algorithm: The algorithm used to generate the hash
            
        Returns:
            bool: True if added successfully, False if already exists
        """
        try:
            self.cursor.execute(
                'INSERT INTO hashes (hash, algorithm) VALUES (?, ?)',
                (hash_value, algorithm)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Hash already exists (UNIQUE constraint violation)
            return False
    
    def hash_exists(self, hash_value):
        """
        Check if a hash exists in the database.
        
        Args:
            hash_value: The hash string to check
            
        Returns:
            bool: True if hash exists, False otherwise
        """
        self.cursor.execute(
            'SELECT COUNT(*) FROM hashes WHERE hash = ?',
            (hash_value,)
        )
        count = self.cursor.fetchone()[0]
        return count > 0
    
    def get_all_hashes(self):
        """
        Retrieve all hashes from the database.
        
        Returns:
            list: List of tuples (id, hash, algorithm)
        """
        self.cursor.execute(
            'SELECT id, hash, algorithm FROM hashes ORDER BY created_at DESC'
        )
        return self.cursor.fetchall()
    
    def close(self):
        """Close the database connection."""
        self.conn.close()
