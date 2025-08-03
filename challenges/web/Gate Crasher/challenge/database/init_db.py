#!/usr/bin/env python3
"""
Database initialization script for CTF challenge
Creates the SQLite database with necessary tables and sample data
"""

import sqlite3
import os
import hashlib

DATABASE_PATH = 'database/ctf.db'

def create_database():
    """Create the CTF database with required tables and sample data"""
    
    # Remove existing database if it exists
    if os.path.exists(DATABASE_PATH):
        os.remove(DATABASE_PATH)
        print(f"Removed existing database: {DATABASE_PATH}")
    
    # Create database connection
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    try:
        # Create users table
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user'
            )
        ''')
        print("Created users table")
        
        # Create flags table
        cursor.execute('''
            CREATE TABLE flags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flag TEXT NOT NULL,
                description TEXT
            )
        ''')
        print("Created flags table")
        
        # Insert sample users
        sample_users = [
            ('admin', 'super_secret_admin_password', 'admin'),
            ('user1', 'password123', 'user'),
            ('guest', 'guest', 'user'),
            ('test', 'test123', 'user')
        ]
        
        for username, password, role in sample_users:
            cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, password, role)
            )
        print(f"Inserted {len(sample_users)} sample users")
        
        # Insert flag
        flag_value = os.environ.get('FLAG', 'ghctf{SQL_1nj3ct10ns_m4st3r}')
        cursor.execute(
            "INSERT INTO flags (flag, description) VALUES (?, ?)",
            (flag_value, "Main CTF flag for SQL injection challenge")
        )
        print("Inserted flag into database")
        
        # Commit changes
        conn.commit()
        print(f"Database created successfully: {DATABASE_PATH}")
        
        # Display created data for verification
        print("\n--- Database Contents ---")
        cursor.execute("SELECT id, username, role FROM users")
        users = cursor.fetchall()
        print("Users:")
        for user in users:
            print(f"  ID: {user[0]}, Username: {user[1]}, Role: {user[2]}")
        
        cursor.execute("SELECT id, description FROM flags")
        flags = cursor.fetchall()
        print("Flags:")
        for flag in flags:
            print(f"  ID: {flag[0]}, Description: {flag[1]}")
            
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == '__main__':
    print("Initializing CTF database...")
    create_database()
    print("Database initialization complete!")
