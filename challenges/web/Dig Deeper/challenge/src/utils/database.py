import sqlite3
from utils.util import generate_uuid


def get_db_connection():
    """
    Establishes a connection to the SQLite database.
    """
    conn = sqlite3.connect('data/database.db')
    conn.row_factory = sqlite3.Row  
    return conn


def init_db():
    """
    Initializes the database by creating the necessary tables.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            bio TEXT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS articles (
            id TEXT PRIMARY KEY NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author_id TEXT NOT NULL,
            admin_only BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (author_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()


def add_user(first_name, last_name, email, password):
    """
    Adds a new user to the database.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    id = generate_uuid()  
    try:
        cursor.execute(
            'INSERT INTO users (id,first_name, last_name, email, password) VALUES (?, ?, ?, ?, ?)', (id,
                                                                                                     first_name, last_name, email, password),
        )
        conn.commit()
        return True

    except:
        return False
    finally:
        conn.close()


def get_user_by_id(user_id):
    """
    Retrieves a user by ID from the database.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        
        user = cursor.execute(
            'SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

        if user is None:
            return None

        return dict(user)  
    except:
        conn.close()
        return None


def get_user_by_email(email):
    """
    Retrieves a user by email from the database.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        
        user = cursor.execute(
            'SELECT * FROM users WHERE email = ?', (email,)).fetchone()

        if user is None:
            return None

        return dict(user)  
    except:
        conn.close()
        return None


def get_all_users_contacts():
    """
    Retrieves all users contacts from the database.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        
        users = cursor.execute('SELECT id,email FROM users').fetchall()

        

        return [dict(user) for user in users]
    except:
        return None
    finally:
        conn.close()


def update_user_profile(user_id, bio):
    """
    Updates the user's profile information in the database.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            'UPDATE users SET bio = ? WHERE id = ?', (bio, user_id))
        conn.commit()
        return True
    except:
        return False
    finally:
        conn.close()


def create_article(title, content, author_id, admin_only=False):
    """
    Creates a new article in the database.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    id = generate_uuid()  
    try:
        cursor.execute(
            'INSERT INTO articles (id, title, content, author_id,admin_only) VALUES (?, ?, ?, ?, ?)',
            (id, title, content, author_id, admin_only)
        )
        conn.commit()
        return True
    except:
        return False
    finally:
        conn.close()


def get_articles_by_author(author_id):
    """
    Retrieves articles by a specific author from the database.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        
        articles = cursor.execute(
            'SELECT * FROM articles WHERE author_id = ? AND admin_only = 0', (author_id,)).fetchall()
        
        return [dict(article) for article in articles]
    except:
        return None
    finally:
        conn.close()


def get_all_articles():
    """
    Retrieves all articles from the database.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        
        articles = cursor.execute('SELECT * FROM articles').fetchall()

        
        return [dict(article) for article in articles]
    except:
        return None
    finally:
        conn.close()
