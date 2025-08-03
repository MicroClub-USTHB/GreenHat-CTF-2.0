from flask import Flask, render_template, request, redirect, url_for, jsonify
import sqlite3
import string
import random
import os
import socket

ADMIN_HOST = "web-gss-admin"
ADMIN_PORT = 3001

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('urls.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS urls
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  original_url TEXT NOT NULL,
                  short_code TEXT UNIQUE NOT NULL,
                  clicks INTEGER DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

def generate_short_code(length=6):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def get_db_connection():
    # Set a timeout for how long to wait for a lock.
    # This prevents indefinite blocking.
    conn = sqlite3.connect('urls.db', timeout=10) 
    conn.row_factory = sqlite3.Row
    # Enable Write-Ahead Logging (WAL) mode for better concurrency.
    conn.execute('PRAGMA journal_mode=WAL') 
    return conn

@app.route('/', methods=['GET', 'POST'])
def index():
    message = None
    shortened_url = None
    
    if request.method == 'POST':
        original_url = request.form['original_url']

        url = original_url.lower()
        while "script" in url:
            url = url.replace("script", "")
        
        conn = get_db_connection()
        try:
            while True:
                short_code = generate_short_code()
                existing = conn.execute('SELECT id FROM urls WHERE short_code = ?', 
                                      (short_code,)).fetchone()
                if not existing:
                    break
            
            conn.execute('INSERT INTO urls (original_url, short_code) VALUES (?, ?)',
                        (original_url, short_code))
            conn.commit()
            
            shortened_url = request.host_url + short_code
            message = "URL shortened successfully!"
        finally:
            conn.close()
    
    return render_template("index.html", 
                                message=message, 
                                shortened_url=shortened_url)

@app.post('/report')
def report():
    submit_id = request.form["submit_id"]
    submit_id = submit_id.split("/")[-1]
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ADMIN_HOST, ADMIN_PORT))
        s.sendall(submit_id.encode())
        s.close()
        report_message = "Reported successfully."
    except Exception as e:
        print(f"Error reporting URL: {e}")
        report_message = "Failed to report URL."

    return render_template("index.html", 
                                report_message=report_message)

@app.route('/<short_code>')
def redirect_url(short_code):
    conn = get_db_connection()
    try:
        url_data = conn.execute('SELECT original_url FROM urls WHERE short_code = ?', 
                               (short_code,)).fetchone()
        
        if url_data:
            conn.execute('UPDATE urls SET clicks = clicks + 1 WHERE short_code = ?', 
                        (short_code,))
            conn.commit()
            return render_template("redir.html", url=url_data["original_url"]), 200
        else:
            return render_template("not_found.html"), 404
    finally:
        conn.close()

init_db()