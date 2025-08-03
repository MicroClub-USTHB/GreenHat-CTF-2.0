from flask import Flask, request, render_template
import sqlite3
import os

app = Flask(__name__)
DATABASE = 'database/ctf.db'
FLAG = os.environ.get('FLAG', 'CTF{EXAMPLE_FLAG}')

@app.route('/', methods=['GET', 'POST'])
def index():
    message = None
    msg_class = 'error'
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Vulnerable SQL query
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute(query)
            user = cursor.fetchone()
            
            if user:
                msg_class = 'success'
                if user[1] == 'admin':
                    # Retrieve flag from database
                    cursor.execute("SELECT flag FROM flags LIMIT 1")
                    flag = cursor.fetchone()[0]
                    message = f"Welcome admin! Flag: {flag}"
                else:
                    message = f"Welcome {user[1]}!"
            else:
                message = "Invalid credentials"
        except sqlite3.Error as e:
            message = f"Database error: {str(e)}"
        finally:
            conn.close()
    
    return render_template('index.html', message=message, msg_class=msg_class)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)