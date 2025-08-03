from flask import Flask, request, render_template
import requests

app = Flask(__name__)

blacklist={'127', 'local', '2130706433', '017700000001', '::1', '0.0.0.0', '[::]', 'ffff', '0.0.0.0'}
def isSafe(url):
    return all([i not in url.lower() for i in blacklist])

@app.route('/admin')
def admin():
    if request.remote_addr == '127.0.0.1': return open("flag.txt").read()
    return 'Access denied. Admin panel only accessible from server side.'

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url=request.form['url']
        if not isSafe(url): return 'Access denied. URL parameter included one or more of the following banned keywords: '+', '.join(blacklist)
        try: req = requests.get(url)
        except: return 'Uh-oh... Try again!'
        return render_template('index.html', rt = 'Your page: ' + req.text)
    return render_template('index.html', rt = '')

if __name__ == '__main__':
    app.run()
