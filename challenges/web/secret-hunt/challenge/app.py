#!/usr/bin/env python3
from flask import Flask, request, jsonify, render_template_string
import os
import requests
import subprocess
import base64

app = Flask(__name__)

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>FileShare Pro - Document Management</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .api-section { background: #f5f5f5; padding: 20px; margin: 20px 0; border-radius: 5px; }
        input[type="text"] { width: 300px; padding: 8px; margin: 5px; }
        button { padding: 10px 15px; background: #007bff; color: white; border: none; border-radius: 3px; cursor: pointer; }
        .result { background: #e9ecef; padding: 15px; margin: 10px 0; border-radius: 3px; white-space: pre-wrap; }
    </style>
</head>
<body>
    <div class="container">
        <h1>FileShare Pro v2.1</h1>
        <p>Enterprise Document Management System</p>
        
        <div class="api-section">
            <h3>📁 File Viewer</h3>
            <p>View system files and documents</p>
            <input type="text" id="filepath" placeholder="Enter file path (e.g., /app/docs/readme.txt)">
            <button onclick="viewFile()">View File</button>
            <div id="fileResult" class="result" style="display:none;"></div>
        </div>

        <div class="api-section">
            <h3>🌐 Health Check Proxy</h3>
            <p>Check if internal services are running</p>
            <input type="text" id="healthUrl" placeholder="Enter service URL (e.g., http://api-service:8080/health)">
            <button onclick="checkHealth()">Check Service</button>
            <div id="healthResult" class="result" style="display:none;"></div>
        </div>

        <div class="api-section">
            <h3>🔧 System Info</h3>
            <button onclick="getSystemInfo()">Get System Information</button>
            <div id="systemResult" class="result" style="display:none;"></div>
        </div>
    </div>

    <script>
        function viewFile() {
            const filepath = document.getElementById('filepath').value;
            fetch('/api/file', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({path: filepath})
            })
            .then(r => r.json())
            .then(data => {
                document.getElementById('fileResult').style.display = 'block';
                document.getElementById('fileResult').textContent = JSON.stringify(data, null, 2);
            });
        }

        function checkHealth() {
            const url = document.getElementById('healthUrl').value;
            fetch('/api/health', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({url: url})
            })
            .then(r => r.json())
            .then(data => {
                document.getElementById('healthResult').style.display = 'block';
                document.getElementById('healthResult').textContent = JSON.stringify(data, null, 2);
            });
        }

        function getSystemInfo() {
            fetch('/api/system')
            .then(r => r.json())
            .then(data => {
                document.getElementById('systemResult').style.display = 'block';
                document.getElementById('systemResult').textContent = JSON.stringify(data, null, 2);
            });
        }
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    return HTML_TEMPLATE

@app.route('/api/file', methods=['POST'])
def read_file():
    """Vulnerable file reading endpoint - Path Traversal"""
    try:
        data = request.get_json()
        filepath = data.get('path', '')
        
        # Vulnerable: No path sanitization
        if not filepath:
            return jsonify({"error": "Path parameter required"}), 400
            
        # Read file content
        with open(filepath, 'r') as f:
            content = f.read()
            
        return jsonify({
            "status": "success",
            "path": filepath,
            "content": content
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/api/health', methods=['POST'])
def health_check():
    """Vulnerable SSRF endpoint"""
    try:
        data = request.get_json()
        url = data.get('url', '')
        
        if not url:
            return jsonify({"error": "URL parameter required"}), 400
        
        # Vulnerable: No URL validation - SSRF possible
        response = requests.get(url, timeout=5)
        
        return jsonify({
            "status": "success",
            "url": url,
            "status_code": response.status_code,
            "response": response.text[:1000]  # Limit response size
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/api/system', methods=['GET'])
def system_info():
    """System information endpoint"""
    try:
        info = {
            "hostname": os.environ.get('HOSTNAME', 'unknown'),
            "user": os.environ.get('USER', 'unknown'),
            "pwd": os.getcwd(),
            "env_vars": {k: v for k, v in os.environ.items() if not k.startswith('KUBERNETES')},
            "mounted_volumes": []
        }
        
        try:
            with open('/proc/mounts', 'r') as f:
                mounts = f.read()
                info["mounts"] = mounts.split('\n')[:10]  
        except:
            pass
            
        return jsonify(info)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)