const express = require('express');
const path = require('path');
const fs = require('fs');
const app = express();

app.use((req, res, next) => {
    if (req.path.includes('/admin')) {
        return res.status(403).json({ error: 'Access denied to admin area' });
    }
    next();
});

app.use('/static', express.static('/var/www/public'));

app.get('/api/status', (req, res) => {
    res.json({ status: 'Server is running', timestamp: new Date() });
});

app.get('/api/files', (req, res) => {
    const filename = req.query.file;
    if (!filename) {
        return res.json({ error: 'No file specified' });
    }
    
    if (filename.includes('..') || filename.includes('admin')) {
        return res.json({ error: 'Invalid file path' });
    }
    
    try {
        const filePath = path.join('/var/www/files', filename);
        const content = fs.readFileSync(filePath, 'utf8');
        res.json({ content: content });
    } catch (err) {
        res.json({ error: 'File not found' });
    }
});

app.get('/debug/info', (req, res) => {
    const realIP = req.headers['x-real-ip'];
    if (realIP !== '127.0.0.1') {
        return res.status(403).json({ error: 'Debug access denied' });
    }
    
    res.json({
        message: 'Debug info',
        headers: req.headers,
        path: req.path,
        originalUrl: req.originalUrl,
        hint: 'Try exploring the file system structure'
    });
});

app.get('/list', (req, res) => {
    const dir = req.query.dir || '/var/www/public';
    if (dir.includes('admin')) {
        return res.json({ error: 'Access denied' });
    }
    
    try {
        const files = fs.readdirSync(dir);
        res.json({ directory: dir, files: files });
    } catch (err) {
        res.json({ error: 'Directory not found' });
    }
});

app.get('/', (req, res) => {
    res.send(`
        <h1>Secure File Server</h1>
        <p>Available endpoints:</p>
        <ul>
            <li><a href="/api/status">API Status</a></li>
            <li><a href="/api/files?file=backup.sql">View Files</a></li>
            <li><a href="/list">List Files</a></li>
            <li><a href="/public/">Public Files</a></li>
        </ul>
        <p>Admin area is protected!</p>
    `);
});

app.listen(3000, '127.0.0.1', () => {
    console.log('Express server running on port 3000');
});