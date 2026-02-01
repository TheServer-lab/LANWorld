#!/usr/bin/env python3
"""
LAN World - A Complete Internet Experience on Your Local Network
Run this script to create a self-contained social network on your LAN
"""

import os
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from functools import wraps

from flask import Flask, request, jsonify, send_from_directory, session, render_template_string
from werkzeug.utils import secure_filename
import sqlite3

# Configuration
BASE_DIR = Path(__file__).parent / 'lanworld_data'
UPLOAD_FOLDER = BASE_DIR / 'uploads'
DATABASE = BASE_DIR / 'lanworld.db'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mp3', 'pdf', 'txt', 'zip', 'doc', 'docx'}

# Create necessary directories
BASE_DIR.mkdir(exist_ok=True)
UPLOAD_FOLDER.mkdir(exist_ok=True)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = str(UPLOAD_FOLDER)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size

# Database initialization
def init_db():
    """Initialize the database with all necessary tables"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT,
        bio TEXT,
        avatar TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Posts table (Twitter/X style)
    c.execute('''CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        media_url TEXT,
        likes INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Forums table (Reddit style)
    c.execute('''CREATE TABLE IF NOT EXISTS forums (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        category TEXT,
        likes INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Forum comments
    c.execute('''CREATE TABLE IF NOT EXISTS forum_comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        forum_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (forum_id) REFERENCES forums (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Chat messages
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        recipient_id INTEGER,
        channel_name TEXT,
        content TEXT NOT NULL,
        is_dm BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (sender_id) REFERENCES users (id),
        FOREIGN KEY (recipient_id) REFERENCES users (id)
    )''')
    
    # Files table
    c.execute('''CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        original_filename TEXT NOT NULL,
        file_type TEXT,
        file_size INTEGER,
        description TEXT,
        downloads INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Media library (videos and music)
    c.execute('''CREATE TABLE IF NOT EXISTS media (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        filename TEXT NOT NULL,
        media_type TEXT NOT NULL,
        duration INTEGER,
        views INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Likes tracking
    c.execute('''CREATE TABLE IF NOT EXISTS likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        item_type TEXT NOT NULL,
        item_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        UNIQUE(user_id, item_type, item_id)
    )''')
    
    conn.commit()
    conn.close()

# Helper functions
def hash_password(password):
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Authentication routes
@app.route('/')
def index():
    """Serve the main application"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/signup', methods=['POST'])
def signup():
    """Register a new user"""
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    email = data.get('email', '').strip()
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    if len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400
    
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    try:
        c.execute('INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
                  (username, hash_password(password), email))
        conn.commit()
        user_id = c.lastrowid
        session['user_id'] = user_id
        session['username'] = username
        return jsonify({'success': True, 'user_id': user_id, 'username': username})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 400
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    """Login a user"""
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id, username, password_hash FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    
    if user and user['password_hash'] == hash_password(password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        return jsonify({'success': True, 'user_id': user['id'], 'username': user['username']})
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    """Logout current user"""
    session.clear()
    return jsonify({'success': True})

@app.route('/api/me')
@login_required
def get_current_user():
    """Get current user info"""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id, username, email, bio, avatar FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()
    conn.close()
    
    if user:
        return jsonify(dict(user))
    return jsonify({'error': 'User not found'}), 404

# Posts (Twitter/X style)
@app.route('/api/posts', methods=['GET', 'POST'])
@login_required
def posts():
    """Get all posts or create a new post"""
    if request.method == 'POST':
        data = request.json
        content = data.get('content', '').strip()
        media_url = data.get('media_url')
        
        if not content:
            return jsonify({'error': 'Content required'}), 400
        
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO posts (user_id, content, media_url) VALUES (?, ?, ?)',
                  (session['user_id'], content, media_url))
        conn.commit()
        post_id = c.lastrowid
        conn.close()
        
        return jsonify({'success': True, 'post_id': post_id})
    
    # GET request
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT posts.*, users.username, users.avatar 
                 FROM posts 
                 JOIN users ON posts.user_id = users.id 
                 ORDER BY posts.created_at DESC LIMIT 100''')
    posts = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify(posts)

@app.route('/api/posts/<int:post_id>/like', methods=['POST'])
@login_required
def like_post(post_id):
    """Like or unlike a post"""
    conn = get_db()
    c = conn.cursor()
    
    # Check if already liked
    c.execute('SELECT id FROM likes WHERE user_id = ? AND item_type = ? AND item_id = ?',
              (session['user_id'], 'post', post_id))
    existing_like = c.fetchone()
    
    if existing_like:
        # Unlike
        c.execute('DELETE FROM likes WHERE id = ?', (existing_like['id'],))
        c.execute('UPDATE posts SET likes = likes - 1 WHERE id = ?', (post_id,))
        action = 'unliked'
    else:
        # Like
        c.execute('INSERT INTO likes (user_id, item_type, item_id) VALUES (?, ?, ?)',
                  (session['user_id'], 'post', post_id))
        c.execute('UPDATE posts SET likes = likes + 1 WHERE id = ?', (post_id,))
        action = 'liked'
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'action': action})

# Forums (Reddit style)
@app.route('/api/forums', methods=['GET', 'POST'])
@login_required
def forums():
    """Get all forum posts or create a new one"""
    if request.method == 'POST':
        data = request.json
        title = data.get('title', '').strip()
        content = data.get('content', '').strip()
        category = data.get('category', 'General')
        
        if not title or not content:
            return jsonify({'error': 'Title and content required'}), 400
        
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO forums (user_id, title, content, category) VALUES (?, ?, ?, ?)',
                  (session['user_id'], title, content, category))
        conn.commit()
        forum_id = c.lastrowid
        conn.close()
        
        return jsonify({'success': True, 'forum_id': forum_id})
    
    # GET request
    category = request.args.get('category')
    conn = get_db()
    c = conn.cursor()
    
    if category:
        c.execute('''SELECT forums.*, users.username, 
                     (SELECT COUNT(*) FROM forum_comments WHERE forum_id = forums.id) as comment_count
                     FROM forums 
                     JOIN users ON forums.user_id = users.id 
                     WHERE forums.category = ?
                     ORDER BY forums.created_at DESC LIMIT 100''', (category,))
    else:
        c.execute('''SELECT forums.*, users.username,
                     (SELECT COUNT(*) FROM forum_comments WHERE forum_id = forums.id) as comment_count
                     FROM forums 
                     JOIN users ON forums.user_id = users.id 
                     ORDER BY forums.created_at DESC LIMIT 100''')
    
    forums = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify(forums)

@app.route('/api/forums/<int:forum_id>')
@login_required
def get_forum(forum_id):
    """Get a specific forum post with comments"""
    conn = get_db()
    c = conn.cursor()
    
    c.execute('''SELECT forums.*, users.username 
                 FROM forums 
                 JOIN users ON forums.user_id = users.id 
                 WHERE forums.id = ?''', (forum_id,))
    forum = c.fetchone()
    
    if not forum:
        conn.close()
        return jsonify({'error': 'Forum not found'}), 404
    
    c.execute('''SELECT forum_comments.*, users.username 
                 FROM forum_comments 
                 JOIN users ON forum_comments.user_id = users.id 
                 WHERE forum_comments.forum_id = ?
                 ORDER BY forum_comments.created_at ASC''', (forum_id,))
    comments = [dict(row) for row in c.fetchall()]
    conn.close()
    
    result = dict(forum)
    result['comments'] = comments
    return jsonify(result)

@app.route('/api/forums/<int:forum_id>/comments', methods=['POST'])
@login_required
def add_forum_comment(forum_id):
    """Add a comment to a forum post"""
    data = request.json
    content = data.get('content', '').strip()
    
    if not content:
        return jsonify({'error': 'Content required'}), 400
    
    conn = get_db()
    c = conn.cursor()
    c.execute('INSERT INTO forum_comments (forum_id, user_id, content) VALUES (?, ?, ?)',
              (forum_id, session['user_id'], content))
    conn.commit()
    comment_id = c.lastrowid
    conn.close()
    
    return jsonify({'success': True, 'comment_id': comment_id})

# Chat (Discord style)
@app.route('/api/messages', methods=['GET', 'POST'])
@login_required
def messages():
    """Get messages or send a new message"""
    if request.method == 'POST':
        data = request.json
        content = data.get('content', '').strip()
        recipient_id = data.get('recipient_id')
        channel_name = data.get('channel_name', 'general')
        is_dm = data.get('is_dm', False)
        
        if not content:
            return jsonify({'error': 'Content required'}), 400
        
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO messages (sender_id, recipient_id, channel_name, content, is_dm) VALUES (?, ?, ?, ?, ?)',
                  (session['user_id'], recipient_id, channel_name, content, is_dm))
        conn.commit()
        message_id = c.lastrowid
        conn.close()
        
        return jsonify({'success': True, 'message_id': message_id})
    
    # GET request
    is_dm = request.args.get('is_dm', 'false').lower() == 'true'
    channel_name = request.args.get('channel', 'general')
    recipient_id = request.args.get('recipient_id')
    
    conn = get_db()
    c = conn.cursor()
    
    if is_dm and recipient_id:
        # Get DMs between current user and recipient
        c.execute('''SELECT messages.*, users.username as sender_username
                     FROM messages 
                     JOIN users ON messages.sender_id = users.id 
                     WHERE messages.is_dm = 1 AND (
                         (messages.sender_id = ? AND messages.recipient_id = ?) OR
                         (messages.sender_id = ? AND messages.recipient_id = ?)
                     )
                     ORDER BY messages.created_at ASC LIMIT 100''',
                  (session['user_id'], recipient_id, recipient_id, session['user_id']))
    else:
        # Get channel messages
        c.execute('''SELECT messages.*, users.username as sender_username
                     FROM messages 
                     JOIN users ON messages.sender_id = users.id 
                     WHERE messages.is_dm = 0 AND messages.channel_name = ?
                     ORDER BY messages.created_at DESC LIMIT 100''', (channel_name,))
    
    messages = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify(messages[::-1])  # Reverse for chronological order

@app.route('/api/users')
@login_required
def get_users():
    """Get all users for DM list"""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id, username, avatar, bio FROM users WHERE id != ? ORDER BY username', 
              (session['user_id'],))
    users = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(users)

# File sharing
@app.route('/api/files', methods=['GET', 'POST'])
@login_required
def files():
    """Upload or list files"""
    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        description = request.form.get('description', '')
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if file and allowed_file(file.filename):
            original_filename = secure_filename(file.filename)
            filename = f"{secrets.token_hex(8)}_{original_filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            file_size = os.path.getsize(filepath)
            file_type = original_filename.rsplit('.', 1)[1].lower()
            
            conn = get_db()
            c = conn.cursor()
            c.execute('''INSERT INTO files (user_id, filename, original_filename, file_type, file_size, description) 
                         VALUES (?, ?, ?, ?, ?, ?)''',
                      (session['user_id'], filename, original_filename, file_type, file_size, description))
            conn.commit()
            file_id = c.lastrowid
            conn.close()
            
            return jsonify({'success': True, 'file_id': file_id, 'filename': filename})
        
        return jsonify({'error': 'File type not allowed'}), 400
    
    # GET request
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT files.*, users.username 
                 FROM files 
                 JOIN users ON files.user_id = users.id 
                 ORDER BY files.created_at DESC LIMIT 100''')
    files = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify(files)

@app.route('/api/files/<int:file_id>/download')
@login_required
def download_file(file_id):
    """Download a file"""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT filename, original_filename FROM files WHERE id = ?', (file_id,))
    file = c.fetchone()
    
    if file:
        c.execute('UPDATE files SET downloads = downloads + 1 WHERE id = ?', (file_id,))
        conn.commit()
        conn.close()
        return send_from_directory(app.config['UPLOAD_FOLDER'], file['filename'], 
                                    as_attachment=True, download_name=file['original_filename'])
    
    conn.close()
    return jsonify({'error': 'File not found'}), 404

# Media streaming
@app.route('/api/media', methods=['GET', 'POST'])
@login_required
def media():
    """Upload or list media (videos/music)"""
    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        title = request.form.get('title', file.filename)
        media_type = request.form.get('media_type', 'video')
        
        if file.filename == '' :
            return jsonify({'error': 'No file selected'}), 400
        
        if file and allowed_file(file.filename):
            original_filename = secure_filename(file.filename)
            filename = f"{secrets.token_hex(8)}_{original_filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            conn = get_db()
            c = conn.cursor()
            c.execute('''INSERT INTO media (user_id, title, filename, media_type) 
                         VALUES (?, ?, ?, ?)''',
                      (session['user_id'], title, filename, media_type))
            conn.commit()
            media_id = c.lastrowid
            conn.close()
            
            return jsonify({'success': True, 'media_id': media_id, 'filename': filename})
        
        return jsonify({'error': 'File type not allowed'}), 400
    
    # GET request
    media_type = request.args.get('type', 'video')
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT media.*, users.username 
                 FROM media 
                 JOIN users ON media.user_id = users.id 
                 WHERE media.media_type = ?
                 ORDER BY media.created_at DESC LIMIT 100''', (media_type,))
    media_list = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify(media_list)

@app.route('/api/media/<int:media_id>/stream')
@login_required
def stream_media(media_id):
    """Stream a media file"""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT filename FROM media WHERE id = ?', (media_id,))
    media = c.fetchone()
    
    if media:
        c.execute('UPDATE media SET views = views + 1 WHERE id = ?', (media_id,))
        conn.commit()
        conn.close()
        return send_from_directory(app.config['UPLOAD_FOLDER'], media['filename'])
    
    conn.close()
    return jsonify({'error': 'Media not found'}), 404

# HTML Template
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <title>LAN World - Your Local Internet</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        
        .auth-container {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            min-height: -webkit-fill-available;
            padding: 20px;
        }
        
        .auth-box {
            background: white;
            padding: 30px;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 400px;
            width: 100%;
        }
        
        @media (max-width: 768px) {
            .auth-box {
                padding: 25px;
                border-radius: 15px;
            }
        }
        
        .auth-box h1 {
            color: #667eea;
            margin-bottom: 10px;
            font-size: 32px;
        }
        
        .auth-box p {
            color: #666;
            margin-bottom: 30px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: #333;
            font-weight: 500;
        }
        
        .form-group input {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .btn {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
        
        .btn:active {
            transform: translateY(0);
        }
        
        .switch-auth {
            text-align: center;
            margin-top: 20px;
            color: #666;
        }
        
        .switch-auth a {
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
        }
        
        .error {
            background: #fee;
            color: #c33;
            padding: 10px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: none;
        }
        
        /* Main App Styles */
        .app-container {
            display: none;
            height: 100vh;
            height: -webkit-fill-available;
            background: #f5f5f5;
            flex-direction: column;
        }
        
        .app-header {
            background: white;
            padding: 15px 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-shrink: 0;
        }
        
        .app-header h1 {
            color: #667eea;
            font-size: 20px;
        }
        
        @media (max-width: 768px) {
            .app-header h1 {
                font-size: 18px;
            }
        }
        
        .user-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .logout-btn {
            padding: 8px 20px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 500;
        }
        
        .app-main {
            display: flex;
            height: calc(100vh - 70px);
            height: calc(-webkit-fill-available - 70px);
            flex: 1;
            overflow: hidden;
        }
        
        .mobile-menu-btn {
            display: none;
            position: fixed;
            bottom: 20px;
            right: 20px;
            width: 56px;
            height: 56px;
            border-radius: 50%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            font-size: 24px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            z-index: 1000;
            cursor: pointer;
        }
        
        .sidebar {
            width: 250px;
            background: white;
            padding: 20px;
            box-shadow: 2px 0 10px rgba(0,0,0,0.05);
            overflow-y: auto;
            flex-shrink: 0;
            transition: transform 0.3s ease;
        }
        
        @media (max-width: 768px) {
            .mobile-menu-btn {
                display: block;
            }
            
            .sidebar {
                position: fixed;
                left: 0;
                top: 70px;
                bottom: 0;
                z-index: 999;
                transform: translateX(-100%);
                box-shadow: 2px 0 10px rgba(0,0,0,0.2);
            }
            
            .sidebar.open {
                transform: translateX(0);
            }
            
            .sidebar-overlay {
                display: none;
                position: fixed;
                top: 70px;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(0,0,0,0.5);
                z-index: 998;
            }
            
            .sidebar-overlay.show {
                display: block;
            }
        }
        
        .nav-item {
            padding: 12px 15px;
            margin-bottom: 5px;
            border-radius: 8px;
            cursor: pointer;
            transition: background 0.2s;
            font-weight: 500;
            color: #333;
        }
        
        .nav-item:hover {
            background: #f0f0f0;
        }
        
        .nav-item.active {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .content {
            flex: 1;
            padding: 20px;
            overflow-y: auto;
            -webkit-overflow-scrolling: touch;
        }
        
        @media (max-width: 768px) {
            .content {
                padding: 15px;
                width: 100%;
            }
        }
        
        .panel {
            display: none;
        }
        
        .panel.active {
            display: block;
        }
        
        .card {
            background: white;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            margin-bottom: 20px;
        }
        
        .post-input, .forum-input, .message-input {
            width: 100%;
            padding: 15px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 14px;
            resize: vertical;
            min-height: 100px;
            font-family: inherit;
        }
        
        .post-btn, .submit-btn {
            padding: 10px 30px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 500;
            margin-top: 10px;
        }
        
        .post {
            background: white;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 15px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }
        
        .post-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
        }
        
        .post-author {
            font-weight: 600;
            color: #333;
        }
        
        .post-time {
            color: #999;
            font-size: 12px;
        }
        
        .post-content {
            color: #333;
            line-height: 1.6;
            margin-bottom: 10px;
        }
        
        .post-actions {
            display: flex;
            gap: 15px;
            color: #666;
            font-size: 14px;
        }
        
        .like-btn {
            cursor: pointer;
            transition: color 0.2s;
        }
        
        .like-btn:hover {
            color: #667eea;
        }
        
        .message {
            padding: 10px 15px;
            background: #f5f5f5;
            border-radius: 8px;
            margin-bottom: 10px;
        }
        
        .message-sender {
            font-weight: 600;
            color: #667eea;
            font-size: 13px;
        }
        
        .message-content {
            color: #333;
            margin-top: 5px;
        }
        
        .file-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px;
            background: white;
            border-radius: 8px;
            margin-bottom: 10px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }
        
        .file-info h4 {
            color: #333;
            margin-bottom: 5px;
        }
        
        .file-meta {
            color: #999;
            font-size: 12px;
        }
        
        .download-btn {
            padding: 8px 20px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
        }
        
        .media-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
        }
        
        @media (max-width: 768px) {
            .media-grid {
                grid-template-columns: 1fr;
            }
        }
        
        .media-item {
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }
        
        .media-item video, .media-item audio {
            width: 100%;
        }
        
        .media-info {
            padding: 15px;
        }
        
        .media-title {
            font-weight: 600;
            color: #333;
            margin-bottom: 5px;
        }
        
        .media-meta {
            color: #999;
            font-size: 12px;
        }
        
        .input-group {
            margin-bottom: 15px;
        }
        
        .input-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
            color: #333;
        }
        
        .input-group input, .input-group textarea, .input-group select {
            width: 100%;
            padding: 10px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 14px;
        }
        
        .chat-container {
            display: flex;
            gap: 20px;
            height: 600px;
            max-height: calc(100vh - 150px);
        }
        
        @media (max-width: 768px) {
            .chat-container {
                flex-direction: column;
                height: auto;
                max-height: calc(100vh - 120px);
            }
        }
        
        .chat-sidebar {
            width: 250px;
            background: white;
            border-radius: 12px;
            padding: 15px;
            overflow-y: auto;
        }
        
        @media (max-width: 768px) {
            .chat-sidebar {
                width: 100%;
                max-height: 200px;
            }
        }
        
        .chat-main {
            flex: 1;
            background: white;
            border-radius: 12px;
            display: flex;
            flex-direction: column;
            min-height: 400px;
        }
        
        @media (max-width: 768px) {
            .chat-main {
                min-height: 300px;
            }
        }
        
        .chat-messages {
            flex: 1;
            padding: 20px;
            overflow-y: auto;
        }
        
        .chat-input-area {
            padding: 15px;
            border-top: 1px solid #e0e0e0;
            display: flex;
            gap: 10px;
        }
        
        .chat-input {
            flex: 1;
            padding: 10px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
        }
        
        .send-btn {
            padding: 10px 25px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
        }
        
        .user-item {
            padding: 10px;
            border-radius: 8px;
            cursor: pointer;
            margin-bottom: 5px;
            transition: background 0.2s;
        }
        
        .user-item:hover {
            background: #f5f5f5;
        }
        
        .user-item.active {
            background: #667eea;
            color: white;
        }
        
        .upload-area {
            border: 2px dashed #e0e0e0;
            border-radius: 12px;
            padding: 40px;
            text-align: center;
            cursor: pointer;
            transition: border-color 0.3s;
        }
        
        .upload-area:hover {
            border-color: #667eea;
        }
        
        .upload-area.dragover {
            border-color: #667eea;
            background: #f0f0ff;
        }
    </style>
</head>
<body>
    <!-- Authentication UI -->
    <div id="authContainer" class="auth-container">
        <div class="auth-box">
            <h1>🌐 LAN World</h1>
            <p>Your complete internet experience on LAN</p>
            
            <div id="errorMessage" class="error"></div>
            
            <div id="loginForm">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" id="loginUsername" placeholder="Enter username">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" id="loginPassword" placeholder="Enter password">
                </div>
                <button class="btn" onclick="login()">Login</button>
                <div class="switch-auth">
                    Don't have an account? <a href="#" onclick="showSignup(); return false;">Sign up</a>
                </div>
            </div>
            
            <div id="signupForm" style="display: none;">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" id="signupUsername" placeholder="Choose a username">
                </div>
                <div class="form-group">
                    <label>Email (optional)</label>
                    <input type="email" id="signupEmail" placeholder="your@email.com">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" id="signupPassword" placeholder="Choose a password">
                </div>
                <button class="btn" onclick="signup()">Sign Up</button>
                <div class="switch-auth">
                    Already have an account? <a href="#" onclick="showLogin(); return false;">Login</a>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Main Application UI -->
    <div id="appContainer" class="app-container">
        <div class="app-header">
            <h1>🌐 LAN World</h1>
            <div class="user-info">
                <span>Welcome, <strong id="currentUsername"></strong>!</span>
                <button class="logout-btn" onclick="logout()">Logout</button>
            </div>
        </div>
        
        <div class="app-main">
            <div class="sidebar-overlay" id="sidebarOverlay" onclick="toggleMobileMenu()"></div>
            <div class="sidebar" id="sidebar">
                <div class="nav-item active" onclick="showPanel('discover')">🔍 Discover</div>
                <div class="nav-item" onclick="showPanel('posts')">🐦 Posts (Twitter)</div>
                <div class="nav-item" onclick="showPanel('forums')">💬 Forums (Reddit)</div>
                <div class="nav-item" onclick="showPanel('chat')">💭 Chat (Discord)</div>
                <div class="nav-item" onclick="showPanel('media')">🎬 Media</div>
                <div class="nav-item" onclick="showPanel('files')">📁 File Share</div>
            </div>
            <button class="mobile-menu-btn" id="mobileMenuBtn" onclick="toggleMobileMenu()">☰</button>
            
            <div class="content">
                <!-- Discover Panel -->
                <div id="discoverPanel" class="panel active">
                    <div class="card">
                        <h2>🎉 Welcome to LAN World!</h2>
                        <p>Your complete internet experience, running entirely on your local network. No internet connection required!</p>
                        <br>
                        <h3>Available Features:</h3>
                        <ul style="margin-left: 20px; margin-top: 10px; line-height: 1.8;">
                            <li><strong>Posts (Twitter/X)</strong> - Share quick updates and thoughts</li>
                            <li><strong>Forums (Reddit)</strong> - Start discussions and engage in threads</li>
                            <li><strong>Chat (Discord)</strong> - Real-time messaging and DMs</li>
                            <li><strong>Media</strong> - Stream videos and music</li>
                            <li><strong>File Share</strong> - Upload and download files</li>
                        </ul>
                        <br>
                        <p><strong>Server Information:</strong></p>
                        <ul style="margin-left: 20px; margin-top: 10px; line-height: 1.8;">
                            <li>Access via: <code>localhost:8080</code> or <code>lanworld.local</code> (if configured)</li>
                            <li>All data stored locally on the host machine</li>
                            <li>Share your IP address for others to join!</li>
                        </ul>
                    </div>
                </div>
                
                <!-- Posts Panel -->
                <div id="postsPanel" class="panel">
                    <div class="card">
                        <h2>Create a Post</h2>
                        <textarea id="postContent" class="post-input" placeholder="What's on your mind?"></textarea>
                        <button class="post-btn" onclick="createPost()">Post</button>
                    </div>
                    <div id="postsFeed"></div>
                </div>
                
                <!-- Forums Panel -->
                <div id="forumsPanel" class="panel">
                    <div class="card">
                        <h2>Create a Forum Thread</h2>
                        <div class="input-group">
                            <label>Title</label>
                            <input type="text" id="forumTitle" placeholder="Thread title">
                        </div>
                        <div class="input-group">
                            <label>Category</label>
                            <select id="forumCategory">
                                <option>General</option>
                                <option>Tech</option>
                                <option>Gaming</option>
                                <option>Movies</option>
                                <option>Music</option>
                                <option>Other</option>
                            </select>
                        </div>
                        <div class="input-group">
                            <label>Content</label>
                            <textarea id="forumContent" class="forum-input" placeholder="What do you want to discuss?"></textarea>
                        </div>
                        <button class="submit-btn" onclick="createForum()">Create Thread</button>
                    </div>
                    <div id="forumsList"></div>
                </div>
                
                <!-- Chat Panel -->
                <div id="chatPanel" class="panel">
                    <div class="chat-container">
                        <div class="chat-sidebar">
                            <h3 style="margin-bottom: 15px;">Channels</h3>
                            <div class="user-item active" onclick="selectChannel('general')">
                                # general
                            </div>
                            <div class="user-item" onclick="selectChannel('random')">
                                # random
                            </div>
                            <h3 style="margin: 20px 0 15px 0;">Direct Messages</h3>
                            <div id="usersList"></div>
                        </div>
                        <div class="chat-main">
                            <div class="chat-messages" id="chatMessages"></div>
                            <div class="chat-input-area">
                                <input type="text" id="messageInput" class="chat-input" placeholder="Type a message..." onkeypress="if(event.key==='Enter') sendMessage()">
                                <button class="send-btn" onclick="sendMessage()">Send</button>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Media Panel -->
                <div id="mediaPanel" class="panel">
                    <div class="card">
                        <h2>Upload Media</h2>
                        <div class="input-group">
                            <label>Title</label>
                            <input type="text" id="mediaTitle" placeholder="Media title">
                        </div>
                        <div class="input-group">
                            <label>Type</label>
                            <select id="mediaType">
                                <option value="video">Video</option>
                                <option value="music">Music</option>
                            </select>
                        </div>
                        <div class="input-group">
                            <label>File</label>
                            <input type="file" id="mediaFile" accept="video/*,audio/*">
                        </div>
                        <button class="submit-btn" onclick="uploadMedia()">Upload</button>
                    </div>
                    <div id="mediaGrid" class="media-grid"></div>
                </div>
                
                <!-- Files Panel -->
                <div id="filesPanel" class="panel">
                    <div class="card">
                        <h2>Upload File</h2>
                        <div class="input-group">
                            <label>Description (optional)</label>
                            <input type="text" id="fileDescription" placeholder="What is this file?">
                        </div>
                        <div class="upload-area" id="uploadArea" onclick="document.getElementById('fileInput').click()">
                            <h3>📤 Click or drag files here</h3>
                            <p style="color: #999; margin-top: 10px;">Max file size: 500MB</p>
                        </div>
                        <input type="file" id="fileInput" style="display: none;" onchange="uploadFile()">
                    </div>
                    <div id="filesList"></div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let currentUser = null;
        let currentChatMode = 'channel';
        let currentChannel = 'general';
        let currentRecipient = null;
        let refreshInterval = null;
        
        function toggleMobileMenu() {
            const sidebar = document.getElementById('sidebar');
            const overlay = document.getElementById('sidebarOverlay');
            sidebar.classList.toggle('open');
            overlay.classList.toggle('show');
        }
        
        function closeMobileMenu() {
            const sidebar = document.getElementById('sidebar');
            const overlay = document.getElementById('sidebarOverlay');
            sidebar.classList.remove('open');
            overlay.classList.remove('show');
        }
        
        function showError(message) {
            const errorDiv = document.getElementById('errorMessage');
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
            setTimeout(() => errorDiv.style.display = 'none', 5000);
        }
        
        function showLogin() {
            document.getElementById('loginForm').style.display = 'block';
            document.getElementById('signupForm').style.display = 'none';
        }
        
        function showSignup() {
            document.getElementById('loginForm').style.display = 'none';
            document.getElementById('signupForm').style.display = 'block';
        }
        
        async function login() {
            const username = document.getElementById('loginUsername').value;
            const password = document.getElementById('loginPassword').value;
            
            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username, password})
                });
                
                const data = await res.json();
                if (res.ok) {
                    currentUser = data;
                    showApp();
                } else {
                    showError(data.error);
                }
            } catch (e) {
                showError('Login failed');
            }
        }
        
        async function signup() {
            const username = document.getElementById('signupUsername').value;
            const email = document.getElementById('signupEmail').value;
            const password = document.getElementById('signupPassword').value;
            
            try {
                const res = await fetch('/api/signup', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username, email, password})
                });
                
                const data = await res.json();
                if (res.ok) {
                    currentUser = data;
                    showApp();
                } else {
                    showError(data.error);
                }
            } catch (e) {
                showError('Signup failed');
            }
        }
        
        async function logout() {
            await fetch('/api/logout', {method: 'POST'});
            clearInterval(refreshInterval);
            document.getElementById('authContainer').style.display = 'flex';
            document.getElementById('appContainer').style.display = 'none';
            currentUser = null;
        }
        
        function showApp() {
            document.getElementById('authContainer').style.display = 'none';
            const appContainer = document.getElementById('appContainer');
            appContainer.style.display = 'flex';
            document.getElementById('currentUsername').textContent = currentUser.username;
            
            // Load initial data
            loadPosts();
            loadForums();
            loadUsers();
            loadMedia();
            loadFiles();
            loadMessages();
            
            // Auto-refresh
            refreshInterval = setInterval(() => {
                loadMessages();
            }, 3000);
        }
        
        function showPanel(panelName) {
            document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            
            document.getElementById(panelName + 'Panel').classList.add('active');
            event.target.classList.add('active');
            
            // Close mobile menu
            closeMobileMenu();
            
            // Load panel data
            if (panelName === 'posts') loadPosts();
            if (panelName === 'forums') loadForums();
            if (panelName === 'chat') loadMessages();
            if (panelName === 'media') loadMedia();
            if (panelName === 'files') loadFiles();
        }
        
        async function createPost() {
            const content = document.getElementById('postContent').value;
            if (!content.trim()) return;
            
            await fetch('/api/posts', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({content})
            });
            
            document.getElementById('postContent').value = '';
            loadPosts();
        }
        
        async function loadPosts() {
            const res = await fetch('/api/posts');
            const posts = await res.json();
            
            const feed = document.getElementById('postsFeed');
            feed.innerHTML = posts.map(post => `
                <div class="post">
                    <div class="post-header">
                        <span class="post-author">@${post.username}</span>
                        <span class="post-time">${new Date(post.created_at).toLocaleString()}</span>
                    </div>
                    <div class="post-content">${post.content}</div>
                    <div class="post-actions">
                        <span class="like-btn" onclick="likePost(${post.id})">
                            ❤️ ${post.likes} likes
                        </span>
                    </div>
                </div>
            `).join('');
        }
        
        async function likePost(postId) {
            await fetch(`/api/posts/${postId}/like`, {method: 'POST'});
            loadPosts();
        }
        
        async function createForum() {
            const title = document.getElementById('forumTitle').value;
            const content = document.getElementById('forumContent').value;
            const category = document.getElementById('forumCategory').value;
            
            if (!title.trim() || !content.trim()) return;
            
            await fetch('/api/forums', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({title, content, category})
            });
            
            document.getElementById('forumTitle').value = '';
            document.getElementById('forumContent').value = '';
            loadForums();
        }
        
        async function loadForums() {
            const res = await fetch('/api/forums');
            const forums = await res.json();
            
            const list = document.getElementById('forumsList');
            list.innerHTML = forums.map(forum => `
                <div class="post">
                    <div class="post-header">
                        <div>
                            <strong style="font-size: 18px;">${forum.title}</strong>
                            <span style="background: #667eea; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; margin-left: 10px;">
                                ${forum.category}
                            </span>
                        </div>
                        <span class="post-time">${new Date(forum.created_at).toLocaleString()}</span>
                    </div>
                    <div class="post-content">${forum.content}</div>
                    <div class="post-actions">
                        <span>👤 ${forum.username}</span>
                        <span>💬 ${forum.comment_count} comments</span>
                        <span>❤️ ${forum.likes} likes</span>
                    </div>
                </div>
            `).join('');
        }
        
        async function loadUsers() {
            const res = await fetch('/api/users');
            const users = await res.json();
            
            const list = document.getElementById('usersList');
            list.innerHTML = users.map(user => `
                <div class="user-item" onclick="selectUser(${user.id}, '${user.username}')">
                    @ ${user.username}
                </div>
            `).join('');
        }
        
        function selectChannel(channel) {
            currentChatMode = 'channel';
            currentChannel = channel;
            currentRecipient = null;
            
            document.querySelectorAll('.chat-sidebar .user-item').forEach(el => {
                el.classList.remove('active');
            });
            event.target.classList.add('active');
            
            loadMessages();
        }
        
        function selectUser(userId, username) {
            currentChatMode = 'dm';
            currentRecipient = userId;
            currentChannel = null;
            
            document.querySelectorAll('.chat-sidebar .user-item').forEach(el => {
                el.classList.remove('active');
            });
            event.target.classList.add('active');
            
            loadMessages();
        }
        
        async function sendMessage() {
            const content = document.getElementById('messageInput').value;
            if (!content.trim()) return;
            
            await fetch('/api/messages', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    content,
                    is_dm: currentChatMode === 'dm',
                    recipient_id: currentRecipient,
                    channel_name: currentChannel
                })
            });
            
            document.getElementById('messageInput').value = '';
            loadMessages();
        }
        
        async function loadMessages() {
            const params = new URLSearchParams();
            if (currentChatMode === 'dm' && currentRecipient) {
                params.append('is_dm', 'true');
                params.append('recipient_id', currentRecipient);
            } else {
                params.append('channel', currentChannel || 'general');
            }
            
            const res = await fetch(`/api/messages?${params}`);
            const messages = await res.json();
            
            const container = document.getElementById('chatMessages');
            container.innerHTML = messages.map(msg => `
                <div class="message">
                    <div class="message-sender">@${msg.sender_username}</div>
                    <div class="message-content">${msg.content}</div>
                </div>
            `).join('');
            
            container.scrollTop = container.scrollHeight;
        }
        
        async function uploadMedia() {
            const title = document.getElementById('mediaTitle').value;
            const type = document.getElementById('mediaType').value;
            const file = document.getElementById('mediaFile').files[0];
            
            if (!file) return;
            
            const formData = new FormData();
            formData.append('file', file);
            formData.append('title', title || file.name);
            formData.append('media_type', type);
            
            await fetch('/api/media', {
                method: 'POST',
                body: formData
            });
            
            document.getElementById('mediaTitle').value = '';
            document.getElementById('mediaFile').value = '';
            loadMedia();
        }
        
        async function loadMedia() {
            const res = await fetch('/api/media');
            const mediaList = await res.json();
            
            const grid = document.getElementById('mediaGrid');
            grid.innerHTML = mediaList.map(media => {
                const tag = media.media_type === 'video' ? 'video' : 'audio';
                return `
                    <div class="media-item">
                        <${tag} controls src="/api/media/${media.id}/stream"></${tag}>
                        <div class="media-info">
                            <div class="media-title">${media.title}</div>
                            <div class="media-meta">
                                Uploaded by ${media.username} • ${media.views} views
                            </div>
                        </div>
                    </div>
                `;
            }).join('');
        }
        
        async function uploadFile() {
            const file = document.getElementById('fileInput').files[0];
            const description = document.getElementById('fileDescription').value;
            
            if (!file) return;
            
            const formData = new FormData();
            formData.append('file', file);
            formData.append('description', description);
            
            await fetch('/api/files', {
                method: 'POST',
                body: formData
            });
            
            document.getElementById('fileInput').value = '';
            document.getElementById('fileDescription').value = '';
            loadFiles();
        }
        
        async function loadFiles() {
            const res = await fetch('/api/files');
            const files = await res.json();
            
            const list = document.getElementById('filesList');
            list.innerHTML = files.map(file => `
                <div class="file-item">
                    <div class="file-info">
                        <h4>📄 ${file.original_filename}</h4>
                        <div class="file-meta">
                            ${(file.file_size / 1024 / 1024).toFixed(2)} MB • 
                            Uploaded by ${file.username} • 
                            ${file.downloads} downloads
                            ${file.description ? `<br>${file.description}` : ''}
                        </div>
                    </div>
                    <button class="download-btn" onclick="downloadFile(${file.id})">Download</button>
                </div>
            `).join('');
        }
        
        function downloadFile(fileId) {
            window.location.href = `/api/files/${fileId}/download`;
        }
        
        // Drag and drop for file upload
        const uploadArea = document.getElementById('uploadArea');
        if (uploadArea) {
            // Prevent default drag behaviors
            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
                uploadArea.addEventListener(eventName, preventDefaults, false);
                document.body.addEventListener(eventName, preventDefaults, false);
            });
            
            function preventDefaults(e) {
                e.preventDefault();
                e.stopPropagation();
            }
            
            uploadArea.addEventListener('dragover', (e) => {
                e.preventDefault();
                uploadArea.classList.add('dragover');
            });
            
            uploadArea.addEventListener('dragleave', () => {
                uploadArea.classList.remove('dragover');
            });
            
            uploadArea.addEventListener('drop', (e) => {
                e.preventDefault();
                uploadArea.classList.remove('dragover');
                const files = e.dataTransfer.files;
                if (files.length > 0) {
                    const fileInput = document.getElementById('fileInput');
                    fileInput.files = files;
                    uploadFile();
                }
            });
        }
        
        // Enter key for login
        document.addEventListener('DOMContentLoaded', () => {
            document.getElementById('loginPassword').addEventListener('keypress', (e) => {
                if (e.key === 'Enter') login();
            });
            document.getElementById('signupPassword').addEventListener('keypress', (e) => {
                if (e.key === 'Enter') signup();
            });
        });
    </script>
</body>
</html>
'''

if __name__ == '__main__':
    print("=" * 60)
    print("🌐 LAN WORLD - Your Local Internet Experience")
    print("=" * 60)
    print("\nInitializing database...")
    init_db()
    print("✓ Database initialized")
    print("\n📍 Access LAN World at:")
    print("   • http://localhost:8080")
    print("   • http://127.0.0.1:8080")
    print("   • http://lanworld.local:8080 (if configured)")
    print(f"   • http://[YOUR-LOCAL-IP]:8080 (share with others!)")
    print("\n💾 Data stored in:", BASE_DIR)
    print("\nStarting server...")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=8080, debug=False)
