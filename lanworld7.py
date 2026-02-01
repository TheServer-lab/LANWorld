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

# Persistent secret key - stays same across restarts
SECRET_KEY_FILE = BASE_DIR / 'secret.key'
if SECRET_KEY_FILE.exists():
    app.secret_key = SECRET_KEY_FILE.read_text()
else:
    app.secret_key = secrets.token_hex(32)
    SECRET_KEY_FILE.write_text(app.secret_key)

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
        role TEXT DEFAULT 'user',
        banned BOOLEAN DEFAULT 0,
        banned_until TIMESTAMP,
        banned_reason TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Moderation log
    c.execute('''CREATE TABLE IF NOT EXISTS moderation_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        moderator_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_id INTEGER NOT NULL,
        reason TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (moderator_id) REFERENCES users (id)
    )''')
    
    # Reports
    c.execute('''CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reporter_id INTEGER NOT NULL,
        item_type TEXT NOT NULL,
        item_id INTEGER NOT NULL,
        reason TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        resolved_by INTEGER,
        resolved_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (reporter_id) REFERENCES users (id),
        FOREIGN KEY (resolved_by) REFERENCES users (id)
    )''')
    
    # Posts table (Twitter/X style)
    c.execute('''CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        media_url TEXT,
        likes INTEGER DEFAULT 0,
        pinned BOOLEAN DEFAULT 0,
        deleted BOOLEAN DEFAULT 0,
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
        locked BOOLEAN DEFAULT 0,
        deleted BOOLEAN DEFAULT 0,
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
    
    # Post comments/replies
    c.execute('''CREATE TABLE IF NOT EXISTS post_comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (post_id) REFERENCES posts (id),
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
    
    # Notifications table
    c.execute('''CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        link TEXT,
        read BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Call history table
    c.execute('''CREATE TABLE IF NOT EXISTS calls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        caller_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        call_type TEXT NOT NULL,
        status TEXT NOT NULL,
        duration INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (caller_id) REFERENCES users (id),
        FOREIGN KEY (receiver_id) REFERENCES users (id)
    )''')
    
    # User status table (online/offline/in-call)
    c.execute('''CREATE TABLE IF NOT EXISTS user_status (
        user_id INTEGER PRIMARY KEY,
        status TEXT DEFAULT 'offline',
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Pastebin table
    c.execute('''CREATE TABLE IF NOT EXISTS pastes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        language TEXT DEFAULT 'text',
        is_public BOOLEAN DEFAULT 1,
        views INTEGER DEFAULT 0,
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Live streams table
    c.execute('''CREATE TABLE IF NOT EXISTS streams (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        is_live BOOLEAN DEFAULT 0,
        viewers INTEGER DEFAULT 0,
        started_at TIMESTAMP,
        ended_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Photos table (Instagram-like)
    c.execute('''CREATE TABLE IF NOT EXISTS photos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        caption TEXT,
        filter TEXT,
        likes INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Photo comments
    c.execute('''CREATE TABLE IF NOT EXISTS photo_comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        photo_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (photo_id) REFERENCES photos (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Notes table
    c.execute('''CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        color TEXT DEFAULT '#ffd700',
        pinned BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Tasks table
    c.execute('''CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        completed BOOLEAN DEFAULT 0,
        priority TEXT DEFAULT 'medium',
        due_date TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Calendar events table
    c.execute('''CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        location TEXT,
        start_time TIMESTAMP NOT NULL,
        end_time TIMESTAMP,
        all_day BOOLEAN DEFAULT 0,
        color TEXT DEFAULT '#667eea',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Games table - for multiplayer game sessions
    c.execute('''CREATE TABLE IF NOT EXISTS game_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        game_type TEXT NOT NULL,
        player1_id INTEGER NOT NULL,
        player2_id INTEGER,
        state TEXT,
        winner_id INTEGER,
        status TEXT DEFAULT 'waiting',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP,
        FOREIGN KEY (player1_id) REFERENCES users (id),
        FOREIGN KEY (player2_id) REFERENCES users (id),
        FOREIGN KEY (winner_id) REFERENCES users (id)
    )''')
    
    # Game scores/leaderboard
    c.execute('''CREATE TABLE IF NOT EXISTS game_scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        game_type TEXT NOT NULL,
        score INTEGER NOT NULL,
        level INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
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

def mod_required(f):
    """Decorator to require moderator or admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        conn.close()
        
        if not user or user['role'] not in ['moderator', 'admin']:
            return jsonify({'error': 'Moderator privileges required'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        conn.close()
        
        if not user or user['role'] != 'admin':
            return jsonify({'error': 'Admin privileges required'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

def check_banned(f):
    """Decorator to check if user is banned"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return f(*args, **kwargs)
        
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT banned, banned_until FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        conn.close()
        
        if user and user['banned']:
            if user['banned_until']:
                # Check if temporary ban expired
                from datetime import datetime
                ban_end = datetime.fromisoformat(user['banned_until'])
                if datetime.now() < ban_end:
                    return jsonify({'error': f'You are banned until {ban_end}'}), 403
                else:
                    # Unban automatically
                    conn = get_db()
                    c = conn.cursor()
                    c.execute('UPDATE users SET banned = 0, banned_until = NULL WHERE id = ?', (session['user_id'],))
                    conn.commit()
                    conn.close()
            else:
                return jsonify({'error': 'You are permanently banned'}), 403
        
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
    c.execute('''SELECT posts.*, users.username, users.avatar,
                 (SELECT COUNT(*) FROM post_comments WHERE post_id = posts.id) as comment_count
                 FROM posts 
                 JOIN users ON posts.user_id = users.id 
                 WHERE posts.deleted = 0
                 ORDER BY posts.pinned DESC, posts.created_at DESC LIMIT 100''')
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

@app.route('/api/posts/<int:post_id>/comments', methods=['GET', 'POST'])
@login_required
def post_comments(post_id):
    """Get or add comments to a post"""
    if request.method == 'POST':
        data = request.json
        content = data.get('content', '').strip()
        
        if not content:
            return jsonify({'error': 'Content required'}), 400
        
        conn = get_db()
        c = conn.cursor()
        c.execute('''INSERT INTO post_comments (post_id, user_id, content) 
                     VALUES (?, ?, ?)''',
                  (post_id, session['user_id'], content))
        conn.commit()
        comment_id = c.lastrowid
        conn.close()
        
        return jsonify({'success': True, 'comment_id': comment_id})
    
    # GET request
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT post_comments.*, users.username 
                 FROM post_comments 
                 JOIN users ON post_comments.user_id = users.id 
                 WHERE post_comments.post_id = ?
                 ORDER BY post_comments.created_at ASC''', (post_id,))
    comments = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify(comments)

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
                     WHERE forums.category = ? AND forums.deleted = 0
                     ORDER BY forums.created_at DESC LIMIT 100''', (category,))
    else:
        c.execute('''SELECT forums.*, users.username,
                     (SELECT COUNT(*) FROM forum_comments WHERE forum_id = forums.id) as comment_count
                     FROM forums 
                     JOIN users ON forums.user_id = users.id 
                     WHERE forums.deleted = 0
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

@app.route('/api/forums/<int:forum_id>/like', methods=['POST'])
@login_required
def like_forum(forum_id):
    """Like or unlike a forum post"""
    conn = get_db()
    c = conn.cursor()
    
    # Check if already liked
    c.execute('SELECT id FROM likes WHERE user_id = ? AND item_type = ? AND item_id = ?',
              (session['user_id'], 'forum', forum_id))
    existing_like = c.fetchone()
    
    if existing_like:
        # Unlike
        c.execute('DELETE FROM likes WHERE id = ?', (existing_like['id'],))
        c.execute('UPDATE forums SET likes = likes - 1 WHERE id = ?', (forum_id,))
        action = 'unliked'
    else:
        # Like
        c.execute('INSERT INTO likes (user_id, item_type, item_id) VALUES (?, ?, ?)',
                  (session['user_id'], 'forum', forum_id))
        c.execute('UPDATE forums SET likes = likes + 1 WHERE id = ?', (forum_id,))
        action = 'liked'
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'action': action})

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

# Notifications
@app.route('/api/notifications')
@login_required
def get_notifications():
    """Get user notifications"""
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT * FROM notifications 
                 WHERE user_id = ? 
                 ORDER BY created_at DESC LIMIT 50''', (session['user_id'],))
    notifications = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(notifications)

@app.route('/api/notifications/unread-count')
@login_required
def get_unread_count():
    """Get count of unread notifications"""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND read = 0', 
              (session['user_id'],))
    result = c.fetchone()
    conn.close()
    return jsonify({'count': result['count']})

@app.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    """Mark a notification as read"""
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE notifications SET read = 1 WHERE id = ? AND user_id = ?', 
              (notification_id, session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/notifications/mark-all-read', methods=['POST'])
@login_required
def mark_all_read():
    """Mark all notifications as read"""
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE notifications SET read = 1 WHERE user_id = ?', (session['user_id'],))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

def create_notification(user_id, notif_type, title, message, link=None):
    """Helper function to create notifications"""
    conn = get_db()
    c = conn.cursor()
    c.execute('''INSERT INTO notifications (user_id, type, title, message, link) 
                 VALUES (?, ?, ?, ?, ?)''',
              (user_id, notif_type, title, message, link))
    conn.commit()
    conn.close()

# Calls
@app.route('/api/calls/initiate', methods=['POST'])
@login_required
def initiate_call():
    """Initiate a call to another user"""
    data = request.json
    receiver_id = data.get('receiver_id')
    call_type = data.get('call_type', 'video')  # 'video' or 'audio'
    
    if not receiver_id:
        return jsonify({'error': 'Receiver ID required'}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    # Check if receiver exists
    c.execute('SELECT username FROM users WHERE id = ?', (receiver_id,))
    receiver = c.fetchone()
    
    if not receiver:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    
    # Create call record
    c.execute('''INSERT INTO calls (caller_id, receiver_id, call_type, status) 
                 VALUES (?, ?, ?, 'ringing')''',
              (session['user_id'], receiver_id, call_type))
    conn.commit()
    call_id = c.lastrowid
    
    # Create notification for receiver
    c.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],))
    caller = c.fetchone()
    
    create_notification(
        receiver_id, 
        'call', 
        f'Incoming {call_type} call',
        f'{caller["username"]} is calling you',
        f'/call/{call_id}'
    )
    
    conn.close()
    
    return jsonify({
        'success': True, 
        'call_id': call_id,
        'receiver_username': receiver['username']
    })

@app.route('/api/calls/<int:call_id>/answer', methods=['POST'])
@login_required
def answer_call(call_id):
    """Answer an incoming call"""
    conn = get_db()
    c = conn.cursor()
    
    # Verify this user is the receiver
    c.execute('SELECT * FROM calls WHERE id = ? AND receiver_id = ?', 
              (call_id, session['user_id']))
    call = c.fetchone()
    
    if not call:
        conn.close()
        return jsonify({'error': 'Call not found'}), 404
    
    # Update call status
    c.execute('UPDATE calls SET status = ? WHERE id = ?', ('active', call_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/calls/<int:call_id>/end', methods=['POST'])
@login_required
def end_call(call_id):
    """End a call"""
    data = request.json
    duration = data.get('duration', 0)
    
    conn = get_db()
    c = conn.cursor()
    
    c.execute('''UPDATE calls SET status = ?, duration = ? 
                 WHERE id = ? AND (caller_id = ? OR receiver_id = ?)''',
              ('ended', duration, call_id, session['user_id'], session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/calls/<int:call_id>/reject', methods=['POST'])
@login_required
def reject_call(call_id):
    """Reject an incoming call"""
    conn = get_db()
    c = conn.cursor()
    
    c.execute('''UPDATE calls SET status = ? 
                 WHERE id = ? AND receiver_id = ?''',
              ('rejected', call_id, session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/calls/history')
@login_required
def call_history():
    """Get call history"""
    conn = get_db()
    c = conn.cursor()
    
    c.execute('''SELECT calls.*, 
                 caller.username as caller_username,
                 receiver.username as receiver_username
                 FROM calls
                 JOIN users caller ON calls.caller_id = caller.id
                 JOIN users receiver ON calls.receiver_id = receiver.id
                 WHERE calls.caller_id = ? OR calls.receiver_id = ?
                 ORDER BY calls.created_at DESC LIMIT 50''',
              (session['user_id'], session['user_id']))
    
    calls = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify(calls)

# User status
@app.route('/api/status/update', methods=['POST'])
@login_required
def update_status():
    """Update user online status"""
    data = request.json
    status = data.get('status', 'online')
    
    conn = get_db()
    c = conn.cursor()
    
    c.execute('''INSERT OR REPLACE INTO user_status (user_id, status, last_seen) 
                 VALUES (?, ?, CURRENT_TIMESTAMP)''',
              (session['user_id'], status))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/status/online-users')
@login_required
def get_online_users():
    """Get list of online users"""
    conn = get_db()
    c = conn.cursor()
    
    # Users online in last 5 minutes
    c.execute('''SELECT users.id, users.username, user_status.status, user_status.last_seen
                 FROM users
                 LEFT JOIN user_status ON users.id = user_status.user_id
                 WHERE users.id != ? 
                 AND (user_status.status = 'online' OR 
                      datetime(user_status.last_seen) > datetime('now', '-5 minutes'))
                 ORDER BY users.username''',
              (session['user_id'],))
    
    users = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify(users)

# ===== PASTEBIN =====
@app.route('/api/pastes', methods=['GET', 'POST'])
@login_required
def pastes():
    """Get all pastes or create a new paste"""
    if request.method == 'POST':
        data = request.json
        title = data.get('title', 'Untitled').strip()
        content = data.get('content', '').strip()
        language = data.get('language', 'text')
        is_public = data.get('is_public', True)
        
        if not content:
            return jsonify({'error': 'Content required'}), 400
        
        conn = get_db()
        c = conn.cursor()
        c.execute('''INSERT INTO pastes (user_id, title, content, language, is_public) 
                     VALUES (?, ?, ?, ?, ?)''',
                  (session['user_id'], title, content, language, is_public))
        conn.commit()
        paste_id = c.lastrowid
        conn.close()
        
        return jsonify({'success': True, 'paste_id': paste_id})
    
    # GET request
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT pastes.*, users.username 
                 FROM pastes 
                 JOIN users ON pastes.user_id = users.id 
                 WHERE pastes.is_public = 1 OR pastes.user_id = ?
                 ORDER BY pastes.created_at DESC LIMIT 100''',
              (session['user_id'],))
    pastes = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify(pastes)

@app.route('/api/pastes/<int:paste_id>')
@login_required
def get_paste(paste_id):
    """Get a specific paste"""
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT pastes.*, users.username 
                 FROM pastes 
                 JOIN users ON pastes.user_id = users.id 
                 WHERE pastes.id = ?''', (paste_id,))
    paste = c.fetchone()
    
    if paste:
        c.execute('UPDATE pastes SET views = views + 1 WHERE id = ?', (paste_id,))
        conn.commit()
        conn.close()
        return jsonify(dict(paste))
    
    conn.close()
    return jsonify({'error': 'Paste not found'}), 404

@app.route('/api/pastes/<int:paste_id>/delete', methods=['POST'])
@login_required
def delete_paste(paste_id):
    """Delete a paste"""
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM pastes WHERE id = ? AND user_id = ?', 
              (paste_id, session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# ===== LIVE STREAMING =====
@app.route('/api/streams', methods=['GET', 'POST'])
@login_required
def streams():
    """Get all streams or create a new stream"""
    if request.method == 'POST':
        data = request.json
        title = data.get('title', 'Untitled Stream').strip()
        description = data.get('description', '')
        
        conn = get_db()
        c = conn.cursor()
        c.execute('''INSERT INTO streams (user_id, title, description, is_live, started_at) 
                     VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)''',
                  (session['user_id'], title, description))
        conn.commit()
        stream_id = c.lastrowid
        conn.close()
        
        return jsonify({'success': True, 'stream_id': stream_id})
    
    # GET request
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT streams.*, users.username 
                 FROM streams 
                 JOIN users ON streams.user_id = users.id 
                 WHERE streams.is_live = 1
                 ORDER BY streams.started_at DESC''')
    streams = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify(streams)

@app.route('/api/streams/<int:stream_id>/end', methods=['POST'])
@login_required
def end_stream(stream_id):
    """End a live stream"""
    conn = get_db()
    c = conn.cursor()
    c.execute('''UPDATE streams SET is_live = 0, ended_at = CURRENT_TIMESTAMP 
                 WHERE id = ? AND user_id = ?''',
              (stream_id, session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/streams/<int:stream_id>/viewers', methods=['POST'])
@login_required
def update_viewers(stream_id):
    """Update viewer count"""
    data = request.json
    viewers = data.get('viewers', 0)
    
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE streams SET viewers = ? WHERE id = ?', (viewers, stream_id))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# ===== PHOTOS (Instagram-like) =====
@app.route('/api/photos', methods=['GET', 'POST'])
@login_required
def photos():
    """Get all photos or upload a new photo"""
    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        caption = request.form.get('caption', '')
        photo_filter = request.form.get('filter', 'none')
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if file and allowed_file(file.filename):
            original_filename = secure_filename(file.filename)
            filename = f"{secrets.token_hex(8)}_{original_filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            conn = get_db()
            c = conn.cursor()
            c.execute('''INSERT INTO photos (user_id, filename, caption, filter) 
                         VALUES (?, ?, ?, ?)''',
                      (session['user_id'], filename, caption, photo_filter))
            conn.commit()
            photo_id = c.lastrowid
            conn.close()
            
            return jsonify({'success': True, 'photo_id': photo_id, 'filename': filename})
        
        return jsonify({'error': 'File type not allowed'}), 400
    
    # GET request
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT photos.*, users.username,
                 (SELECT COUNT(*) FROM photo_comments WHERE photo_id = photos.id) as comment_count
                 FROM photos 
                 JOIN users ON photos.user_id = users.id 
                 ORDER BY photos.created_at DESC LIMIT 100''')
    photos = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify(photos)

@app.route('/api/photos/<int:photo_id>/like', methods=['POST'])
@login_required
def like_photo(photo_id):
    """Like or unlike a photo"""
    conn = get_db()
    c = conn.cursor()
    
    c.execute('SELECT id FROM likes WHERE user_id = ? AND item_type = ? AND item_id = ?',
              (session['user_id'], 'photo', photo_id))
    existing_like = c.fetchone()
    
    if existing_like:
        c.execute('DELETE FROM likes WHERE id = ?', (existing_like['id'],))
        c.execute('UPDATE photos SET likes = likes - 1 WHERE id = ?', (photo_id,))
        action = 'unliked'
    else:
        c.execute('INSERT INTO likes (user_id, item_type, item_id) VALUES (?, ?, ?)',
                  (session['user_id'], 'photo', photo_id))
        c.execute('UPDATE photos SET likes = likes + 1 WHERE id = ?', (photo_id,))
        action = 'liked'
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'action': action})

@app.route('/api/photos/<int:photo_id>/comments', methods=['GET', 'POST'])
@login_required
def photo_comments(photo_id):
    """Get or add photo comments"""
    if request.method == 'POST':
        data = request.json
        content = data.get('content', '').strip()
        
        if not content:
            return jsonify({'error': 'Content required'}), 400
        
        conn = get_db()
        c = conn.cursor()
        c.execute('''INSERT INTO photo_comments (photo_id, user_id, content) 
                     VALUES (?, ?, ?)''',
                  (photo_id, session['user_id'], content))
        conn.commit()
        comment_id = c.lastrowid
        conn.close()
        
        return jsonify({'success': True, 'comment_id': comment_id})
    
    # GET request
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT photo_comments.*, users.username 
                 FROM photo_comments 
                 JOIN users ON photo_comments.user_id = users.id 
                 WHERE photo_comments.photo_id = ?
                 ORDER BY photo_comments.created_at ASC''', (photo_id,))
    comments = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify(comments)

@app.route('/api/photos/<int:photo_id>/view')
def view_photo(photo_id):
    """View a photo file"""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT filename FROM photos WHERE id = ?', (photo_id,))
    photo = c.fetchone()
    conn.close()
    
    if photo:
        return send_from_directory(app.config['UPLOAD_FOLDER'], photo['filename'])
    
    return jsonify({'error': 'Photo not found'}), 404

# ===== NOTES =====
@app.route('/api/notes', methods=['GET', 'POST'])
@login_required
def notes():
    """Get all notes or create a new note"""
    if request.method == 'POST':
        data = request.json
        title = data.get('title', 'Untitled').strip()
        content = data.get('content', '').strip()
        color = data.get('color', '#ffd700')
        pinned = data.get('pinned', False)
        
        if not content:
            return jsonify({'error': 'Content required'}), 400
        
        conn = get_db()
        c = conn.cursor()
        c.execute('''INSERT INTO notes (user_id, title, content, color, pinned) 
                     VALUES (?, ?, ?, ?, ?)''',
                  (session['user_id'], title, content, color, pinned))
        conn.commit()
        note_id = c.lastrowid
        conn.close()
        
        return jsonify({'success': True, 'note_id': note_id})
    
    # GET request
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT * FROM notes 
                 WHERE user_id = ? 
                 ORDER BY pinned DESC, updated_at DESC''',
              (session['user_id'],))
    notes = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify(notes)

@app.route('/api/notes/<int:note_id>', methods=['PUT', 'DELETE'])
@login_required
def update_note(note_id):
    """Update or delete a note"""
    if request.method == 'PUT':
        data = request.json
        title = data.get('title')
        content = data.get('content')
        color = data.get('color')
        pinned = data.get('pinned')
        
        conn = get_db()
        c = conn.cursor()
        
        updates = []
        values = []
        if title is not None:
            updates.append('title = ?')
            values.append(title)
        if content is not None:
            updates.append('content = ?')
            values.append(content)
        if color is not None:
            updates.append('color = ?')
            values.append(color)
        if pinned is not None:
            updates.append('pinned = ?')
            values.append(pinned)
        
        updates.append('updated_at = CURRENT_TIMESTAMP')
        values.extend([note_id, session['user_id']])
        
        c.execute(f'''UPDATE notes SET {', '.join(updates)} 
                     WHERE id = ? AND user_id = ?''', values)
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
    
    # DELETE
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM notes WHERE id = ? AND user_id = ?', 
              (note_id, session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

# ===== TASKS =====
@app.route('/api/tasks', methods=['GET', 'POST'])
@login_required
def tasks():
    """Get all tasks or create a new task"""
    if request.method == 'POST':
        data = request.json
        title = data.get('title', '').strip()
        description = data.get('description', '')
        priority = data.get('priority', 'medium')
        due_date = data.get('due_date')
        
        if not title:
            return jsonify({'error': 'Title required'}), 400
        
        conn = get_db()
        c = conn.cursor()
        c.execute('''INSERT INTO tasks (user_id, title, description, priority, due_date) 
                     VALUES (?, ?, ?, ?, ?)''',
                  (session['user_id'], title, description, priority, due_date))
        conn.commit()
        task_id = c.lastrowid
        conn.close()
        
        return jsonify({'success': True, 'task_id': task_id})
    
    # GET request
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT * FROM tasks 
                 WHERE user_id = ? 
                 ORDER BY completed ASC, due_date ASC, priority DESC, created_at DESC''',
              (session['user_id'],))
    tasks = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify(tasks)

@app.route('/api/tasks/<int:task_id>/toggle', methods=['POST'])
@login_required
def toggle_task(task_id):
    """Toggle task completion"""
    conn = get_db()
    c = conn.cursor()
    c.execute('''UPDATE tasks SET completed = NOT completed 
                 WHERE id = ? AND user_id = ?''',
              (task_id, session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/tasks/<int:task_id>', methods=['DELETE'])
@login_required
def delete_task(task_id):
    """Delete a task"""
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM tasks WHERE id = ? AND user_id = ?', 
              (task_id, session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

# ===== CALENDAR =====
@app.route('/api/events', methods=['GET', 'POST'])
@login_required
def events():
    """Get all events or create a new event"""
    if request.method == 'POST':
        data = request.json
        title = data.get('title', '').strip()
        description = data.get('description', '')
        location = data.get('location', '')
        start_time = data.get('start_time')
        end_time = data.get('end_time')
        all_day = data.get('all_day', False)
        color = data.get('color', '#667eea')
        
        if not title or not start_time:
            return jsonify({'error': 'Title and start time required'}), 400
        
        conn = get_db()
        c = conn.cursor()
        c.execute('''INSERT INTO events (user_id, title, description, location, start_time, end_time, all_day, color) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                  (session['user_id'], title, description, location, start_time, end_time, all_day, color))
        conn.commit()
        event_id = c.lastrowid
        conn.close()
        
        return jsonify({'success': True, 'event_id': event_id})
    
    # GET request - optionally filter by month
    month = request.args.get('month')
    year = request.args.get('year')
    
    conn = get_db()
    c = conn.cursor()
    
    if month and year:
        c.execute('''SELECT * FROM events 
                     WHERE user_id = ? 
                     AND strftime('%Y', start_time) = ? 
                     AND strftime('%m', start_time) = ?
                     ORDER BY start_time ASC''',
                  (session['user_id'], year, month.zfill(2)))
    else:
        c.execute('''SELECT * FROM events 
                     WHERE user_id = ? 
                     ORDER BY start_time ASC''',
                  (session['user_id'],))
    
    events = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify(events)

@app.route('/api/events/<int:event_id>', methods=['DELETE'])
@login_required
def delete_event(event_id):
    """Delete an event"""
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM events WHERE id = ? AND user_id = ?', 
              (event_id, session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

# ===== MODERATION & ADMIN =====
def log_moderation_action(moderator_id, action, target_type, target_id, reason=None):
    """Helper to log moderation actions"""
    conn = get_db()
    c = conn.cursor()
    c.execute('''INSERT INTO moderation_log (moderator_id, action, target_type, target_id, reason)
                 VALUES (?, ?, ?, ?, ?)''', (moderator_id, action, target_type, target_id, reason))
    conn.commit()
    conn.close()

@app.route('/api/admin/users')
@admin_required
def get_all_users():
    """Get all users (admin only)"""
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT users.id, users.username, users.email, users.role, users.banned, 
                 users.banned_reason, users.banned_until, users.created_at,
                 COUNT(DISTINCT posts.id) as post_count,
                 COUNT(DISTINCT forums.id) as forum_count
                 FROM users
                 LEFT JOIN posts ON users.id = posts.user_id AND posts.deleted = 0
                 LEFT JOIN forums ON users.id = forums.user_id AND forums.deleted = 0
                 GROUP BY users.id
                 ORDER BY users.created_at DESC''')
    users = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(users)

@app.route('/api/admin/users/<int:user_id>/role', methods=['POST'])
@admin_required
def change_user_role(user_id):
    """Change user's role (admin only)"""
    data = request.json
    role = data.get('role')
    
    if role not in ['user', 'moderator', 'admin']:
        return jsonify({'error': 'Invalid role'}), 400
    
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE users SET role = ? WHERE id = ?', (role, user_id))
    conn.commit()
    conn.close()
    
    log_moderation_action(session['user_id'], 'role_change', 'user', user_id, f'Changed to {role}')
    
    return jsonify({'success': True})

@app.route('/api/mod/users/<int:user_id>/ban', methods=['POST'])
@mod_required
def ban_user(user_id):
    """Ban a user (moderator+)"""
    data = request.json
    reason = data.get('reason', 'No reason provided')
    duration = data.get('duration')  # in hours, None = permanent
    
    banned_until = None
    if duration:
        from datetime import datetime, timedelta
        banned_until = (datetime.now() + timedelta(hours=int(duration))).isoformat()
    
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE users SET banned = 1, banned_reason = ?, banned_until = ? WHERE id = ?',
              (reason, banned_until, user_id))
    conn.commit()
    conn.close()
    
    log_moderation_action(session['user_id'], 'ban', 'user', user_id, reason)
    
    return jsonify({'success': True})

@app.route('/api/mod/users/<int:user_id>/unban', methods=['POST'])
@mod_required
def unban_user(user_id):
    """Unban a user (moderator+)"""
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE users SET banned = 0, banned_reason = NULL, banned_until = NULL WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    log_moderation_action(session['user_id'], 'unban', 'user', user_id, None)
    
    return jsonify({'success': True})

@app.route('/api/mod/posts/<int:post_id>/delete', methods=['POST'])
@mod_required
def delete_post_mod(post_id):
    """Delete a post (moderator+)"""
    data = request.json
    reason = data.get('reason', 'Violates community guidelines')
    
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE posts SET deleted = 1 WHERE id = ?', (post_id,))
    conn.commit()
    conn.close()
    
    log_moderation_action(session['user_id'], 'delete_post', 'post', post_id, reason)
    
    return jsonify({'success': True})

@app.route('/api/mod/posts/<int:post_id>/pin', methods=['POST'])
@mod_required
def pin_post(post_id):
    """Pin/unpin a post (moderator+)"""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT pinned FROM posts WHERE id = ?', (post_id,))
    post = c.fetchone()
    
    if post:
        new_status = not post['pinned']
        c.execute('UPDATE posts SET pinned = ? WHERE id = ?', (new_status, post_id))
        conn.commit()
        action = 'pin_post' if new_status else 'unpin_post'
        log_moderation_action(session['user_id'], action, 'post', post_id, None)
    
    conn.close()
    return jsonify({'success': True})

@app.route('/api/mod/forums/<int:forum_id>/delete', methods=['POST'])
@mod_required
def delete_forum_mod(forum_id):
    """Delete a forum thread (moderator+)"""
    data = request.json
    reason = data.get('reason', 'Violates community guidelines')
    
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE forums SET deleted = 1 WHERE id = ?', (forum_id,))
    conn.commit()
    conn.close()
    
    log_moderation_action(session['user_id'], 'delete_forum', 'forum', forum_id, reason)
    
    return jsonify({'success': True})

@app.route('/api/mod/forums/<int:forum_id>/lock', methods=['POST'])
@mod_required
def lock_forum(forum_id):
    """Lock/unlock a forum thread (moderator+)"""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT locked FROM forums WHERE id = ?', (forum_id,))
    forum = c.fetchone()
    
    if forum:
        new_status = not forum['locked']
        c.execute('UPDATE forums SET locked = ? WHERE id = ?', (new_status, forum_id))
        conn.commit()
        action = 'lock_forum' if new_status else 'unlock_forum'
        log_moderation_action(session['user_id'], action, 'forum', forum_id, None)
    
    conn.close()
    return jsonify({'success': True})

@app.route('/api/reports', methods=['GET', 'POST'])
@login_required
def reports():
    """Submit or view reports"""
    if request.method == 'POST':
        data = request.json
        item_type = data.get('item_type')
        item_id = data.get('item_id')
        reason = data.get('reason', '').strip()
        
        if not reason:
            return jsonify({'error': 'Reason required'}), 400
        
        conn = get_db()
        c = conn.cursor()
        c.execute('''INSERT INTO reports (reporter_id, item_type, item_id, reason)
                     VALUES (?, ?, ?, ?)''', (session['user_id'], item_type, item_id, reason))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
    
    # GET - moderators only
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()
    
    if not user or user['role'] not in ['moderator', 'admin']:
        conn.close()
        return jsonify({'error': 'Unauthorized'}), 403
    
    status = request.args.get('status', 'pending')
    c.execute('''SELECT reports.*, users.username as reporter_name
                 FROM reports
                 JOIN users ON reports.reporter_id = users.id
                 WHERE reports.status = ?
                 ORDER BY reports.created_at DESC
                 LIMIT 100''', (status,))
    reports_list = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify(reports_list)

@app.route('/api/reports/<int:report_id>/resolve', methods=['POST'])
@mod_required
def resolve_report(report_id):
    """Resolve a report (moderator+)"""
    from datetime import datetime
    
    conn = get_db()
    c = conn.cursor()
    c.execute('''UPDATE reports 
                 SET status = 'resolved', resolved_by = ?, resolved_at = ?
                 WHERE id = ?''',
              (session['user_id'], datetime.now().isoformat(), report_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/mod/logs')
@mod_required
def get_mod_logs():
    """Get moderation logs (moderator+)"""
    limit = request.args.get('limit', 100)
    
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT moderation_log.*, users.username as moderator_name
                 FROM moderation_log
                 JOIN users ON moderation_log.moderator_id = users.id
                 ORDER BY created_at DESC
                 LIMIT ?''', (limit,))
    logs = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify(logs)

@app.route('/api/admin/stats')
@admin_required
def get_admin_stats():
    """Get system statistics (admin only)"""
    conn = get_db()
    c = conn.cursor()
    
    stats = {}
    
    # User stats
    c.execute('SELECT COUNT(*) as count FROM users')
    stats['total_users'] = c.fetchone()['count']
    
    c.execute('SELECT COUNT(*) as count FROM users WHERE banned = 1')
    stats['banned_users'] = c.fetchone()['count']
    
    c.execute('SELECT COUNT(*) as count FROM users WHERE role = "moderator"')
    stats['moderators'] = c.fetchone()['count']
    
    c.execute('SELECT COUNT(*) as count FROM users WHERE role = "admin"')
    stats['admins'] = c.fetchone()['count']
    
    # Content stats
    c.execute('SELECT COUNT(*) as count FROM posts WHERE deleted = 0')
    stats['active_posts'] = c.fetchone()['count']
    
    c.execute('SELECT COUNT(*) as count FROM posts WHERE deleted = 1')
    stats['deleted_posts'] = c.fetchone()['count']
    
    c.execute('SELECT COUNT(*) as count FROM forums WHERE deleted = 0')
    stats['active_forums'] = c.fetchone()['count']
    
    c.execute('SELECT COUNT(*) as count FROM forums WHERE deleted = 1')
    stats['deleted_forums'] = c.fetchone()['count']
    
    c.execute('SELECT COUNT(*) as count FROM forums WHERE locked = 1')
    stats['locked_forums'] = c.fetchone()['count']
    
    c.execute('SELECT COUNT(*) as count FROM reports WHERE status = "pending"')
    stats['pending_reports'] = c.fetchone()['count']
    
    conn.close()
    return jsonify(stats)

@app.route('/api/user/me')
@login_required
def get_current_user_with_role():
    """Get current user info including role"""
    conn = get_db()
    c = cursor()
    c.execute('SELECT id, username, email, role, banned FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()
    conn.close()
    
    if user:
        return jsonify(dict(user))
    return jsonify({'error': 'User not found'}), 404

# ===== GAMES =====
@app.route('/api/games/sessions', methods=['GET', 'POST'])
@login_required
def game_sessions():
    """Get active game sessions or create new session"""
    if request.method == 'POST':
        data = request.json
        game_type = data.get('game_type')
        player2_id = data.get('player2_id')  # Optional for single-player
        
        conn = get_db()
        c = conn.cursor()
        c.execute('''INSERT INTO game_sessions (game_type, player1_id, player2_id, status, state) 
                     VALUES (?, ?, ?, ?, ?)''',
                  (game_type, session['user_id'], player2_id, 'active', '{}'))
        conn.commit()
        session_id = c.lastrowid
        conn.close()
        
        return jsonify({'success': True, 'session_id': session_id})
    
    # GET request - get waiting/active sessions
    game_type = request.args.get('type')
    conn = get_db()
    c = conn.cursor()
    
    if game_type:
        c.execute('''SELECT game_sessions.*, 
                     p1.username as player1_name,
                     p2.username as player2_name
                     FROM game_sessions
                     JOIN users p1 ON game_sessions.player1_id = p1.id
                     LEFT JOIN users p2 ON game_sessions.player2_id = p2.id
                     WHERE game_type = ? AND status IN ('waiting', 'active')
                     ORDER BY created_at DESC LIMIT 20''', (game_type,))
    else:
        c.execute('''SELECT game_sessions.*, 
                     p1.username as player1_name,
                     p2.username as player2_name
                     FROM game_sessions
                     JOIN users p1 ON game_sessions.player1_id = p1.id
                     LEFT JOIN users p2 ON game_sessions.player2_id = p2.id
                     WHERE status IN ('waiting', 'active')
                     ORDER BY created_at DESC LIMIT 20''')
    
    sessions = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify(sessions)

@app.route('/api/games/sessions/<int:session_id>', methods=['GET', 'PUT'])
@login_required
def game_session(session_id):
    """Get or update a game session"""
    conn = get_db()
    c = conn.cursor()
    
    if request.method == 'PUT':
        data = request.json
        state = data.get('state')
        status = data.get('status')
        winner_id = data.get('winner_id')
        
        updates = []
        values = []
        
        if state is not None:
            updates.append('state = ?')
            values.append(json.dumps(state) if isinstance(state, dict) else state)
        if status:
            updates.append('status = ?')
            values.append(status)
        if winner_id is not None:
            updates.append('winner_id = ?')
            values.append(winner_id)
            updates.append('completed_at = CURRENT_TIMESTAMP')
        
        values.extend([session_id])
        
        c.execute(f'''UPDATE game_sessions SET {', '.join(updates)} 
                     WHERE id = ?''', values)
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
    
    # GET request
    c.execute('''SELECT game_sessions.*, 
                 p1.username as player1_name,
                 p2.username as player2_name
                 FROM game_sessions
                 JOIN users p1 ON game_sessions.player1_id = p1.id
                 LEFT JOIN users p2 ON game_sessions.player2_id = p2.id
                 WHERE game_sessions.id = ?''', (session_id,))
    session_data = c.fetchone()
    conn.close()
    
    if session_data:
        result = dict(session_data)
        # Parse JSON state if it exists
        if result.get('state'):
            try:
                result['state'] = json.loads(result['state'])
            except:
                pass
        return jsonify(result)
    
    return jsonify({'error': 'Session not found'}), 404

@app.route('/api/games/sessions/<int:session_id>/join', methods=['POST'])
@login_required
def join_game_session(session_id):
    """Join a waiting game session"""
    conn = get_db()
    c = conn.cursor()
    
    c.execute('SELECT * FROM game_sessions WHERE id = ? AND status = ?', 
              (session_id, 'waiting'))
    game_session = c.fetchone()
    
    if not game_session:
        conn.close()
        return jsonify({'error': 'Session not available'}), 404
    
    c.execute('UPDATE game_sessions SET player2_id = ?, status = ? WHERE id = ?',
              (session['user_id'], 'active', session_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/games/scores', methods=['GET', 'POST'])
@login_required
def game_scores():
    """Submit score or get leaderboard"""
    if request.method == 'POST':
        data = request.json
        game_type = data.get('game_type')
        score = data.get('score')
        level = data.get('level')
        
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO game_scores (user_id, game_type, score, level) VALUES (?, ?, ?, ?)',
                  (session['user_id'], game_type, score, level))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
    
    # GET request - get leaderboard
    game_type = request.args.get('type')
    limit = request.args.get('limit', 10)
    
    conn = get_db()
    c = conn.cursor()
    
    if game_type:
        c.execute('''SELECT game_scores.*, users.username,
                     RANK() OVER (ORDER BY score DESC) as rank
                     FROM game_scores
                     JOIN users ON game_scores.user_id = users.id
                     WHERE game_type = ?
                     ORDER BY score DESC LIMIT ?''', (game_type, limit))
    else:
        c.execute('''SELECT game_scores.*, users.username,
                     RANK() OVER (PARTITION BY game_type ORDER BY score DESC) as rank
                     FROM game_scores
                     JOIN users ON game_scores.user_id = users.id
                     ORDER BY game_type, score DESC LIMIT ?''', (limit,))
    
    scores = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify(scores)

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
        
        /* Notifications */
        .notification-bell {
            position: relative;
            cursor: pointer;
            font-size: 20px;
            padding: 8px;
        }
        
        .notification-badge {
            position: absolute;
            top: 0;
            right: 0;
            background: #f44336;
            color: white;
            border-radius: 50%;
            width: 18px;
            height: 18px;
            font-size: 11px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
        }
        
        .notification-panel {
            position: fixed;
            top: 70px;
            right: 20px;
            width: 350px;
            max-height: 500px;
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            display: none;
            flex-direction: column;
            z-index: 1000;
        }
        
        .notification-panel.show {
            display: flex;
        }
        
        @media (max-width: 768px) {
            .notification-panel {
                right: 10px;
                left: 10px;
                width: auto;
            }
        }
        
        .notification-header {
            padding: 15px;
            border-bottom: 1px solid #e0e0e0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .notification-header h3 {
            font-size: 16px;
        }
        
        .mark-all-read {
            color: #667eea;
            font-size: 12px;
            cursor: pointer;
        }
        
        .notification-list {
            flex: 1;
            overflow-y: auto;
            max-height: 400px;
        }
        
        .notification-item {
            padding: 15px;
            border-bottom: 1px solid #f0f0f0;
            cursor: pointer;
            transition: background 0.2s;
        }
        
        .notification-item:hover {
            background: #f8f8f8;
        }
        
        .notification-item.unread {
            background: #f0f0ff;
        }
        
        .notification-title {
            font-weight: 600;
            color: #333;
            margin-bottom: 5px;
        }
        
        .notification-message {
            color: #666;
            font-size: 13px;
            margin-bottom: 5px;
        }
        
        .notification-time {
            color: #999;
            font-size: 11px;
        }
        
        /* Call UI */
        .call-modal {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.8);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 2000;
        }
        
        .call-modal.show {
            display: flex;
        }
        
        .call-container {
            background: #2c2c2c;
            border-radius: 20px;
            padding: 40px;
            text-align: center;
            max-width: 500px;
            width: 90%;
        }
        
        .call-avatar {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0 auto 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 48px;
            color: white;
        }
        
        .call-username {
            font-size: 28px;
            color: white;
            margin-bottom: 10px;
        }
        
        .call-status {
            color: #aaa;
            margin-bottom: 30px;
        }
        
        .call-timer {
            color: #667eea;
            font-size: 18px;
            margin-bottom: 20px;
        }
        
        .call-buttons {
            display: flex;
            gap: 20px;
            justify-content: center;
        }
        
        .call-btn {
            width: 60px;
            height: 60px;
            border-radius: 50%;
            border: none;
            font-size: 24px;
            cursor: pointer;
            transition: transform 0.2s;
        }
        
        .call-btn:hover {
            transform: scale(1.1);
        }
        
        .call-btn-answer {
            background: #4caf50;
            color: white;
        }
        
        .call-btn-reject, .call-btn-end {
            background: #f44336;
            color: white;
        }
        
        .call-btn-mute {
            background: #555;
            color: white;
        }
        
        .call-btn-video {
            background: #667eea;
            color: white;
        }
        
        .video-container {
            position: relative;
            width: 100%;
            max-width: 800px;
            margin: 20px auto;
        }
        
        .video-main {
            width: 100%;
            border-radius: 12px;
            background: #000;
        }
        
        .video-self {
            position: absolute;
            bottom: 20px;
            right: 20px;
            width: 150px;
            border-radius: 8px;
            border: 2px solid white;
        }
        
        @media (max-width: 768px) {
            .call-container {
                padding: 30px 20px;
            }
            
            .call-avatar {
                width: 100px;
                height: 100px;
                font-size: 40px;
            }
            
            .call-username {
                font-size: 22px;
            }
            
            .video-self {
                width: 100px;
                bottom: 10px;
                right: 10px;
            }
        }
        
        /* Online status indicator */
        .status-indicator {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 5px;
        }
        
        .status-online {
            background: #4caf50;
        }
        
        .status-offline {
            background: #999;
        }
        
        .status-in-call {
            background: #ff9800;
        }
        
        /* Call button in user list */
        .user-call-btn {
            padding: 4px 10px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 11px;
            cursor: pointer;
            margin-left: 10px;
        }
        
        /* Games */
        .game-card {
            background: white;
            padding: 20px;
            border-radius: 12px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s;
            border: 2px solid #e0e0e0;
        }
        
        .game-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            border-color: #667eea;
        }
        
        .game-icon {
            font-size: 48px;
            margin-bottom: 10px;
        }
        
        .game-card h3 {
            color: #333;
            margin-bottom: 5px;
        }
        
        .game-card p {
            color: #999;
            font-size: 13px;
            margin-bottom: 10px;
        }
        
        .game-badge {
            display: inline-block;
            padding: 3px 10px;
            background: #4caf50;
            color: white;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
        }
        
        .game-badge.multiplayer {
            background: #ff9800;
        }
        
        #canvas {
            background: #f5f5f5;
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
                <div class="notification-bell" onclick="toggleNotifications()">
                    🔔
                    <span id="notificationBadge" class="notification-badge" style="display: none;">0</span>
                </div>
                <span>Welcome, <strong id="currentUsername"></strong>!</span>
                <button class="logout-btn" onclick="logout()">Logout</button>
            </div>
        </div>
        
        <!-- Notification Panel -->
        <div id="notificationPanel" class="notification-panel">
            <div class="notification-header">
                <h3>Notifications</h3>
                <span class="mark-all-read" onclick="markAllRead()">Mark all read</span>
            </div>
            <div id="notificationList" class="notification-list"></div>
        </div>
        
        <div class="app-main">
            <div class="sidebar-overlay" id="sidebarOverlay" onclick="toggleMobileMenu()"></div>
            <div class="sidebar" id="sidebar">
                <div class="nav-item active" onclick="showPanel('discover')">🔍 Discover</div>
                <div class="nav-item" onclick="showPanel('posts')">🐦 Posts</div>
                <div class="nav-item" onclick="showPanel('forums')">💬 Forums</div>
                <div class="nav-item" onclick="showPanel('chat')">💭 Chat</div>
                <div class="nav-item" onclick="showPanel('photos')">📷 Photos</div>
                <div class="nav-item" onclick="showPanel('streaming')">📺 Live</div>
                <div class="nav-item" onclick="showPanel('media')">🎬 Media</div>
                <div class="nav-item" onclick="showPanel('games')">🎮 Games</div>
                <div class="nav-item" onclick="showPanel('pastebin')">📋 Pastebin</div>
                <div class="nav-item" onclick="showPanel('notes')">📝 Notes</div>
                <div class="nav-item" onclick="showPanel('tasks')">✅ Tasks</div>
                <div class="nav-item" onclick="showPanel('calendar')">📅 Calendar</div>
                <div class="nav-item" onclick="showPanel('files')">📁 Files</div>
                <div class="nav-item" id="adminNavItem" onclick="showPanel('admin')" style="display: none;">🛡️ Admin</div>
            </div>
            <button class="mobile-menu-btn" id="mobileMenuBtn" onclick="toggleMobileMenu()">☰</button>
            
            <div class="content">
                <!-- Discover Panel -->
                <div id="discoverPanel" class="panel active">
                    <div class="card">
                        <h2>🎉 Welcome to LAN World!</h2>
                        <p>Your complete digital ecosystem, running entirely on your local network. No internet connection required!</p>
                        <br>
                        <h3>📱 Social & Communication:</h3>
                        <ul style="margin-left: 20px; margin-top: 10px; line-height: 1.8;">
                            <li><strong>🐦 Posts</strong> - Share quick updates and thoughts (Twitter-style)</li>
                            <li><strong>💬 Forums</strong> - Start discussions and engage in threads (Reddit-style)</li>
                            <li><strong>💭 Chat</strong> - Real-time messaging, DMs, voice & video calls (Discord-style)</li>
                            <li><strong>📷 Photos</strong> - Share photos with filters, likes & comments (Instagram-style)</li>
                        </ul>
                        <br>
                        <h3>🎬 Media & Entertainment:</h3>
                        <ul style="margin-left: 20px; margin-top: 10px; line-height: 1.8;">
                            <li><strong>📺 Live Streaming</strong> - Broadcast live to your network (Twitch-style)</li>
                            <li><strong>🎬 Media Library</strong> - Stream videos and music</li>
                            <li><strong>🎮 Games</strong> - 6 single-player and multiplayer games with leaderboards!</li>
                        </ul>
                        <br>
                        <h3>🛠️ Productivity & Tools:</h3>
                        <ul style="margin-left: 20px; margin-top: 10px; line-height: 1.8;">
                            <li><strong>📋 Pastebin</strong> - Share code snippets with syntax highlighting</li>
                            <li><strong>📝 Notes</strong> - Personal note-taking with colors and pinning</li>
                            <li><strong>✅ Tasks</strong> - Todo lists and task management</li>
                            <li><strong>📅 Calendar</strong> - Events and scheduling</li>
                            <li><strong>📁 Files</strong> - Upload and download any files</li>
                        </ul>
                        <br>
                        <h3>🔔 Core Features:</h3>
                        <ul style="margin-left: 20px; margin-top: 10px; line-height: 1.8;">
                            <li>📞 Voice & video calls with anyone on the network</li>
                            <li>🔔 Real-time notifications for all activities</li>
                            <li>🎮 Gaming arcade with 6 fun games</li>
                            <li>📱 Fully mobile-responsive design</li>
                            <li>🔒 All data stored locally and private</li>
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
                
                <!-- Photos Panel (Instagram-style) -->
                <div id="photosPanel" class="panel">
                    <div class="card">
                        <h2>📷 Upload Photo</h2>
                        <div class="input-group">
                            <label>Caption</label>
                            <input type="text" id="photoCaption" placeholder="Write a caption...">
                        </div>
                        <div class="input-group">
                            <label>Filter</label>
                            <select id="photoFilter">
                                <option value="none">None</option>
                                <option value="grayscale">Grayscale</option>
                                <option value="sepia">Sepia</option>
                                <option value="vintage">Vintage</option>
                                <option value="cool">Cool</option>
                            </select>
                        </div>
                        <div class="input-group">
                            <label>Photo</label>
                            <input type="file" id="photoFile" accept="image/*">
                        </div>
                        <button class="submit-btn" onclick="uploadPhoto()">Share Photo</button>
                    </div>
                    <div id="photoGrid" class="media-grid"></div>
                </div>
                
                <!-- Live Streaming Panel -->
                <div id="streamingPanel" class="panel">
                    <div class="card">
                        <h2>📺 Go Live</h2>
                        <div id="streamControls">
                            <div class="input-group">
                                <label>Stream Title</label>
                                <input type="text" id="streamTitle" placeholder="What are you streaming?">
                            </div>
                            <div class="input-group">
                                <label>Description</label>
                                <textarea id="streamDescription" style="min-height: 60px;" placeholder="Tell viewers what to expect..."></textarea>
                            </div>
                            <button class="submit-btn" onclick="startStream()">🔴 Start Streaming</button>
                        </div>
                        <div id="streamView" style="display: none;">
                            <video id="streamVideo" autoplay playsinline style="width: 100%; border-radius: 12px; background: #000;"></video>
                            <div style="margin-top: 15px; text-align: center;">
                                <span style="color: red; font-size: 18px;">● LIVE</span>
                                <span style="margin-left: 15px;">👁️ <span id="viewerCount">0</span> viewers</span>
                                <button class="submit-btn" onclick="endStreamSession()" style="margin-left: 15px; background: #f44336;">End Stream</button>
                            </div>
                        </div>
                    </div>
                    <h3 style="margin: 20px 0;">Live Now:</h3>
                    <div id="liveStreams"></div>
                </div>
                
                <!-- Pastebin Panel -->
                <div id="pastebinPanel" class="panel">
                    <div class="card">
                        <h2>📋 Create Paste</h2>
                        <div class="input-group">
                            <label>Title</label>
                            <input type="text" id="pasteTitle" placeholder="Untitled">
                        </div>
                        <div class="input-group">
                            <label>Language</label>
                            <select id="pasteLanguage">
                                <option value="text">Plain Text</option>
                                <option value="python">Python</option>
                                <option value="javascript">JavaScript</option>
                                <option value="html">HTML</option>
                                <option value="css">CSS</option>
                                <option value="java">Java</option>
                                <option value="cpp">C++</option>
                                <option value="json">JSON</option>
                                <option value="sql">SQL</option>
                                <option value="bash">Bash</option>
                            </select>
                        </div>
                        <div class="input-group">
                            <label>Content</label>
                            <textarea id="pasteContent" style="min-height: 200px; font-family: monospace;" placeholder="Paste your code or text here..."></textarea>
                        </div>
                        <label style="display: flex; align-items: center; gap: 10px; margin-bottom: 15px;">
                            <input type="checkbox" id="pastePublic" checked>
                            <span>Public (visible to everyone)</span>
                        </label>
                        <button class="submit-btn" onclick="createPaste()">Create Paste</button>
                    </div>
                    <h3 style="margin: 20px 0;">Recent Pastes:</h3>
                    <div id="pastesList"></div>
                </div>
                
                <!-- Notes Panel -->
                <div id="notesPanel" class="panel">
                    <div class="card">
                        <h2>📝 New Note</h2>
                        <div class="input-group">
                            <label>Title</label>
                            <input type="text" id="noteTitle" placeholder="Note title">
                        </div>
                        <div class="input-group">
                            <label>Color</label>
                            <select id="noteColor">
                                <option value="#ffd700">Yellow</option>
                                <option value="#ff9999">Pink</option>
                                <option value="#99ccff">Blue</option>
                                <option value="#99ff99">Green</option>
                                <option value="#ffcc99">Orange</option>
                                <option value="#cc99ff">Purple</option>
                            </select>
                        </div>
                        <div class="input-group">
                            <label>Content</label>
                            <textarea id="noteContent" style="min-height: 120px;" placeholder="Write your note..."></textarea>
                        </div>
                        <button class="submit-btn" onclick="createNote()">Create Note</button>
                    </div>
                    <h3 style="margin: 20px 0;">My Notes:</h3>
                    <div id="notesGrid" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 15px;"></div>
                </div>
                
                <!-- Tasks Panel -->
                <div id="tasksPanel" class="panel">
                    <div class="card">
                        <h2>✅ New Task</h2>
                        <div class="input-group">
                            <label>Task</label>
                            <input type="text" id="taskTitle" placeholder="What needs to be done?">
                        </div>
                        <div class="input-group">
                            <label>Description (optional)</label>
                            <textarea id="taskDescription" style="min-height: 60px;" placeholder="Additional details..."></textarea>
                        </div>
                        <div class="input-group">
                            <label>Priority</label>
                            <select id="taskPriority">
                                <option value="low">Low</option>
                                <option value="medium" selected>Medium</option>
                                <option value="high">High</option>
                            </select>
                        </div>
                        <div class="input-group">
                            <label>Due Date (optional)</label>
                            <input type="datetime-local" id="taskDueDate">
                        </div>
                        <button class="submit-btn" onclick="createTask()">Add Task</button>
                    </div>
                    <h3 style="margin: 20px 0;">My Tasks:</h3>
                    <div id="tasksList"></div>
                </div>
                
                <!-- Calendar Panel -->
                <div id="calendarPanel" class="panel">
                    <div class="card">
                        <h2>📅 New Event</h2>
                        <div class="input-group">
                            <label>Event Title</label>
                            <input type="text" id="eventTitle" placeholder="Event name">
                        </div>
                        <div class="input-group">
                            <label>Description</label>
                            <textarea id="eventDescription" style="min-height: 60px;" placeholder="Event details..."></textarea>
                        </div>
                        <div class="input-group">
                            <label>Location (optional)</label>
                            <input type="text" id="eventLocation" placeholder="Where is it?">
                        </div>
                        <div class="input-group">
                            <label>Start Time</label>
                            <input type="datetime-local" id="eventStart">
                        </div>
                        <div class="input-group">
                            <label>End Time (optional)</label>
                            <input type="datetime-local" id="eventEnd">
                        </div>
                        <label style="display: flex; align-items: center; gap: 10px; margin-bottom: 15px;">
                            <input type="checkbox" id="eventAllDay">
                            <span>All-day event</span>
                        </label>
                        <div class="input-group">
                            <label>Color</label>
                            <input type="color" id="eventColor" value="#667eea">
                        </div>
                        <button class="submit-btn" onclick="createEvent()">Create Event</button>
                    </div>
                    <h3 style="margin: 20px 0;">Upcoming Events:</h3>
                    <div id="eventsList"></div>
                </div>
                
                <!-- Games Panel -->
                <div id="gamesPanel" class="panel">
                    <div id="gameMenu" class="card">
                        <h2>🎮 Game Arcade</h2>
                        <p style="margin-bottom: 20px; color: #666;">Choose a game to play solo or challenge others!</p>
                        
                        <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 15px;">
                            <div class="game-card" onclick="startGame('snake')">
                                <div class="game-icon">🐍</div>
                                <h3>Snake</h3>
                                <p>Classic single-player</p>
                                <span class="game-badge">Solo</span>
                            </div>
                            
                            <div class="game-card" onclick="startGame('2048')">
                                <div class="game-icon">🔢</div>
                                <h3>2048</h3>
                                <p>Puzzle challenge</p>
                                <span class="game-badge">Solo</span>
                            </div>
                            
                            <div class="game-card" onclick="startGame('tictactoe')">
                                <div class="game-icon">⭕</div>
                                <h3>Tic-Tac-Toe</h3>
                                <p>Classic strategy</p>
                                <span class="game-badge multiplayer">Multiplayer</span>
                            </div>
                            
                            <div class="game-card" onclick="startGame('pong')">
                                <div class="game-icon">🏓</div>
                                <h3>Pong</h3>
                                <p>Classic arcade</p>
                                <span class="game-badge multiplayer">Multiplayer</span>
                            </div>
                            
                            <div class="game-card" onclick="startGame('memory')">
                                <div class="game-icon">🎴</div>
                                <h3>Memory</h3>
                                <p>Card matching</p>
                                <span class="game-badge">Solo</span>
                            </div>
                            
                            <div class="game-card" onclick="startGame('trivia')">
                                <div class="game-icon">🧠</div>
                                <h3>Trivia</h3>
                                <p>Test your knowledge</p>
                                <span class="game-badge multiplayer">Multiplayer</span>
                            </div>
                        </div>
                        
                        <h3 style="margin-top: 30px;">🏆 Leaderboards</h3>
                        <div id="leaderboardsList"></div>
                    </div>
                    
                    <!-- Game Container (hidden by default) -->
                    <div id="gameContainer" style="display: none;">
                        <div class="card">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                                <h2 id="gameTitle">Game</h2>
                                <button class="submit-btn" onclick="exitGame()" style="background: #999;">← Back to Menu</button>
                            </div>
                            
                            <div style="display: flex; justify-content: space-between; margin-bottom: 15px;">
                                <div>Score: <strong id="gameScore">0</strong></div>
                                <div id="gameInfo"></div>
                            </div>
                            
                            <div id="gameCanvas" style="display: flex; justify-content: center;">
                                <canvas id="canvas" style="border: 2px solid #667eea; border-radius: 8px; max-width: 100%;"></canvas>
                            </div>
                            
                            <div id="gameControls" style="margin-top: 15px; text-align: center;">
                                <button class="submit-btn" id="gameButton" onclick="gameAction()">Start</button>
                            </div>
                            
                            <div id="gameInstructions" style="margin-top: 15px; padding: 15px; background: #f5f5f5; border-radius: 8px;">
                                <strong>Instructions:</strong>
                                <p id="instructionsText">Loading...</p>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Admin Panel -->
                <div id="adminPanel" class="panel">
                    <div class="card">
                        <h2>🛡️ Administration</h2>
                        <p id="adminRole" style="color: #666;"></p>
                    </div>
                    
                    <!-- Tabs -->
                    <div style="display: flex; gap: 10px; margin: 20px 0; flex-wrap: wrap;">
                        <button class="submit-btn" onclick="showAdminTab('users')" id="adminTabUsers">👥 Users</button>
                        <button class="submit-btn" onclick="showAdminTab('reports')" id="adminTabReports">🚩 Reports</button>
                        <button class="submit-btn" onclick="showAdminTab('logs')" id="adminTabLogs">📋 Mod Logs</button>
                        <button class="submit-btn" onclick="showAdminTab('stats')" id="adminTabStats" style="display: none;">📊 Stats</button>
                    </div>
                    
                    <!-- Users Tab -->
                    <div id="adminUsers" style="display: none;">
                        <div id="usersList"></div>
                    </div>
                    
                    <!-- Reports Tab -->
                    <div id="adminReports" style="display: none;">
                        <div id="reportsList"></div>
                    </div>
                    
                    <!-- Logs Tab -->
                    <div id="adminLogs" style="display: none;">
                        <div id="logsList"></div>
                    </div>
                    
                    <!-- Stats Tab (Admin only) -->
                    <div id="adminStats" style="display: none;">
                        <div id="statsDisplay"></div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Call Modal -->
    <div id="callModal" class="call-modal">
        <div class="call-container">
            <div class="video-container" id="videoContainer" style="display: none;">
                <video id="remoteVideo" class="video-main" autoplay playsinline></video>
                <video id="localVideo" class="video-self" autoplay playsinline muted></video>
            </div>
            <div class="call-avatar" id="callAvatar">👤</div>
            <div class="call-username" id="callUsername">User</div>
            <div class="call-status" id="callStatus">Connecting...</div>
            <div class="call-timer" id="callTimer" style="display: none;">00:00</div>
            <div class="call-buttons" id="callButtons">
                <button class="call-btn call-btn-answer" id="answerBtn" onclick="answerCall()" style="display: none;">📞</button>
                <button class="call-btn call-btn-reject" id="rejectBtn" onclick="rejectCall()" style="display: none;">✖️</button>
                <button class="call-btn call-btn-mute" id="muteBtn" onclick="toggleMute()" style="display: none;">🎤</button>
                <button class="call-btn call-btn-video" id="videoBtn" onclick="toggleVideo()" style="display: none;">📹</button>
                <button class="call-btn call-btn-end" id="endBtn" onclick="endCall()">📵</button>
            </div>
        </div>
    </div>
    
    <script>
        let currentUser = null;
        let currentChatMode = 'channel';
        let currentChannel = 'general';
        let currentRecipient = null;
        let refreshInterval = null;
        let notificationInterval = null;
        let callCheckInterval = null;
        
        // Call variables
        let currentCall = null;
        let localStream = null;
        let peerConnection = null;
        let callStartTime = null;
        let callTimerInterval = null;
        let isMuted = false;
        let isVideoOn = true;

        function showLogin() {
            document.getElementById('loginForm').style.display = 'block';
            document.getElementById('signupForm').style.display = 'none';
        }

        function showSignup() {
            document.getElementById('loginForm').style.display = 'none';
            document.getElementById('signupForm').style.display = 'block';
        }
        
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
            await updateUserStatus('offline');
            await fetch('/api/logout', {method: 'POST'});
            clearInterval(refreshInterval);
            clearInterval(notificationInterval);
            document.getElementById('authContainer').style.display = 'flex';
            document.getElementById('appContainer').style.display = 'none';
            currentUser = null;
        }
        
        function showApp() {
            document.getElementById('authContainer').style.display = 'none';
            const appContainer = document.getElementById('appContainer');
            appContainer.style.display = 'flex';
            document.getElementById('currentUsername').textContent = currentUser.username;
            
            // Check user role and permissions
            checkUserRole();
            
            // Request notification permission
            requestNotificationPermission();
            
            // Update user status to online
            updateUserStatus('online');
            
            // Load initial data
            loadPosts();
            loadForums();
            loadUsers();
            loadMedia();
            loadFiles();
            loadMessages();
            loadNotifications();
            
            // Auto-refresh
            refreshInterval = setInterval(() => {
                loadMessages();
            }, 3000);
            
            // Check notifications every 10 seconds
            notificationInterval = setInterval(() => {
                loadNotifications();
            }, 10000);
            
            // Update status every minute
            setInterval(() => {
                updateUserStatus('online');
            }, 60000);
        }
        
        function showPanel(panelName) {
            document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            
            document.getElementById(panelName + 'Panel').classList.add('active');
            event.target.classList.add('active');
            
            // Close mobile menu
            closeMobileMenu();
            
            // Exit any active game when leaving games panel
            if (panelName !== 'games' && currentGame) {
                exitGame();
            }
            
            // Load panel data
            if (panelName === 'posts') loadPosts();
            if (panelName === 'forums') loadForums();
            if (panelName === 'chat') loadMessages();
            if (panelName === 'media') loadMedia();
            if (panelName === 'files') loadFiles();
            if (panelName === 'photos') loadPhotos();
            if (panelName === 'streaming') loadStreams();
            if (panelName === 'pastebin') loadPastes();
            if (panelName === 'notes') loadNotes();
            if (panelName === 'tasks') loadTasks();
            if (panelName === 'calendar') loadEvents();
            if (panelName === 'games') loadLeaderboards();
            if (panelName === 'admin') showAdminTab(currentAdminTab);
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
                <div class="post" style="${post.pinned ? 'border-left: 4px solid #667eea;' : ''}">
                    <div class="post-header">
                        <span class="post-author">
                            ${post.pinned ? '📌 ' : ''}@${post.username}
                        </span>
                        <span class="post-time">${new Date(post.created_at).toLocaleString()}</span>
                    </div>
                    <div class="post-content">${post.content}</div>
                    <div class="post-actions">
                        <span class="like-btn" onclick="likePost(${post.id})">
                            ❤️ ${post.likes} likes
                        </span>
                        <span class="like-btn" onclick="togglePostComments(${post.id})">
                            💬 ${post.comment_count || 0} replies
                        </span>
                        <span class="like-btn" onclick="reportContent('post', ${post.id})">
                            🚩 Report
                        </span>
                        ${userRole === 'moderator' || userRole === 'admin' ? `
                            <span class="like-btn" onclick="pinPost(${post.id})" style="color: #667eea;">
                                ${post.pinned ? '📍 Unpin' : '📌 Pin'}
                            </span>
                            <span class="like-btn" onclick="deletePost(${post.id})" style="color: #f44336;">
                                🗑️ Delete
                            </span>
                        ` : ''}
                    </div>
                    <div id="comments-${post.id}" style="display: none; margin-top: 15px; padding-top: 15px; border-top: 1px solid #e0e0e0;">
                        <div id="comments-list-${post.id}" style="margin-bottom: 10px;"></div>
                        <div style="display: flex; gap: 10px;">
                            <input type="text" id="comment-input-${post.id}" placeholder="Write a reply..." style="flex: 1; padding: 8px; border: 1px solid #e0e0e0; border-radius: 6px;" onkeypress="if(event.key==='Enter') addPostComment(${post.id})">
                            <button onclick="addPostComment(${post.id})" style="padding: 8px 16px; background: #667eea; color: white; border: none; border-radius: 6px; cursor: pointer;">Reply</button>
                        </div>
                    </div>
                </div>
            `).join('');
        }
        
        async function togglePostComments(postId) {
            const commentsDiv = document.getElementById(`comments-${postId}`);
            const isVisible = commentsDiv.style.display !== 'none';
            
            if (isVisible) {
                commentsDiv.style.display = 'none';
            } else {
                commentsDiv.style.display = 'block';
                await loadPostComments(postId);
            }
        }
        
        async function loadPostComments(postId) {
            const res = await fetch(`/api/posts/${postId}/comments`);
            const comments = await res.json();
            
            const commentsList = document.getElementById(`comments-list-${postId}`);
            if (comments.length === 0) {
                commentsList.innerHTML = '<p style="color: #999; font-size: 13px;">No comments yet. Be the first!</p>';
            } else {
                commentsList.innerHTML = comments.map(comment => `
                    <div style="padding: 10px; background: #f8f8f8; border-radius: 6px; margin-bottom: 8px;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                            <strong style="font-size: 13px;">@${comment.username}</strong>
                            <span style="color: #999; font-size: 11px;">${new Date(comment.created_at).toLocaleString()}</span>
                        </div>
                        <p style="font-size: 14px;">${comment.content}</p>
                    </div>
                `).join('');
            }
        }
        
        async function addPostComment(postId) {
            const input = document.getElementById(`comment-input-${postId}`);
            const content = input.value.trim();
            
            if (!content) return;
            
            await fetch(`/api/posts/${postId}/comments`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content })
            });
            
            input.value = '';
            await loadPostComments(postId);
            loadPosts(); // Refresh to update comment count
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
                <div class="post" style="${forum.locked ? 'border-left: 4px solid #f44336;' : ''}">
                    <div class="post-header">
                        <div>
                            <strong style="font-size: 18px;">
                                ${forum.locked ? '🔒 ' : ''}${forum.title}
                            </strong>
                            <span style="background: #667eea; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; margin-left: 10px;">
                                ${forum.category}
                            </span>
                        </div>
                        <span class="post-time">${new Date(forum.created_at).toLocaleString()}</span>
                    </div>
                    <div class="post-content">${forum.content}</div>
                    <div class="post-actions">
                        <span>👤 ${forum.username}</span>
                        <span class="like-btn" onclick="likeForum(${forum.id})">❤️ ${forum.likes} likes</span>
                        <span class="like-btn" onclick="toggleForumComments(${forum.id})">💬 ${forum.comment_count} comments</span>
                        <span class="like-btn" onclick="reportContent('forum', ${forum.id})">
                            🚩 Report
                        </span>
                        ${userRole === 'moderator' || userRole === 'admin' ? `
                            <span class="like-btn" onclick="lockForum(${forum.id})" style="color: #ff9800;">
                                ${forum.locked ? '🔓 Unlock' : '🔒 Lock'}
                            </span>
                            <span class="like-btn" onclick="deleteForum(${forum.id})" style="color: #f44336;">
                                🗑️ Delete
                            </span>
                        ` : ''}
                    </div>
                    ${forum.locked ? '<div style="padding: 10px; background: #fff3cd; border-radius: 6px; margin-top: 10px; font-size: 13px;">🔒 This thread is locked. Only moderators can add new comments.</div>' : ''}
                    <div id="forum-comments-${forum.id}" style="display: none; margin-top: 15px; padding-top: 15px; border-top: 1px solid #e0e0e0;">
                        <div id="forum-comments-list-${forum.id}" style="margin-bottom: 10px;"></div>
                        ${!forum.locked || userRole === 'moderator' || userRole === 'admin' ? `
                            <div style="display: flex; gap: 10px;">
                                <input type="text" id="forum-comment-input-${forum.id}" placeholder="Write a comment..." style="flex: 1; padding: 8px; border: 1px solid #e0e0e0; border-radius: 6px;" onkeypress="if(event.key==='Enter') addForumCommentNew(${forum.id})">
                                <button onclick="addForumCommentNew(${forum.id})" style="padding: 8px 16px; background: #667eea; color: white; border: none; border-radius: 6px; cursor: pointer;">Comment</button>
                            </div>
                        ` : '<div style="color: #999; text-align: center; padding: 10px;">This thread is locked</div>'}
                    </div>
                </div>
            `).join('');
        }
        
        async function likeForum(forumId) {
            await fetch(`/api/forums/${forumId}/like`, { method: 'POST' });
            loadForums();
        }
        
        async function toggleForumComments(forumId) {
            const commentsDiv = document.getElementById(`forum-comments-${forumId}`);
            const isVisible = commentsDiv.style.display !== 'none';
            
            if (isVisible) {
                commentsDiv.style.display = 'none';
            } else {
                commentsDiv.style.display = 'block';
                await loadForumComments(forumId);
            }
        }
        
        async function loadForumComments(forumId) {
            const res = await fetch(`/api/forums/${forumId}`);
            const data = await res.json();
            
            const commentsList = document.getElementById(`forum-comments-list-${forumId}`);
            if (data.comments.length === 0) {
                commentsList.innerHTML = '<p style="color: #999; font-size: 13px;">No comments yet. Start the discussion!</p>';
            } else {
                commentsList.innerHTML = data.comments.map(comment => `
                    <div style="padding: 10px; background: #f8f8f8; border-radius: 6px; margin-bottom: 8px;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                            <strong style="font-size: 13px;">@${comment.username}</strong>
                            <span style="color: #999; font-size: 11px;">${new Date(comment.created_at).toLocaleString()}</span>
                        </div>
                        <p style="font-size: 14px;">${comment.content}</p>
                    </div>
                `).join('');
            }
        }
        
        async function addForumCommentNew(forumId) {
            const input = document.getElementById(`forum-comment-input-${forumId}`);
            const content = input.value.trim();
            
            if (!content) return;
            
            await fetch(`/api/forums/${forumId}/comments`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content })
            });
            
            input.value = '';
            await loadForumComments(forumId);
            loadForums(); // Refresh to update comment count
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
        
        // ===== NOTIFICATIONS =====
        async function loadNotifications() {
            try {
                const res = await fetch('/api/notifications');
                const notifications = await res.json();
                
                const list = document.getElementById('notificationList');
                if (notifications.length === 0) {
                    list.innerHTML = '<div style="padding: 20px; text-align: center; color: #999;">No notifications</div>';
                } else {
                    list.innerHTML = notifications.map(notif => `
                        <div class="notification-item ${notif.read ? '' : 'unread'}" onclick="handleNotificationClick(${notif.id}, '${notif.link || ''}')">
                            <div class="notification-title">${notif.title}</div>
                            <div class="notification-message">${notif.message}</div>
                            <div class="notification-time">${new Date(notif.created_at).toLocaleString()}</div>
                        </div>
                    `).join('');
                }
                
                // Update badge
                const unreadRes = await fetch('/api/notifications/unread-count');
                const unreadData = await unreadRes.json();
                const badge = document.getElementById('notificationBadge');
                if (unreadData.count > 0) {
                    badge.textContent = unreadData.count > 99 ? '99+' : unreadData.count;
                    badge.style.display = 'flex';
                } else {
                    badge.style.display = 'none';
                }
            } catch (e) {
                console.error('Failed to load notifications:', e);
            }
        }
        
        function toggleNotifications() {
            const panel = document.getElementById('notificationPanel');
            panel.classList.toggle('show');
            if (panel.classList.contains('show')) {
                loadNotifications();
            }
        }
        
        async function handleNotificationClick(notificationId, link) {
            await fetch(`/api/notifications/${notificationId}/read`, { method: 'POST' });
            loadNotifications();
            if (link) {
                // Handle notification links (like call links)
                console.log('Navigating to:', link);
            }
        }
        
        async function markAllRead() {
            await fetch('/api/notifications/mark-all-read', { method: 'POST' });
            loadNotifications();
        }
        
        // Request browser notification permission
        function requestNotificationPermission() {
            if ('Notification' in window && Notification.permission === 'default') {
                Notification.requestPermission();
            }
        }
        
        function showBrowserNotification(title, body) {
            if ('Notification' in window && Notification.permission === 'granted') {
                new Notification(title, {
                    body: body,
                    icon: '🌐',
                    badge: '🔔'
                });
            }
        }
        
        // ===== CALLS =====
        async function initiateCall(userId, username, callType = 'video') {
            try {
                const res = await fetch('/api/calls/initiate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ receiver_id: userId, call_type: callType })
                });
                
                const data = await res.json();
                if (res.ok) {
                    currentCall = { id: data.call_id, type: callType, role: 'caller' };
                    showCallUI(username, callType, 'calling');
                    
                    // For demo purposes, we'll use a simple audio call
                    // In production, you'd implement WebRTC here
                    if (callType === 'audio' || callType === 'video') {
                        await startLocalMedia(callType === 'video');
                    }
                }
            } catch (e) {
                console.error('Failed to initiate call:', e);
                alert('Failed to initiate call');
            }
        }
        
        async function startLocalMedia(includeVideo = false) {
            try {
                const constraints = {
                    audio: true,
                    video: includeVideo
                };
                
                localStream = await navigator.mediaDevices.getUserMedia(constraints);
                
                if (includeVideo) {
                    document.getElementById('videoContainer').style.display = 'block';
                    document.getElementById('localVideo').srcObject = localStream;
                    document.getElementById('callAvatar').style.display = 'none';
                }
                
                // Show controls
                document.getElementById('muteBtn').style.display = 'block';
                if (includeVideo) {
                    document.getElementById('videoBtn').style.display = 'block';
                }
            } catch (e) {
                console.error('Failed to get media:', e);
                alert('Could not access camera/microphone');
            }
        }
        
        function showCallUI(username, callType, status) {
            document.getElementById('callUsername').textContent = username;
            document.getElementById('callStatus').textContent = status;
            document.getElementById('callModal').classList.add('show');
            
            if (currentCall && currentCall.role === 'receiver') {
                document.getElementById('answerBtn').style.display = 'block';
                document.getElementById('rejectBtn').style.display = 'block';
            }
        }
        
        async function answerCall() {
            if (!currentCall) return;
            
            try {
                await fetch(`/api/calls/${currentCall.id}/answer`, { method: 'POST' });
                
                document.getElementById('answerBtn').style.display = 'none';
                document.getElementById('rejectBtn').style.display = 'none';
                document.getElementById('callStatus').textContent = 'Connected';
                
                // Start call timer
                callStartTime = Date.now();
                callTimerInterval = setInterval(updateCallTimer, 1000);
                document.getElementById('callTimer').style.display = 'block';
                
                // Start media
                await startLocalMedia(currentCall.type === 'video');
            } catch (e) {
                console.error('Failed to answer call:', e);
            }
        }
        
        async function rejectCall() {
            if (!currentCall) return;
            
            try {
                await fetch(`/api/calls/${currentCall.id}/reject`, { method: 'POST' });
                closeCallUI();
            } catch (e) {
                console.error('Failed to reject call:', e);
            }
        }
        
        async function endCall() {
            if (!currentCall) return;
            
            try {
                const duration = callStartTime ? Math.floor((Date.now() - callStartTime) / 1000) : 0;
                await fetch(`/api/calls/${currentCall.id}/end`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ duration })
                });
                
                closeCallUI();
            } catch (e) {
                console.error('Failed to end call:', e);
                closeCallUI();
            }
        }
        
        function closeCallUI() {
            // Stop media
            if (localStream) {
                localStream.getTracks().forEach(track => track.stop());
                localStream = null;
            }
            
            // Clear timer
            if (callTimerInterval) {
                clearInterval(callTimerInterval);
                callTimerInterval = null;
            }
            
            // Reset UI
            document.getElementById('callModal').classList.remove('show');
            document.getElementById('videoContainer').style.display = 'none';
            document.getElementById('callAvatar').style.display = 'block';
            document.getElementById('callTimer').style.display = 'none';
            document.getElementById('answerBtn').style.display = 'none';
            document.getElementById('rejectBtn').style.display = 'none';
            document.getElementById('muteBtn').style.display = 'none';
            document.getElementById('videoBtn').style.display = 'none';
            
            currentCall = null;
            callStartTime = null;
        }
        
        function updateCallTimer() {
            if (!callStartTime) return;
            
            const elapsed = Math.floor((Date.now() - callStartTime) / 1000);
            const minutes = Math.floor(elapsed / 60);
            const seconds = elapsed % 60;
            document.getElementById('callTimer').textContent = 
                `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
        }
        
        function toggleMute() {
            if (!localStream) return;
            
            isMuted = !isMuted;
            localStream.getAudioTracks().forEach(track => {
                track.enabled = !isMuted;
            });
            
            document.getElementById('muteBtn').textContent = isMuted ? '🔇' : '🎤';
        }
        
        function toggleVideo() {
            if (!localStream) return;
            
            isVideoOn = !isVideoOn;
            localStream.getVideoTracks().forEach(track => {
                track.enabled = isVideoOn;
            });
            
            document.getElementById('videoBtn').textContent = isVideoOn ? '📹' : '📵';
        }
        
        // Update user status
        async function updateUserStatus(status = 'online') {
            try {
                await fetch('/api/status/update', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ status })
                });
            } catch (e) {
                console.error('Failed to update status:', e);
            }
        }
        
        // Enhanced loadUsers with call buttons
        async function loadUsers() {
            const res = await fetch('/api/users');
            const users = await res.json();
            
            const list = document.getElementById('usersList');
            list.innerHTML = users.map(user => `
                <div class="user-item" onclick="selectUser(${user.id}, '${user.username}')">
                    <span class="status-indicator status-online"></span>
                    @ ${user.username}
                    <button class="user-call-btn" onclick="event.stopPropagation(); initiateCall(${user.id}, '${user.username}', 'audio')">📞</button>
                </div>
            `).join('');
        }
        
        // ===== PHOTOS (Instagram-style) =====
        async function uploadPhoto() {
            const file = document.getElementById('photoFile').files[0];
            const caption = document.getElementById('photoCaption').value;
            const filter = document.getElementById('photoFilter').value;
            
            if (!file) return alert('Please select a photo');
            
            const formData = new FormData();
            formData.append('file', file);
            formData.append('caption', caption);
            formData.append('filter', filter);
            
            await fetch('/api/photos', {
                method: 'POST',
                body: formData
            });
            
            document.getElementById('photoFile').value = '';
            document.getElementById('photoCaption').value = '';
            loadPhotos();
        }
        
        async function loadPhotos() {
            const res = await fetch('/api/photos');
            const photos = await res.json();
            
            const grid = document.getElementById('photoGrid');
            grid.innerHTML = photos.map(photo => `
                <div class="card">
                    <div style="display: flex; align-items: center; margin-bottom: 10px;">
                        <strong>@${photo.username}</strong>
                        <span style="margin-left: auto; color: #999; font-size: 12px;">
                            ${new Date(photo.created_at).toLocaleDateString()}
                        </span>
                    </div>
                    <img src="/api/photos/${photo.id}/view" style="width: 100%; border-radius: 8px; filter: ${getPhotoFilter(photo.filter)};" alt="${photo.caption}">
                    <div style="margin-top: 10px;">
                        <p style="margin-bottom: 10px;">${photo.caption || ''}</p>
                        <div style="display: flex; gap: 15px; color: #666;">
                            <span style="cursor: pointer;" onclick="likePhoto(${photo.id})">❤️ ${photo.likes}</span>
                            <span>💬 ${photo.comment_count}</span>
                        </div>
                    </div>
                </div>
            `).join('');
        }
        
        function getPhotoFilter(filter) {
            const filters = {
                'none': 'none',
                'grayscale': 'grayscale(100%)',
                'sepia': 'sepia(100%)',
                'vintage': 'sepia(50%) contrast(120%)',
                'cool': 'hue-rotate(180deg) saturate(120%)'
            };
            return filters[filter] || 'none';
        }
        
        async function likePhoto(photoId) {
            await fetch(`/api/photos/${photoId}/like`, { method: 'POST' });
            loadPhotos();
        }
        
        // ===== LIVE STREAMING =====
        let currentStream = null;
        let streamVideo = null;
        
        async function startStream() {
            const title = document.getElementById('streamTitle').value;
            const description = document.getElementById('streamDescription').value;
            
            if (!title.trim()) return alert('Please enter a stream title');
            
            try {
                // Create stream
                const res = await fetch('/api/streams', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ title, description })
                });
                
                const data = await res.json();
                currentStream = data.stream_id;
                
                // Get camera access
                streamVideo = await navigator.mediaDevices.getUserMedia({ 
                    video: true, 
                    audio: true 
                });
                
                document.getElementById('streamVideo').srcObject = streamVideo;
                document.getElementById('streamControls').style.display = 'none';
                document.getElementById('streamView').style.display = 'block';
                
                alert('You are now live! 🔴');
            } catch (e) {
                console.error('Failed to start stream:', e);
                alert('Could not access camera/microphone');
            }
        }
        
        async function endStreamSession() {
            if (currentStream) {
                await fetch(`/api/streams/${currentStream}/end`, { method: 'POST' });
            }
            
            if (streamVideo) {
                streamVideo.getTracks().forEach(track => track.stop());
                streamVideo = null;
            }
            
            document.getElementById('streamControls').style.display = 'block';
            document.getElementById('streamView').style.display = 'none';
            document.getElementById('streamTitle').value = '';
            document.getElementById('streamDescription').value = '';
            currentStream = null;
            
            loadStreams();
        }
        
        async function loadStreams() {
            const res = await fetch('/api/streams');
            const streams = await res.json();
            
            const list = document.getElementById('liveStreams');
            if (streams.length === 0) {
                list.innerHTML = '<div class="card" style="text-align: center; color: #999;">No one is streaming right now</div>';
            } else {
                list.innerHTML = streams.map(stream => `
                    <div class="card">
                        <div style="display: flex; align-items: center; margin-bottom: 10px;">
                            <span style="color: red; margin-right: 10px;">● LIVE</span>
                            <strong>${stream.title}</strong>
                        </div>
                        <p style="color: #666; margin-bottom: 10px;">${stream.description || ''}</p>
                        <div style="color: #999; font-size: 12px;">
                            Streaming by @${stream.username} • 👁️ ${stream.viewers} viewers
                        </div>
                    </div>
                `).join('');
            }
        }
        
        // ===== PASTEBIN =====
        async function createPaste() {
            const title = document.getElementById('pasteTitle').value;
            const content = document.getElementById('pasteContent').value;
            const language = document.getElementById('pasteLanguage').value;
            const isPublic = document.getElementById('pastePublic').checked;
            
            if (!content.trim()) return alert('Please enter some content');
            
            await fetch('/api/pastes', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ title, content, language, is_public: isPublic })
            });
            
            document.getElementById('pasteTitle').value = '';
            document.getElementById('pasteContent').value = '';
            loadPastes();
        }
        
        async function loadPastes() {
            const res = await fetch('/api/pastes');
            const pastes = await res.json();
            
            const list = document.getElementById('pastesList');
            list.innerHTML = pastes.map(paste => `
                <div class="card">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                        <strong>${paste.title}</strong>
                        <span style="background: #667eea; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px;">
                            ${paste.language}
                        </span>
                    </div>
                    <pre style="background: #f5f5f5; padding: 15px; border-radius: 8px; overflow-x: auto; max-height: 200px;"><code>${escapeHtml(paste.content)}</code></pre>
                    <div style="margin-top: 10px; display: flex; justify-content: space-between; color: #999; font-size: 12px;">
                        <span>By @${paste.username}</span>
                        <span>👁️ ${paste.views} views • ${new Date(paste.created_at).toLocaleDateString()}</span>
                    </div>
                </div>
            `).join('');
        }
        
        function escapeHtml(text) {
            const map = {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#039;'
            };
            return text.replace(/[&<>"']/g, m => map[m]);
        }
        
        // ===== NOTES =====
        async function createNote() {
            const title = document.getElementById('noteTitle').value;
            const content = document.getElementById('noteContent').value;
            const color = document.getElementById('noteColor').value;
            
            if (!content.trim()) return alert('Please enter some content');
            
            await fetch('/api/notes', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ title, content, color })
            });
            
            document.getElementById('noteTitle').value = '';
            document.getElementById('noteContent').value = '';
            loadNotes();
        }
        
        async function loadNotes() {
            const res = await fetch('/api/notes');
            const notes = await res.json();
            
            const grid = document.getElementById('notesGrid');
            if (notes.length === 0) {
                grid.innerHTML = '<div class="card" style="grid-column: 1/-1; text-align: center; color: #999;">No notes yet</div>';
            } else {
                grid.innerHTML = notes.map(note => `
                    <div class="card" style="background: ${note.color}; min-height: 150px; position: relative;">
                        ${note.pinned ? '<div style="position: absolute; top: 10px; right: 10px; font-size: 20px;">📌</div>' : ''}
                        <h4 style="margin-bottom: 10px;">${note.title}</h4>
                        <p style="white-space: pre-wrap; word-wrap: break-word;">${note.content}</p>
                        <div style="margin-top: 15px; padding-top: 10px; border-top: 1px solid rgba(0,0,0,0.1); font-size: 11px; color: #666;">
                            ${new Date(note.updated_at).toLocaleDateString()}
                        </div>
                        <button onclick="deleteNote(${note.id})" style="position: absolute; bottom: 10px; right: 10px; background: rgba(255,255,255,0.5); border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer;">🗑️</button>
                    </div>
                `).join('');
            }
        }
        
        async function deleteNote(noteId) {
            if (!confirm('Delete this note?')) return;
            await fetch(`/api/notes/${noteId}`, { method: 'DELETE' });
            loadNotes();
        }
        
        // ===== TASKS =====
        async function createTask() {
            const title = document.getElementById('taskTitle').value;
            const description = document.getElementById('taskDescription').value;
            const priority = document.getElementById('taskPriority').value;
            const dueDate = document.getElementById('taskDueDate').value;
            
            if (!title.trim()) return alert('Please enter a task');
            
            await fetch('/api/tasks', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ title, description, priority, due_date: dueDate || null })
            });
            
            document.getElementById('taskTitle').value = '';
            document.getElementById('taskDescription').value = '';
            document.getElementById('taskDueDate').value = '';
            loadTasks();
        }
        
        async function loadTasks() {
            const res = await fetch('/api/tasks');
            const tasks = await res.json();
            
            const list = document.getElementById('tasksList');
            if (tasks.length === 0) {
                list.innerHTML = '<div class="card" style="text-align: center; color: #999;">No tasks yet</div>';
            } else {
                list.innerHTML = tasks.map(task => {
                    const priorityColors = { low: '#4caf50', medium: '#ff9800', high: '#f44336' };
                    return `
                        <div class="card" style="display: flex; align-items: start; gap: 15px; ${task.completed ? 'opacity: 0.6;' : ''}">
                            <input type="checkbox" ${task.completed ? 'checked' : ''} onclick="toggleTask(${task.id})" style="margin-top: 3px; width: 20px; height: 20px; cursor: pointer;">
                            <div style="flex: 1;">
                                <h4 style="${task.completed ? 'text-decoration: line-through;' : ''}">${task.title}</h4>
                                ${task.description ? `<p style="color: #666; margin: 5px 0;">${task.description}</p>` : ''}
                                <div style="display: flex; gap: 10px; margin-top: 10px; font-size: 12px;">
                                    <span style="background: ${priorityColors[task.priority]}; color: white; padding: 2px 8px; border-radius: 4px;">
                                        ${task.priority}
                                    </span>
                                    ${task.due_date ? `<span style="color: #666;">Due: ${new Date(task.due_date).toLocaleString()}</span>` : ''}
                                </div>
                            </div>
                            <button onclick="deleteTask(${task.id})" style="background: none; border: none; font-size: 18px; cursor: pointer; opacity: 0.6;">🗑️</button>
                        </div>
                    `;
                }).join('');
            }
        }
        
        async function toggleTask(taskId) {
            await fetch(`/api/tasks/${taskId}/toggle`, { method: 'POST' });
            loadTasks();
        }
        
        async function deleteTask(taskId) {
            if (!confirm('Delete this task?')) return;
            await fetch(`/api/tasks/${taskId}`, { method: 'DELETE' });
            loadTasks();
        }
        
        // ===== CALENDAR =====
        async function createEvent() {
            const title = document.getElementById('eventTitle').value;
            const description = document.getElementById('eventDescription').value;
            const location = document.getElementById('eventLocation').value;
            const startTime = document.getElementById('eventStart').value;
            const endTime = document.getElementById('eventEnd').value;
            const allDay = document.getElementById('eventAllDay').checked;
            const color = document.getElementById('eventColor').value;
            
            if (!title.trim() || !startTime) return alert('Please enter title and start time');
            
            await fetch('/api/events', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    title, description, location,
                    start_time: startTime,
                    end_time: endTime || null,
                    all_day: allDay,
                    color
                })
            });
            
            document.getElementById('eventTitle').value = '';
            document.getElementById('eventDescription').value = '';
            document.getElementById('eventLocation').value = '';
            document.getElementById('eventStart').value = '';
            document.getElementById('eventEnd').value = '';
            document.getElementById('eventAllDay').checked = false;
            loadEvents();
        }
        
        async function loadEvents() {
            const res = await fetch('/api/events');
            const events = await res.json();
            
            const list = document.getElementById('eventsList');
            if (events.length === 0) {
                list.innerHTML = '<div class="card" style="text-align: center; color: #999;">No events scheduled</div>';
            } else {
                list.innerHTML = events.map(event => `
                    <div class="card" style="border-left: 4px solid ${event.color};">
                        <div style="display: flex; justify-content: space-between; align-items: start;">
                            <div style="flex: 1;">
                                <h4>${event.title}</h4>
                                ${event.description ? `<p style="color: #666; margin: 5px 0;">${event.description}</p>` : ''}
                                <div style="margin-top: 10px; font-size: 13px; color: #666;">
                                    <div>📅 ${new Date(event.start_time).toLocaleString()}</div>
                                    ${event.end_time ? `<div>→ ${new Date(event.end_time).toLocaleString()}</div>` : ''}
                                    ${event.location ? `<div>📍 ${event.location}</div>` : ''}
                                </div>
                            </div>
                            <button onclick="deleteEvent(${event.id})" style="background: none; border: none; font-size: 18px; cursor: pointer; opacity: 0.6;">🗑️</button>
                        </div>
                    </div>
                `).join('');
            }
        }
        
        async function deleteEvent(eventId) {
            if (!confirm('Delete this event?')) return;
            await fetch(`/api/events/${eventId}`, { method: 'DELETE' });
            loadEvents();
        }
        
        // ===== GAMES =====
        let currentGame = null;
        let gameLoop = null;
        let gameState = {};
        
        function startGame(gameType) {
            currentGame = gameType;
            document.getElementById('gameMenu').style.display = 'none';
            document.getElementById('gameContainer').style.display = 'block';
            
            // Initialize game
            switch(gameType) {
                case 'snake':
                    initSnake();
                    break;
                case '2048':
                    init2048();
                    break;
                case 'tictactoe':
                    initTicTacToe();
                    break;
                case 'pong':
                    initPong();
                    break;
                case 'memory':
                    initMemory();
                    break;
                case 'trivia':
                    initTrivia();
                    break;
            }
        }
        
        function exitGame() {
            if (gameLoop) {
                cancelAnimationFrame(gameLoop);
                gameLoop = null;
            }
            currentGame = null;
            gameState = {};
            document.getElementById('gameMenu').style.display = 'block';
            document.getElementById('gameContainer').style.display = 'none';
        }
        
        function gameAction() {
            // Universal game action button handler
            if (!currentGame) return;
            
            if (currentGame === 'snake') toggleSnake();
            if (currentGame === '2048') reset2048();
            if (currentGame === 'tictactoe') resetTicTacToe();
            if (currentGame === 'pong') togglePong();
            if (currentGame === 'memory') resetMemory();
            if (currentGame === 'trivia') nextTrivia();
        }
        
        async function submitScore(gameType, score, level = null) {
            await fetch('/api/games/scores', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ game_type: gameType, score, level })
            });
            loadLeaderboards();
        }
        
        async function loadLeaderboards() {
            const res = await fetch('/api/games/scores?limit=50');
            const scores = await res.json();
            
            // Group by game type
            const byGame = {};
            scores.forEach(score => {
                if (!byGame[score.game_type]) byGame[score.game_type] = [];
                byGame[score.game_type].push(score);
            });
            
            const list = document.getElementById('leaderboardsList');
            let html = '';
            
            for (const [game, gameScores] of Object.entries(byGame)) {
                const top5 = gameScores.slice(0, 5);
                html += `
                    <div class="card" style="margin-top: 15px;">
                        <h4 style="margin-bottom: 10px;">${game.toUpperCase()}</h4>
                        ${top5.map((s, i) => `
                            <div style="display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #f0f0f0;">
                                <span>${i === 0 ? '🥇' : i === 1 ? '🥈' : i === 2 ? '🥉' : '🏅'} ${s.username}</span>
                                <strong>${s.score}</strong>
                            </div>
                        `).join('')}
                    </div>
                `;
            }
            
            list.innerHTML = html || '<p style="text-align: center; color: #999; margin-top: 15px;">No scores yet. Be the first!</p>';
        }
        
        // ===== SNAKE GAME =====
        function initSnake() {
            document.getElementById('gameTitle').textContent = '🐍 Snake';
            document.getElementById('instructionsText').innerHTML = "Use Arrow Keys or WASD to move. Eat the red food to grow. Don't hit walls or yourself!";
            document.getElementById('gameButton').textContent = 'Start';
            
            const canvas = document.getElementById('canvas');
            canvas.width = 400;
            canvas.height = 400;
            
            gameState = {
                snake: [{x: 10, y: 10}],
                direction: {x: 0, y: 0},
                food: {x: 15, y: 15},
                score: 0,
                running: false,
                gridSize: 20,
                tileCount: 20
            };
            
            document.getElementById('gameScore').textContent = '0';
            drawSnake();
            
            // Keyboard controls
            document.onkeydown = (e) => {
                if (!currentGame === 'snake') return;
                const s = gameState;
                if ((e.key === 'ArrowUp' || e.key === 'w') && s.direction.y === 0) s.direction = {x: 0, y: -1};
                if ((e.key === 'ArrowDown' || e.key === 's') && s.direction.y === 0) s.direction = {x: 0, y: 1};
                if ((e.key === 'ArrowLeft' || e.key === 'a') && s.direction.x === 0) s.direction = {x: -1, y: 0};
                if ((e.key === 'ArrowRight' || e.key === 'd') && s.direction.x === 0) s.direction = {x: 1, y: 0};
            };
        }
        
        function toggleSnake() {
            gameState.running = !gameState.running;
            document.getElementById('gameButton').textContent = gameState.running ? 'Pause' : 'Resume';
            if (gameState.running) runSnake();
        }
        
        function runSnake() {
            if (!gameState.running) return;
            
            const s = gameState;
            const head = {x: s.snake[0].x + s.direction.x, y: s.snake[0].y + s.direction.y};
            
            // Check collision with walls
            if (head.x < 0 || head.x >= s.tileCount || head.y < 0 || head.y >= s.tileCount) {
                gameOver();
                return;
            }
            
            // Check collision with self
            if (s.snake.some(segment => segment.x === head.x && segment.y === head.y)) {
                gameOver();
                return;
            }
            
            s.snake.unshift(head);
            
            // Check if ate food
            if (head.x === s.food.x && head.y === s.food.y) {
                s.score++;
                document.getElementById('gameScore').textContent = s.score;
                s.food = {
                    x: Math.floor(Math.random() * s.tileCount),
                    y: Math.floor(Math.random() * s.tileCount)
                };
            } else {
                s.snake.pop();
            }
            
            drawSnake();
            setTimeout(() => runSnake(), 100);
        }
        
        function drawSnake() {
            const canvas = document.getElementById('canvas');
            const ctx = canvas.getContext('2d');
            const s = gameState;
            
            // Clear canvas
            ctx.fillStyle = '#f5f5f5';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            
            // Draw grid
            ctx.strokeStyle = '#e0e0e0';
            for (let i = 0; i <= s.tileCount; i++) {
                ctx.beginPath();
                ctx.moveTo(i * s.gridSize, 0);
                ctx.lineTo(i * s.gridSize, canvas.height);
                ctx.stroke();
                ctx.beginPath();
                ctx.moveTo(0, i * s.gridSize);
                ctx.lineTo(canvas.width, i * s.gridSize);
                ctx.stroke();
            }
            
            // Draw snake
            ctx.fillStyle = '#667eea';
            s.snake.forEach((segment, i) => {
                ctx.fillStyle = i === 0 ? '#667eea' : '#9ab1ff';
                ctx.fillRect(segment.x * s.gridSize + 1, segment.y * s.gridSize + 1, s.gridSize - 2, s.gridSize - 2);
            });
            
            // Draw food
            ctx.fillStyle = '#f44336';
            ctx.fillRect(s.food.x * s.gridSize + 1, s.food.y * s.gridSize + 1, s.gridSize - 2, s.gridSize - 2);
        }
        
        function gameOver() {
            gameState.running = false;
            submitScore('snake', gameState.score);
            alert(`Game Over! Score: ${gameState.score}`);
            initSnake();
        }
        
        // ===== 2048 GAME =====
        function init2048() {
            document.getElementById('gameTitle').textContent = '🔢 2048';
            document.getElementById('instructionsText').innerHTML = 'Use Arrow Keys or WASD to slide tiles. Combine tiles with same numbers. Reach 2048 to win!';
            document.getElementById('gameButton').textContent = 'New Game';
            
            const canvas = document.getElementById('canvas');
            canvas.width = 400;
            canvas.height = 400;
            
            gameState = {
                board: [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]],
                score: 0,
                size: 4,
                tileSize: 90,
                gap: 10
            };
            
            addRandomTile();
            addRandomTile();
            draw2048();
            
            document.onkeydown = (e) => {
                if (currentGame !== '2048') return;
                let moved = false;
                if (e.key === 'ArrowUp' || e.key === 'w') moved = move2048('up');
                if (e.key === 'ArrowDown' || e.key === 's') moved = move2048('down');
                if (e.key === 'ArrowLeft' || e.key === 'a') moved = move2048('left');
                if (e.key === 'ArrowRight' || e.key === 'd') moved = move2048('right');
                
                if (moved) {
                    addRandomTile();
                    draw2048();
                    document.getElementById('gameScore').textContent = gameState.score;
                }
            };
        }
        
        function reset2048() {
            init2048();
        }
        
        function addRandomTile() {
            const empty = [];
            for (let i = 0; i < 4; i++) {
                for (let j = 0; j < 4; j++) {
                    if (gameState.board[i][j] === 0) empty.push({i, j});
                }
            }
            if (empty.length > 0) {
                const {i, j} = empty[Math.floor(Math.random() * empty.length)];
                gameState.board[i][j] = Math.random() < 0.9 ? 2 : 4;
            }
        }
        
        function move2048(direction) {
            const oldBoard = JSON.stringify(gameState.board);
            
            if (direction === 'left' || direction === 'right') {
                for (let i = 0; i < 4; i++) {
                    let row = gameState.board[i].filter(x => x !== 0);
                    if (direction === 'right') row.reverse();
                    
                    for (let j = 0; j < row.length - 1; j++) {
                        if (row[j] === row[j + 1]) {
                            row[j] *= 2;
                            gameState.score += row[j];
                            row.splice(j + 1, 1);
                        }
                    }
                    
                    while (row.length < 4) row.push(0);
                    if (direction === 'right') row.reverse();
                    gameState.board[i] = row;
                }
            } else {
                for (let j = 0; j < 4; j++) {
                    let col = [];
                    for (let i = 0; i < 4; i++) {
                        if (gameState.board[i][j] !== 0) col.push(gameState.board[i][j]);
                    }
                    if (direction === 'down') col.reverse();
                    
                    for (let i = 0; i < col.length - 1; i++) {
                        if (col[i] === col[i + 1]) {
                            col[i] *= 2;
                            gameState.score += col[i];
                            col.splice(i + 1, 1);
                        }
                    }
                    
                    while (col.length < 4) col.push(0);
                    if (direction === 'down') col.reverse();
                    for (let i = 0; i < 4; i++) {
                        gameState.board[i][j] = col[i];
                    }
                }
            }
            
            return oldBoard !== JSON.stringify(gameState.board);
        }
        
        function draw2048() {
            const canvas = document.getElementById('canvas');
            const ctx = canvas.getContext('2d');
            const s = gameState;
            
            ctx.fillStyle = '#bbada0';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            
            const colors = {
                0: '#cdc1b4', 2: '#eee4da', 4: '#ede0c8', 8: '#f2b179',
                16: '#f59563', 32: '#f67c5f', 64: '#f65e3b', 128: '#edcf72',
                256: '#edcc61', 512: '#edc850', 1024: '#edc53f', 2048: '#edc22e'
            };
            
            for (let i = 0; i < 4; i++) {
                for (let j = 0; j < 4; j++) {
                    const value = s.board[i][j];
                    const x = j * (s.tileSize + s.gap) + s.gap;
                    const y = i * (s.tileSize + s.gap) + s.gap;
                    
                    ctx.fillStyle = colors[value] || '#3c3a32';
                    ctx.fillRect(x, y, s.tileSize, s.tileSize);
                    
                    if (value !== 0) {
                        ctx.fillStyle = value <= 4 ? '#776e65' : '#f9f6f2';
                        ctx.font = 'bold 36px Arial';
                        ctx.textAlign = 'center';
                        ctx.textBaseline = 'middle';
                        ctx.fillText(value, x + s.tileSize / 2, y + s.tileSize / 2);
                    }
                }
            }
        }
        
        // ===== TIC-TAC-TOE =====
        function initTicTacToe() {
            document.getElementById('gameTitle').textContent = '⭕ Tic-Tac-Toe';
            document.getElementById('instructionsText').innerHTML = 'Click on a cell to place your mark. Get 3 in a row to win!';
            document.getElementById('gameButton').textContent = 'New Game';
            
            const canvas = document.getElementById('canvas');
            canvas.width = 300;
            canvas.height = 300;
            
            gameState = {
                board: [[null,null,null],[null,null,null],[null,null,null]],
                currentPlayer: 'X',
                gameOver: false,
                winner: null
            };
            
            drawTicTacToe();
            
            canvas.onclick = (e) => {
                if (currentGame !== 'tictactoe' || gameState.gameOver) return;
                
                const rect = canvas.getBoundingClientRect();
                const x = Math.floor((e.clientX - rect.left) / 100);
                const y = Math.floor((e.clientY - rect.top) / 100);
                
                if (gameState.board[y][x] === null) {
                    gameState.board[y][x] = gameState.currentPlayer;
                    checkTicTacToeWin();
                    gameState.currentPlayer = gameState.currentPlayer === 'X' ? 'O' : 'X';
                    drawTicTacToe();
                }
            };
        }
        
        function resetTicTacToe() {
            initTicTacToe();
        }
        
        function drawTicTacToe() {
            const canvas = document.getElementById('canvas');
            const ctx = canvas.getContext('2d');
            
            ctx.fillStyle = '#f5f5f5';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            
            ctx.strokeStyle = '#667eea';
            ctx.lineWidth = 3;
            
            // Draw grid
            ctx.beginPath();
            ctx.moveTo(100, 0);
            ctx.lineTo(100, 300);
            ctx.moveTo(200, 0);
            ctx.lineTo(200, 300);
            ctx.moveTo(0, 100);
            ctx.lineTo(300, 100);
            ctx.moveTo(0, 200);
            ctx.lineTo(300, 200);
            ctx.stroke();
            
            // Draw marks
            ctx.font = 'bold 60px Arial';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            
            for (let i = 0; i < 3; i++) {
                for (let j = 0; j < 3; j++) {
                    if (gameState.board[i][j]) {
                        ctx.fillStyle = gameState.board[i][j] === 'X' ? '#667eea' : '#f44336';
                        ctx.fillText(gameState.board[i][j], j * 100 + 50, i * 100 + 50);
                    }
                }
            }
            
            document.getElementById('gameInfo').textContent = gameState.gameOver ? 
                (gameState.winner ? `${gameState.winner} wins!` : 'Draw!') :
                `${gameState.currentPlayer}'s turn`;
        }
        
        function checkTicTacToeWin() {
            const b = gameState.board;
            
            // Check rows and cols
            for (let i = 0; i < 3; i++) {
                if (b[i][0] && b[i][0] === b[i][1] && b[i][1] === b[i][2]) {
                    gameState.gameOver = true;
                    gameState.winner = b[i][0];
                }
                if (b[0][i] && b[0][i] === b[1][i] && b[1][i] === b[2][i]) {
                    gameState.gameOver = true;
                    gameState.winner = b[0][i];
                }
            }
            
            // Check diagonals
            if (b[0][0] && b[0][0] === b[1][1] && b[1][1] === b[2][2]) {
                gameState.gameOver = true;
                gameState.winner = b[0][0];
            }
            if (b[0][2] && b[0][2] === b[1][1] && b[1][1] === b[2][0]) {
                gameState.gameOver = true;
                gameState.winner = b[0][2];
            }
            
            // Check draw
            if (!gameState.gameOver && b.flat().every(cell => cell !== null)) {
                gameState.gameOver = true;
            }
        }
        
        // ===== PONG =====
        function initPong() {
            document.getElementById('gameTitle').textContent = '🏓 Pong';
            document.getElementById('instructionsText').innerHTML = 'Use W/S or Arrow Up/Down to move your paddle. First to 5 points wins!';
            document.getElementById('gameButton').textContent = 'Start';
            
            const canvas = document.getElementById('canvas');
            canvas.width = 600;
            canvas.height = 400;
            
            gameState = {
                paddle1: {x: 10, y: 150, w: 10, h: 100},
                paddle2: {x: 580, y: 150, w: 10, h: 100},
                ball: {x: 300, y: 200, vx: 4, vy: 4, size: 10},
                score1: 0,
                score2: 0,
                running: false
            };
            
            drawPong();
            
            document.onkeydown = (e) => {
                if (currentGame !== 'pong') return;
                if (e.key === 'w' && gameState.paddle1.y > 0) gameState.paddle1.y -= 20;
                if (e.key === 's' && gameState.paddle1.y < 300) gameState.paddle1.y += 20;
            };
        }
        
        function togglePong() {
            gameState.running = !gameState.running;
            document.getElementById('gameButton').textContent = gameState.running ? 'Pause' : 'Resume';
            if (gameState.running) runPong();
        }
        
        function runPong() {
            if (!gameState.running) return;
            
            const s = gameState;
            
            // Move ball
            s.ball.x += s.ball.vx;
            s.ball.y += s.ball.vy;
            
            // Ball collision with top/bottom
            if (s.ball.y <= 0 || s.ball.y >= 400) s.ball.vy *= -1;
            
            // Ball collision with paddles
            if (s.ball.x <= 20 && s.ball.y >= s.paddle1.y && s.ball.y <= s.paddle1.y + 100) {
                s.ball.vx = Math.abs(s.ball.vx);
            }
            if (s.ball.x >= 580 && s.ball.y >= s.paddle2.y && s.ball.y <= s.paddle2.y + 100) {
                s.ball.vx = -Math.abs(s.ball.vx);
            }
            
            // Score points
            if (s.ball.x < 0) {
                s.score2++;
                resetBall();
            }
            if (s.ball.x > 600) {
                s.score1++;
                resetBall();
            }
            
            // AI for paddle2
            if (s.paddle2.y + 50 < s.ball.y) s.paddle2.y += 3;
            if (s.paddle2.y + 50 > s.ball.y) s.paddle2.y -= 3;
            
            document.getElementById('gameScore').textContent = `${s.score1} - ${s.score2}`;
            
            if (s.score1 >= 5 || s.score2 >= 5) {
                gameState.running = false;
                alert(`Game Over! ${s.score1 >= 5 ? 'You win!' : 'AI wins!'}`);
                submitScore('pong', s.score1);
                initPong();
                return;
            }
            
            drawPong();
            requestAnimationFrame(runPong);
        }
        
        function resetBall() {
            gameState.ball = {x: 300, y: 200, vx: 4 * (Math.random() < 0.5 ? 1 : -1), vy: 4 * (Math.random() < 0.5 ? 1 : -1), size: 10};
        }
        
        function drawPong() {
            const canvas = document.getElementById('canvas');
            const ctx = canvas.getContext('2d');
            const s = gameState;
            
            ctx.fillStyle = '#000';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            
            // Draw paddles
            ctx.fillStyle = '#fff';
            ctx.fillRect(s.paddle1.x, s.paddle1.y, s.paddle1.w, s.paddle1.h);
            ctx.fillRect(s.paddle2.x, s.paddle2.y, s.paddle2.w, s.paddle2.h);
            
            // Draw ball
            ctx.fillRect(s.ball.x, s.ball.y, s.ball.size, s.ball.size);
            
            // Draw center line
            ctx.setLineDash([5, 5]);
            ctx.strokeStyle = '#666';
            ctx.beginPath();
            ctx.moveTo(300, 0);
            ctx.lineTo(300, 400);
            ctx.stroke();
            ctx.setLineDash([]);
        }
        
        // ===== MEMORY GAME =====
        function initMemory() {
            document.getElementById('gameTitle').textContent = '🎴 Memory';
            document.getElementById('instructionsText').innerHTML = 'Click cards to flip them. Match pairs to clear them. Complete all pairs to win!';
            document.getElementById('gameButton').textContent = 'New Game';
            
            const canvas = document.getElementById('canvas');
            canvas.width = 400;
            canvas.height = 400;
            
            const symbols = ['🍎', '🍌', '🍇', '🍊', '🍓', '🍒', '🍉', '🥝'];
            const cards = [...symbols, ...symbols].sort(() => Math.random() - 0.5);
            
            gameState = {
                cards: cards.map((symbol, i) => ({symbol, flipped: false, matched: false, id: i})),
                flipped: [],
                moves: 0,
                matches: 0
            };
            
            drawMemory();
            
            canvas.onclick = (e) => {
                if (currentGame !== 'memory' || gameState.flipped.length >= 2) return;
                
                const rect = canvas.getBoundingClientRect();
                const x = Math.floor((e.clientX - rect.left) / 100);
                const y = Math.floor((e.clientY - rect.top) / 100);
                const index = y * 4 + x;
                const card = gameState.cards[index];
                
                if (!card.flipped && !card.matched) {
                    card.flipped = true;
                    gameState.flipped.push(index);
                    
                    if (gameState.flipped.length === 2) {
                        gameState.moves++;
                        const [i1, i2] = gameState.flipped;
                        
                        if (gameState.cards[i1].symbol === gameState.cards[i2].symbol) {
                            gameState.cards[i1].matched = true;
                            gameState.cards[i2].matched = true;
                            gameState.matches++;
                            gameState.flipped = [];
                            
                            if (gameState.matches === 8) {
                                setTimeout(() => {
                                    alert(`You won in ${gameState.moves} moves!`);
                                    submitScore('memory', gameState.moves);
                                }, 500);
                            }
                        } else {
                            setTimeout(() => {
                                gameState.cards[i1].flipped = false;
                                gameState.cards[i2].flipped = false;
                                gameState.flipped = [];
                                drawMemory();
                            }, 1000);
                        }
                    }
                    
                    drawMemory();
                }
            };
        }
        
        function resetMemory() {
            initMemory();
        }
        
        function drawMemory() {
            const canvas = document.getElementById('canvas');
            const ctx = canvas.getContext('2d');
            
            ctx.fillStyle = '#f5f5f5';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            
            gameState.cards.forEach((card, i) => {
                const x = (i % 4) * 100;
                const y = Math.floor(i / 4) * 100;
                
                ctx.fillStyle = card.matched ? '#4caf50' : (card.flipped ? '#667eea' : '#ccc');
                ctx.fillRect(x + 5, y + 5, 90, 90);
                
                if (card.flipped || card.matched) {
                    ctx.font = '48px Arial';
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillText(card.symbol, x + 50, y + 50);
                }
            });
            
            document.getElementById('gameScore').textContent = gameState.moves;
        }
        
        // ===== TRIVIA =====
        const triviaQuestions = [
            {q: 'What is the capital of France?', a: ['Paris', 'London', 'Berlin', 'Madrid'], correct: 0},
            {q: 'What is 2 + 2?', a: ['3', '4', '5', '6'], correct: 1},
            {q: 'What color is the sky?', a: ['Red', 'Blue', 'Green', 'Yellow'], correct: 1},
            {q: 'How many legs does a spider have?', a: ['6', '8', '10', '12'], correct: 1},
            {q: 'What is the largest planet?', a: ['Earth', 'Mars', 'Jupiter', 'Saturn'], correct: 2},
        ];
        
        function initTrivia() {
            document.getElementById('gameTitle').textContent = '🧠 Trivia';
            document.getElementById('instructionsText').innerHTML = 'Answer questions correctly to score points!';
            document.getElementById('gameButton').textContent = 'Next Question';
            
            const canvas = document.getElementById('canvas');
            canvas.width = 500;
            canvas.height = 400;
            
            gameState = {
                questions: [...triviaQuestions].sort(() => Math.random() - 0.5),
                currentQ: 0,
                score: 0,
                answered: false
            };
            
            drawTrivia();
            
            canvas.onclick = (e) => {
                if (currentGame !== 'trivia' || gameState.answered) return;
                
                const rect = canvas.getBoundingClientRect();
                const y = Math.floor((e.clientY - rect.top - 100) / 60);
                
                if (y >= 0 && y < 4) {
                    const q = gameState.questions[gameState.currentQ];
                    if (y === q.correct) {
                        gameState.score++;
                        document.getElementById('gameScore').textContent = gameState.score;
                    }
                    gameState.answered = true;
                    drawTrivia();
                }
            };
        }
        
        function nextTrivia() {
            if (gameState.currentQ < gameState.questions.length - 1) {
                gameState.currentQ++;
                gameState.answered = false;
                drawTrivia();
            } else {
                alert(`Quiz complete! Score: ${gameState.score}/${gameState.questions.length}`);
                submitScore('trivia', gameState.score);
                initTrivia();
            }
        }
        
        function drawTrivia() {
            const canvas = document.getElementById('canvas');
            const ctx = canvas.getContext('2d');
            const q = gameState.questions[gameState.currentQ];
            
            ctx.fillStyle = '#f5f5f5';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            
            // Draw question
            ctx.fillStyle = '#333';
            ctx.font = 'bold 18px Arial';
            ctx.textAlign = 'center';
            ctx.fillText(q.q, 250, 50);
            
            // Draw answers
            q.a.forEach((answer, i) => {
                const y = 100 + i * 60;
                const isCorrect = i === q.correct;
                
                if (gameState.answered) {
                    ctx.fillStyle = isCorrect ? '#4caf50' : '#f44336';
                } else {
                    ctx.fillStyle = '#667eea';
                }
                
                ctx.fillRect(50, y, 400, 50);
                
                ctx.fillStyle = '#fff';
                ctx.font = '16px Arial';
                ctx.fillText(answer, 250, y + 30);
            });
            
            document.getElementById('gameInfo').textContent = `Question ${gameState.currentQ + 1}/${gameState.questions.length}`;
        }
        
        // ===== ADMINISTRATION & MODERATION =====
        let userRole = 'user';
        let currentAdminTab = 'users';
        
        async function checkUserRole() {
            try {
                const res = await fetch('/api/user/me');
                const user = await res.json();
                userRole = user.role || 'user';
                
                // Show/hide admin panel based on role
                if (userRole === 'moderator' || userRole === 'admin') {
                    document.getElementById('adminNavItem').style.display = 'block';
                    document.getElementById('adminRole').textContent = `Role: ${userRole.charAt(0).toUpperCase() + userRole.slice(1)}`;
                    
                    // Show stats tab only for admins
                    if (userRole === 'admin') {
                        document.getElementById('adminTabStats').style.display = 'inline-block';
                    }
                }
            } catch (e) {
                console.error('Failed to check role:', e);
            }
        }
        
        function showAdminTab(tab) {
            currentAdminTab = tab;
            
            // Hide all tabs
            document.getElementById('adminUsers').style.display = 'none';
            document.getElementById('adminReports').style.display = 'none';
            document.getElementById('adminLogs').style.display = 'none';
            document.getElementById('adminStats').style.display = 'none';
            
            // Remove active class from all buttons
            document.querySelectorAll('[id^="adminTab"]').forEach(btn => {
                btn.style.background = '#667eea';
            });
            
            // Show selected tab
            document.getElementById(`admin${tab.charAt(0).toUpperCase() + tab.slice(1)}`).style.display = 'block';
            document.getElementById(`adminTab${tab.charAt(0).toUpperCase() + tab.slice(1)}`).style.background = '#5568d3';
            
            // Load data
            if (tab === 'users') loadUsers();
            if (tab === 'reports') loadReports();
            if (tab === 'logs') loadModLogs();
            if (tab === 'stats') loadStats();
        }
        
        async function loadUsers() {
            const res = await fetch('/api/admin/users');
            const users = await res.json();
            
            const list = document.getElementById('usersList');
            list.innerHTML = users.map(user => `
                <div class="card">
                    <div style="display: flex; justify-content: space-between; align-items: start;">
                        <div style="flex: 1;">
                            <h3 style="margin-bottom: 5px;">@${user.username}</h3>
                            <div style="color: #666; font-size: 13px; margin-bottom: 10px;">
                                ${user.email || 'No email'} • Role: ${user.role}
                                ${user.banned ? ' • <span style="color: red;">BANNED</span>' : ''}
                            </div>
                            <div style="font-size: 12px; color: #999;">
                                Posts: ${user.post_count} • Forums: ${user.forum_count}
                                • Joined: ${new Date(user.created_at).toLocaleDateString()}
                            </div>
                            ${user.banned && user.banned_reason ? `<div style="margin-top: 10px; padding: 10px; background: #fff3cd; border-radius: 6px; font-size: 13px;"><strong>Ban reason:</strong> ${user.banned_reason}</div>` : ''}
                        </div>
                        <div style="display: flex; flex-direction: column; gap: 8px;">
                            ${userRole === 'admin' && user.id !== currentUser.user_id ? `
                                <select onchange="changeRole(${user.id}, this.value)" style="padding: 5px; border-radius: 4px;">
                                    <option value="user" ${user.role === 'user' ? 'selected' : ''}>User</option>
                                    <option value="moderator" ${user.role === 'moderator' ? 'selected' : ''}>Moderator</option>
                                    <option value="admin" ${user.role === 'admin' ? 'selected' : ''}>Admin</option>
                                </select>
                            ` : ''}
                            ${!user.banned ? `
                                <button onclick="banUser(${user.id})" style="padding: 6px 12px; background: #f44336; color: white; border: none; border-radius: 4px; cursor: pointer;">Ban</button>
                            ` : `
                                <button onclick="unbanUser(${user.id})" style="padding: 6px 12px; background: #4caf50; color: white; border: none; border-radius: 4px; cursor: pointer;">Unban</button>
                            `}
                        </div>
                    </div>
                </div>
            `).join('');
        }
        
        async function changeRole(userId, newRole) {
            if (!confirm(`Change user role to ${newRole}?`)) return;
            
            await fetch(`/api/admin/users/${userId}/role`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ role: newRole })
            });
            
            loadUsers();
        }
        
        async function banUser(userId) {
            const reason = prompt('Ban reason:');
            if (!reason) return;
            
            const duration = prompt('Duration in hours (leave empty for permanent):');
            
            await fetch(`/api/mod/users/${userId}/ban`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ reason, duration: duration || null })
            });
            
            loadUsers();
        }
        
        async function unbanUser(userId) {
            if (!confirm('Unban this user?')) return;
            
            await fetch(`/api/mod/users/${userId}/unban`, {
                method: 'POST'
            });
            
            loadUsers();
        }
        
        async function loadReports() {
            const res = await fetch('/api/reports');
            const reports = await res.json();
            
            const list = document.getElementById('reportsList');
            if (reports.length === 0) {
                list.innerHTML = '<div class="card" style="text-align: center; color: #999;">No pending reports</div>';
            } else {
                list.innerHTML = reports.map(report => `
                    <div class="card">
                        <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 10px;">
                            <div>
                                <strong>${report.item_type.toUpperCase()} #${report.item_id}</strong>
                                <div style="color: #666; font-size: 13px; margin-top: 5px;">
                                    Reported by @${report.reporter_name} • ${new Date(report.created_at).toLocaleString()}
                                </div>
                            </div>
                            <button onclick="resolveReport(${report.id})" style="padding: 6px 12px; background: #4caf50; color: white; border: none; border-radius: 4px; cursor: pointer;">Resolve</button>
                        </div>
                        <div style="padding: 10px; background: #f8f8f8; border-radius: 6px;">
                            <strong>Reason:</strong> ${report.reason}
                        </div>
                    </div>
                `).join('');
            }
        }
        
        async function resolveReport(reportId) {
            await fetch(`/api/reports/${reportId}/resolve`, {
                method: 'POST'
            });
            loadReports();
        }
        
        async function loadModLogs() {
            const res = await fetch('/api/mod/logs');
            const logs = await res.json();
            
            const list = document.getElementById('logsList');
            if (logs.length === 0) {
                list.innerHTML = '<div class="card" style="text-align: center; color: #999;">No moderation logs</div>';
            } else {
                list.innerHTML = logs.map(log => `
                    <div class="card">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                            <strong>@${log.moderator_name}</strong>
                            <span style="color: #999; font-size: 12px;">${new Date(log.created_at).toLocaleString()}</span>
                        </div>
                        <div style="font-size: 14px;">
                            <span style="background: #667eea; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px;">${log.action}</span>
                            ${log.target_type} #${log.target_id}
                            ${log.reason ? `<div style="margin-top: 8px; color: #666;">Reason: ${log.reason}</div>` : ''}
                        </div>
                    </div>
                `).join('');
            }
        }
        
        async function loadStats() {
            const res = await fetch('/api/admin/stats');
            const stats = await res.json();
            
            const display = document.getElementById('statsDisplay');
            display.innerHTML = `
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                    <div class="card" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;">
                        <h2 style="margin-bottom: 10px;">${stats.total_users}</h2>
                        <div>Total Users</div>
                    </div>
                    <div class="card" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white;">
                        <h2 style="margin-bottom: 10px;">${stats.moderators}</h2>
                        <div>Moderators</div>
                    </div>
                    <div class="card" style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); color: white;">
                        <h2 style="margin-bottom: 10px;">${stats.active_posts}</h2>
                        <div>Active Posts</div>
                    </div>
                    <div class="card" style="background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%); color: white;">
                        <h2 style="margin-bottom: 10px;">${stats.active_forums}</h2>
                        <div>Active Forums</div>
                    </div>
                    <div class="card" style="background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); color: white;">
                        <h2 style="margin-bottom: 10px;">${stats.banned_users}</h2>
                        <div>Banned Users</div>
                    </div>
                    <div class="card" style="background: linear-gradient(135deg, #30cfd0 0%, #330867 100%); color: white;">
                        <h2 style="margin-bottom: 10px;">${stats.pending_reports}</h2>
                        <div>Pending Reports</div>
                    </div>
                    <div class="card" style="background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%);">
                        <h2 style="margin-bottom: 10px;">${stats.deleted_posts}</h2>
                        <div>Deleted Posts</div>
                    </div>
                    <div class="card" style="background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%);">
                        <h2 style="margin-bottom: 10px;">${stats.locked_forums}</h2>
                        <div>Locked Forums</div>
                    </div>
                </div>
            `;
        }
        
        async function reportContent(itemType, itemId) {
            const reason = prompt('Report reason:');
            if (!reason) return;
            
            await fetch('/api/reports', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ item_type: itemType, item_id: itemId, reason })
            });
            
            alert('Report submitted. Moderators will review it.');
        }
        
        async function deletePost(postId) {
            const reason = prompt('Deletion reason:');
            if (!reason) return;
            
            await fetch(`/api/mod/posts/${postId}/delete`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ reason })
            });
            
            loadPosts();
        }
        
        async function pinPost(postId) {
            await fetch(`/api/mod/posts/${postId}/pin`, {
                method: 'POST'
            });
            loadPosts();
        }
        
        async function deleteForum(forumId) {
            const reason = prompt('Deletion reason:');
            if (!reason) return;
            
            await fetch(`/api/mod/forums/${forumId}/delete`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ reason })
            });
            
            loadForums();
        }
        
        async function lockForum(forumId) {
            await fetch(`/api/mod/forums/${forumId}/lock`, {
                method: 'POST'
            });
            loadForums();
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
