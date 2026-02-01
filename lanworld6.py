#!/usr/bin/env python3
"""
LAN World - A Complete Internet Experience on Your Local Network
Run this script to create a self-contained social network on your LAN
"""

import os
import json
import hashlib
import secrets
import ssl
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from functools import wraps

from flask import Flask, request, jsonify, send_from_directory, session, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3

# Configuration
BASE_DIR = Path(__file__).parent / 'lanworld_data'
UPLOAD_FOLDER = BASE_DIR / 'uploads'
DATABASE = BASE_DIR / 'lanworld.db'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mp3', 'pdf', 'txt', 'zip', 'doc', 'docx'}
SECRET_KEY_FILE = BASE_DIR / '.secret_key'

# Create necessary directories
BASE_DIR.mkdir(exist_ok=True)
UPLOAD_FOLDER.mkdir(exist_ok=True)

app = Flask(__name__)

# Persistent secret key
def get_or_create_secret_key():
    if SECRET_KEY_FILE.exists():
        return SECRET_KEY_FILE.read_text().strip()
    key = secrets.token_hex(32)
    SECRET_KEY_FILE.write_text(key)
    try:
        import os
        os.chmod(SECRET_KEY_FILE, 0o600)
    except:
        pass
    return key

app.secret_key = get_or_create_secret_key()
app.config['UPLOAD_FOLDER'] = str(UPLOAD_FOLDER)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024

# In-memory game state cache
active_games = {}

# Database initialization
def init_db():
    """Initialize the database with all necessary tables"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Performance and durability settings
    c.execute('PRAGMA journal_mode=WAL')
    c.execute('PRAGMA synchronous=NORMAL')
    c.execute('PRAGMA temp_store=MEMORY')
    
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
    
    # Post comments with nesting
    c.execute('''CREATE TABLE IF NOT EXISTS post_comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        parent_id INTEGER DEFAULT NULL,
        content TEXT NOT NULL,
        likes INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (parent_id) REFERENCES post_comments (id) ON DELETE CASCADE
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS post_comment_likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        comment_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (comment_id) REFERENCES post_comments (id) ON DELETE CASCADE,
        UNIQUE(user_id, comment_id)
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
    
    # Forum comments with nesting
    c.execute('''CREATE TABLE IF NOT EXISTS forum_comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        forum_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        parent_id INTEGER DEFAULT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (forum_id) REFERENCES forums (id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (parent_id) REFERENCES forum_comments (id) ON DELETE CASCADE
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
    
    # GAMING TABLES
    c.execute('''CREATE TABLE IF NOT EXISTS game_rooms (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER NOT NULL,
        game_type TEXT NOT NULL,
        room_name TEXT NOT NULL,
        max_players INTEGER DEFAULT 2,
        status TEXT DEFAULT 'waiting',
        winner_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        started_at TIMESTAMP,
        ended_at TIMESTAMP,
        FOREIGN KEY (host_id) REFERENCES users (id),
        FOREIGN KEY (winner_id) REFERENCES users (id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS game_players (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        player_number INTEGER,
        score INTEGER DEFAULT 0,
        status TEXT DEFAULT 'active',
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (room_id) REFERENCES game_rooms (id),
        FOREIGN KEY (user_id) REFERENCES users (id),
        UNIQUE(room_id, user_id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS game_moves (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        move_data TEXT NOT NULL,
        move_number INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (room_id) REFERENCES game_rooms (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS game_scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        game_type TEXT NOT NULL,
        score INTEGER,
        is_win BOOLEAN,
        opponent_id INTEGER,
        played_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (opponent_id) REFERENCES users (id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS achievements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        achievement_type TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        unlocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        UNIQUE(user_id, achievement_type)
    )''')
    
    conn.commit()
    conn.close()

# Helper functions
def hash_password(password):
    """Hash a password using Werkzeug"""
    return generate_password_hash(password)

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

def create_notification(user_id, notif_type, title, message, link=None):
    """Helper function to create notifications"""
    conn = get_db()
    c = conn.cursor()
    c.execute('''INSERT INTO notifications (user_id, type, title, message, link) 
                 VALUES (?, ?, ?, ?, ?)''',
              (user_id, notif_type, title, message, link))
    conn.commit()
    conn.close()

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
        
        # Add default user status
        c.execute('INSERT OR REPLACE INTO user_status (user_id, status) VALUES (?, ?)',
                  (user_id, 'online'))
        conn.commit()
        
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
    
    if user and check_password_hash(user['password_hash'], password):
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

# Posts (Twitter/X style) with Comments
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
                 ORDER BY posts.created_at DESC LIMIT 100''')
    posts = [dict(row) for row in c.fetchall()]
    
    # Check if current user liked each post
    for post in posts:
        c.execute('SELECT id FROM likes WHERE user_id = ? AND item_type = ? AND item_id = ?',
                  (session['user_id'], 'post', post['id']))
        post['user_liked'] = c.fetchone() is not None
    
    conn.close()
    return jsonify(posts)

@app.route('/api/posts/<int:post_id>')
@login_required
def get_post_detail(post_id):
    """Get single post with full details"""
    conn = get_db()
    c = conn.cursor()
    
    c.execute('''SELECT p.*, u.username, u.avatar,
                 (SELECT COUNT(*) FROM post_comments WHERE post_id = p.id) as comment_count
                 FROM posts p
                 JOIN users u ON p.user_id = u.id
                 WHERE p.id = ?''', (post_id,))
    post = c.fetchone()
    
    if not post:
        conn.close()
        return jsonify({'error': 'Post not found'}), 404
    
    result = dict(post)
    
    # Check if current user liked this post
    c.execute('SELECT id FROM likes WHERE user_id = ? AND item_type = ? AND item_id = ?',
              (session['user_id'], 'post', post_id))
    result['user_liked'] = c.fetchone() is not None
    
    conn.close()
    return jsonify(result)

@app.route('/api/posts/<int:post_id>/comments', methods=['GET', 'POST'])
@login_required
def post_comments(post_id):
    """Get comments for a post or add new comment"""
    if request.method == 'POST':
        data = request.json
        content = data.get('content', '').strip()
        parent_id = data.get('parent_id')
        
        if not content:
            return jsonify({'error': 'Content required'}), 400
        
        conn = get_db()
        c = conn.cursor()
        
        c.execute('SELECT id FROM posts WHERE id = ?', (post_id,))
        if not c.fetchone():
            conn.close()
            return jsonify({'error': 'Post not found'}), 404
        
        c.execute('''INSERT INTO post_comments (post_id, user_id, parent_id, content) 
                     VALUES (?, ?, ?, ?)''',
                  (post_id, session['user_id'], parent_id, content))
        comment_id = c.lastrowid
        
        # Create notifications
        c.execute('SELECT user_id FROM posts WHERE id = ?', (post_id,))
        post_owner = c.fetchone()
        if post_owner and post_owner['user_id'] != session['user_id']:
            c.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],))
            commenter = c.fetchone()
            create_notification(
                post_owner['user_id'],
                'comment',
                'New Comment',
                f'{commenter["username"]} commented on your post',
                f'/posts/{post_id}'
            )
        
        if parent_id:
            c.execute('SELECT user_id FROM post_comments WHERE id = ?', (parent_id,))
            parent_owner = c.fetchone()
            if parent_owner and parent_owner['user_id'] != session['user_id']:
                c.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],))
                commenter = c.fetchone()
                create_notification(
                    parent_owner['user_id'],
                    'reply',
                    'New Reply',
                    f'{commenter["username"]} replied to your comment',
                    f'/posts/{post_id}'
                )
        
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'comment_id': comment_id})
    
    # GET - retrieve comments with nested structure
    conn = get_db()
    c = conn.cursor()
    
    c.execute('''SELECT c.*, u.username, u.avatar,
                 (SELECT COUNT(*) FROM post_comment_likes WHERE comment_id = c.id) as like_count,
                 (SELECT COUNT(*) FROM post_comments WHERE parent_id = c.id) as reply_count
                 FROM post_comments c
                 JOIN users u ON c.user_id = u.id
                 WHERE c.post_id = ?
                 ORDER BY c.created_at ASC''', (post_id,))
    
    all_comments = [dict(row) for row in c.fetchall()]
    conn.close()
    
    # Build nested tree
    comment_map = {}
    root_comments = []
    
    for comment in all_comments:
        comment['replies'] = []
        comment_map[comment['id']] = comment
        
        if comment['parent_id']:
            if comment['parent_id'] in comment_map:
                comment_map[comment['parent_id']]['replies'].append(comment)
        else:
            root_comments.append(comment)
    
    return jsonify(root_comments)

@app.route('/api/comments/<int:comment_id>/like', methods=['POST'])
@login_required
def like_comment(comment_id):
    """Like or unlike a comment"""
    conn = get_db()
    c = conn.cursor()
    
    c.execute('SELECT id FROM post_comment_likes WHERE user_id = ? AND comment_id = ?',
              (session['user_id'], comment_id))
    existing = c.fetchone()
    
    if existing:
        c.execute('DELETE FROM post_comment_likes WHERE id = ?', (existing['id'],))
        action = 'unliked'
    else:
        c.execute('INSERT INTO post_comment_likes (user_id, comment_id) VALUES (?, ?)',
                  (session['user_id'], comment_id))
        action = 'liked'
        
        c.execute('SELECT user_id FROM post_comments WHERE id = ?', (comment_id,))
        owner = c.fetchone()
        if owner and owner['user_id'] != session['user_id']:
            c.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],))
            liker = c.fetchone()
            create_notification(
                owner['user_id'],
                'like',
                'Comment Liked',
                f'{liker["username"]} liked your comment',
                None
            )
    
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'action': action})

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

# Enhanced Forums
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
    
    # Get nested comments
    c.execute('''SELECT c.*, u.username, u.avatar
                 FROM forum_comments c
                 JOIN users u ON c.user_id = u.id
                 WHERE c.forum_id = ? AND c.parent_id IS NULL
                 ORDER BY c.created_at ASC''', (forum_id,))
    comments = [dict(row) for row in c.fetchall()]
    
    for comment in comments:
        c.execute('''SELECT c.*, u.username, u.avatar
                     FROM forum_comments c
                     JOIN users u ON c.user_id = u.id
                     WHERE c.parent_id = ?
                     ORDER BY c.created_at ASC''', (comment['id'],))
        comment['replies'] = [dict(row) for row in c.fetchall()]
    
    conn.close()
    
    result = dict(forum)
    result['comments'] = comments
    return jsonify(result)

@app.route('/api/forums/<int:forum_id>/comments', methods=['GET', 'POST'])
@login_required
def forum_comments_api(forum_id):
    """Enhanced forum comments with threading"""
    conn = get_db()
    c = conn.cursor()
    
    if request.method == 'POST':
        data = request.json
        content = data.get('content', '').strip()
        parent_id = data.get('parent_id')
        
        if not content:
            return jsonify({'error': 'Content required'}), 400
        
        c.execute('SELECT user_id FROM forums WHERE id = ?', (forum_id,))
        forum = c.fetchone()
        if not forum:
            conn.close()
            return jsonify({'error': 'Forum not found'}), 404
        
        c.execute('''INSERT INTO forum_comments (forum_id, user_id, parent_id, content) 
                     VALUES (?, ?, ?, ?)''',
                  (forum_id, session['user_id'], parent_id, content))
        comment_id = c.lastrowid
        
        if forum['user_id'] != session['user_id']:
            c.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],))
            commenter = c.fetchone()
            c.execute('SELECT title FROM forums WHERE id = ?', (forum_id,))
            title = c.fetchone()['title']
            create_notification(
                forum['user_id'],
                'forum_reply',
                'New Forum Reply',
                f'{commenter["username"]} replied to "{title}"',
                f'/forums/{forum_id}'
            )
        
        conn.commit()
        
        c.execute('''SELECT c.*, u.username FROM forum_comments c
                     JOIN users u ON c.user_id = u.id WHERE c.id = ?''', (comment_id,))
        new_comment = dict(c.fetchone())
        conn.close()
        return jsonify(new_comment)
    
    c.execute('''SELECT c.*, u.username, u.avatar
                 FROM forum_comments c
                 JOIN users u ON c.user_id = u.id
                 WHERE c.forum_id = ? AND c.parent_id IS NULL
                 ORDER BY c.created_at ASC''', (forum_id,))
    comments = [dict(row) for row in c.fetchall()]
    
    for comment in comments:
        c.execute('''SELECT c.*, u.username, u.avatar
                     FROM forum_comments c
                     JOIN users u ON c.user_id = u.id
                     WHERE c.parent_id = ?
                     ORDER BY c.created_at ASC''', (comment['id'],))
        comment['replies'] = [dict(row) for row in c.fetchall()]
    
    conn.close()
    return jsonify(comments)

@app.route('/api/forums/categories')
@login_required
def get_forum_categories():
    """Get all forum categories with post counts"""
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT category, COUNT(*) as count 
                 FROM forums GROUP BY category ORDER BY count DESC''')
    categories = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(categories)

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
        c.execute('''SELECT messages.*, users.username as sender_username
                     FROM messages 
                     JOIN users ON messages.sender_id = users.id 
                     WHERE messages.is_dm = 0 AND messages.channel_name = ?
                     ORDER BY messages.created_at DESC LIMIT 100''', (channel_name,))
    
    messages = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify(messages[::-1])

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
        
        if file.filename == '':
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

# Calls
@app.route('/api/calls/initiate', methods=['POST'])
@login_required
def initiate_call():
    """Initiate a call to another user"""
    data = request.json
    receiver_id = data.get('receiver_id')
    call_type = data.get('call_type', 'video')
    
    if not receiver_id:
        return jsonify({'error': 'Receiver ID required'}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    c.execute('SELECT username FROM users WHERE id = ?', (receiver_id,))
    receiver = c.fetchone()
    
    if not receiver:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    
    c.execute('''INSERT INTO calls (caller_id, receiver_id, call_type, status) 
                 VALUES (?, ?, ?, 'ringing')''',
              (session['user_id'], receiver_id, call_type))
    conn.commit()
    call_id = c.lastrowid
    
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
    
    c.execute('SELECT * FROM calls WHERE id = ? AND receiver_id = ?', 
              (call_id, session['user_id']))
    call = c.fetchone()
    
    if not call:
        conn.close()
        return jsonify({'error': 'Call not found'}), 404
    
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

# Pastebin
@app.route('/api/pastes', methods=['GET', 'POST'])
@login_required
def pastes():
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

# Live Streaming
@app.route('/api/streams', methods=['GET', 'POST'])
@login_required
def streams():
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
    conn = get_db()
    c = conn.cursor()
    c.execute('''UPDATE streams SET is_live = 0, ended_at = CURRENT_TIMESTAMP 
                 WHERE id = ? AND user_id = ?''',
              (stream_id, session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# Photos (Instagram-like)
@app.route('/api/photos', methods=['GET', 'POST'])
@login_required
def photos():
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

@app.route('/api/photos/<int:photo_id>/view')
def view_photo(photo_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT filename FROM photos WHERE id = ?', (photo_id,))
    photo = c.fetchone()
    conn.close()
    
    if photo:
        return send_from_directory(app.config['UPLOAD_FOLDER'], photo['filename'])
    return jsonify({'error': 'Photo not found'}), 404

# Notes
@app.route('/api/notes', methods=['GET', 'POST'])
@login_required
def notes():
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
    
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT * FROM notes 
                 WHERE user_id = ? 
                 ORDER BY pinned DESC, updated_at DESC''',
              (session['user_id'],))
    notes = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(notes)

@app.route('/api/notes/<int:note_id>', methods=['DELETE'])
@login_required
def delete_note(note_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM notes WHERE id = ? AND user_id = ?', 
              (note_id, session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# Tasks
@app.route('/api/tasks', methods=['GET', 'POST'])
@login_required
def tasks():
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
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM tasks WHERE id = ? AND user_id = ?', 
              (task_id, session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# Calendar
@app.route('/api/events', methods=['GET', 'POST'])
@login_required
def events():
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
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM events WHERE id = ? AND user_id = ?', 
              (event_id, session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# ===== GAMING ROUTES =====
@app.route('/api/games/rooms', methods=['GET', 'POST'])
@login_required
def game_rooms():
    """List available game rooms or create new one"""
    if request.method == 'POST':
        data = request.json
        game_type = data.get('game_type', 'chess')
        room_name = data.get('game_name', f"Game Room")
        max_players = data.get('max_players', 2)
        
        conn = get_db()
        c = conn.cursor()
        c.execute('''INSERT INTO game_rooms (host_id, game_type, room_name, max_players) 
                     VALUES (?, ?, ?, ?)''',
                  (session['user_id'], game_type, room_name, max_players))
        room_id = c.lastrowid
        
        c.execute('''INSERT INTO game_players (room_id, user_id, player_number, status) 
                     VALUES (?, ?, 1, 'ready')''',
                  (room_id, session['user_id']))
        conn.commit()
        conn.close()
        
        active_games[room_id] = initialize_game(game_type, room_id)
        return jsonify({'success': True, 'room_id': room_id})
    
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT r.*, h.username as host_name,
                 (SELECT COUNT(*) FROM game_players WHERE room_id = r.id) as player_count
                 FROM game_rooms r
                 JOIN users h ON r.host_id = h.id
                 WHERE r.status = 'waiting'
                 ORDER BY r.created_at DESC''')
    rooms = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(rooms)

def initialize_game(game_type, room_id):
    """Initialize game state based on type"""
    if game_type == 'chess':
        return {
            'board': [
                ['r','n','b','q','k','b','n','r'],
                ['p']*8,
                ['']*8,
                ['']*8,
                ['']*8,
                ['']*8,
                ['P']*8,
                ['R','N','B','Q','K','B','N','R']
            ],
            'turn': 1,
            'moves': [],
            'captured': {'1': [], '2': []},
            'status': 'active',
            'game_type': 'chess'
        }
    elif game_type == 'tictactoe':
        return {
            'board': [''] * 9,
            'turn': 1,
            'status': 'active',
            'game_type': 'tictactoe'
        }
    elif game_type == 'snake':
        return {
            'food': [10, 10],
            'grid_size': 20,
            'turn': 1,
            'status': 'active',
            'game_type': 'snake'
        }
    return {}

@app.route('/api/games/rooms/<int:room_id>/join', methods=['POST'])
@login_required
def join_game(room_id):
    """Join an existing game room"""
    conn = get_db()
    c = conn.cursor()
    
    c.execute('''SELECT max_players, status, game_type FROM game_rooms WHERE id = ?''', (room_id,))
    room = c.fetchone()
    
    if not room:
        conn.close()
        return jsonify({'error': 'Room not found'}), 404
    
    if room['status'] != 'waiting':
        conn.close()
        return jsonify({'error': 'Game already started'}), 400
    
    c.execute('SELECT COUNT(*) as count FROM game_players WHERE room_id = ?', (room_id,))
    current_count = c.fetchone()['count']
    
    if current_count >= room['max_players']:
        conn.close()
        return jsonify({'error': 'Room is full'}), 400
    
    player_num = current_count + 1
    c.execute('''INSERT INTO game_players (room_id, user_id, player_number) 
                 VALUES (?, ?, ?)''',
              (room_id, session['user_id'], player_num))
    
    if player_num >= room['max_players']:
        c.execute('''UPDATE game_rooms SET status = 'active', started_at = CURRENT_TIMESTAMP 
                     WHERE id = ?''', (room_id,))
    
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'player_number': player_num})

@app.route('/api/games/rooms/<int:room_id>/state')
@login_required
def get_game_state(room_id):
    """Get current game state"""
    if room_id in active_games:
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT player_number FROM game_players WHERE room_id = ? AND user_id = ?',
                  (room_id, session['user_id']))
        player = c.fetchone()
        conn.close()
        
        state = active_games[room_id].copy()
        state['your_player'] = player['player_number'] if player else None
        return jsonify(state)
    return jsonify({'error': 'Game not found'}), 404

@app.route('/api/games/rooms/<int:room_id>/move', methods=['POST'])
@login_required
def make_move(room_id):
    """Submit a game move"""
    data = request.json
    conn = get_db()
    c = conn.cursor()
    
    c.execute('''SELECT player_number, status FROM game_players 
                 WHERE room_id = ? AND user_id = ?''', (room_id, session['user_id']))
    player = c.fetchone()
    
    if not player or player['status'] != 'active':
        conn.close()
        return jsonify({'error': 'Not your turn or game ended'}), 403
    
    c.execute('''SELECT COUNT(*) as count FROM game_moves WHERE room_id = ?''', (room_id,))
    move_num = c.fetchone()['count'] + 1
    
    move_data = json.dumps(data.get('move'))
    c.execute('''INSERT INTO game_moves (room_id, user_id, move_data, move_number) 
                 VALUES (?, ?, ?, ?)''',
              (room_id, session['user_id'], move_data, move_num))
    
    success, new_state, winner = process_game_move(room_id, player['player_number'], data.get('move'))
    
    if success:
        active_games[room_id] = new_state
        if winner:
            c.execute('''UPDATE game_rooms SET status = 'completed', winner_id = ?, ended_at = CURRENT_TIMESTAMP 
                         WHERE id = ?''', (winner, room_id))
            c.execute('UPDATE game_players SET status = ? WHERE room_id = ? AND user_id = ?',
                     ('won' if winner == session['user_id'] else 'lost', room_id, session['user_id']))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'state': new_state, 'winner': winner})
    
    conn.close()
    return jsonify({'error': 'Invalid move'}), 400

def process_game_move(room_id, player_num, move):
    """Process move and return (success, new_state, winner)"""
    state = active_games.get(room_id, {})
    game_type = state.get('game_type')
    
    if game_type == 'chess':
        if state['turn'] != player_num:
            return False, state, None
        from_pos = move.get('from')
        to_pos = move.get('to')
        board = state['board']
        piece = board[from_pos[0]][from_pos[1]]
        board[to_pos[0]][to_pos[1]] = piece
        board[from_pos[0]][from_pos[1]] = ''
        state['turn'] = 2 if player_num == 1 else 1
        state['moves'].append({'player': player_num, 'from': from_pos, 'to': to_pos, 'piece': piece})
        winner = None
        kings = sum(row.count('k') + row.count('K') for row in board)
        if kings < 2:
            winner = session['user_id']
        return True, state, winner
    
    elif game_type == 'tictactoe':
        pos = move.get('position')
        if pos < 0 or pos > 8 or state['board'][pos] != '':
            return False, state, None
        symbol = 'X' if player_num == 1 else 'O'
        state['board'][pos] = symbol
        state['turn'] = 2 if player_num == 1 else 1
        
        wins = [[0,1,2], [3,4,5], [6,7,8], [0,3,6], [1,4,7], [2,5,8], [0,4,8], [2,4,6]]
        winner = None
        for combo in wins:
            if state['board'][combo[0]] == state['board'][combo[1]] == state['board'][combo[2]] != '':
                winner = session['user_id']
                break
        if not winner and '' not in state['board']:
            winner = 'draw'
        return True, state, winner
    
    return False, state, None

@app.route('/api/games/rooms/<int:room_id>/leave', methods=['POST'])
@login_required
def leave_game(room_id):
    """Leave a game"""
    conn = get_db()
    c = conn.cursor()
    
    c.execute('''UPDATE game_players SET status = 'forfeited' 
                 WHERE room_id = ? AND user_id = ?''', (room_id, session['user_id']))
    
    c.execute('SELECT status FROM game_rooms WHERE id = ?', (room_id,))
    room = c.fetchone()
    
    if room and room['status'] == 'active':
        c.execute('''SELECT user_id FROM game_players 
                     WHERE room_id = ? AND user_id != ? AND status = 'active' LIMIT 1''',
                  (room_id, session['user_id']))
        opponent = c.fetchone()
        if opponent:
            c.execute('''UPDATE game_rooms SET status = 'completed', winner_id = ?, ended_at = CURRENT_TIMESTAMP 
                         WHERE id = ?''', (opponent['user_id'], room_id))
    
    c.execute('SELECT COUNT(*) FROM game_players WHERE room_id = ? AND status != "forfeited"', (room_id,))
    remaining = c.fetchone()[0]
    if remaining == 0:
        c.execute('UPDATE game_rooms SET status = ? WHERE id = ?', ('cancelled', room_id))
        if room_id in active_games:
            del active_games[room_id]
    
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/games/scores')
@login_required
def get_scores():
    """Get global leaderboard and personal stats"""
    conn = get_db()
    c = conn.cursor()
    
    c.execute('''SELECT game_type, COUNT(*) as games_played, 
                 SUM(CASE WHEN is_win THEN 1 ELSE 0 END) as wins,
                 MAX(score) as high_score
                 FROM game_scores 
                 WHERE user_id = ?
                 GROUP BY game_type''', (session['user_id'],))
    my_stats = [dict(row) for row in c.fetchall()]
    
    c.execute('''SELECT u.username, s.game_type, COUNT(*) as wins
                 FROM game_scores s
                 JOIN users u ON s.user_id = u.id
                 WHERE s.is_win = 1
                 GROUP BY s.user_id, s.game_type
                 ORDER BY wins DESC
                 LIMIT 20''')
    leaderboard = [dict(row) for row in c.fetchall()]
    
    c.execute('''SELECT * FROM achievements WHERE user_id = ? ORDER BY unlocked_at DESC''',
              (session['user_id'],))
    achievements = [dict(row) for row in c.fetchall()]
    
    conn.close()
    return jsonify({
        'my_stats': my_stats,
        'leaderboard': leaderboard,
        'achievements': achievements
    })

@app.route('/api/games/singleplayer/<game_type>', methods=['POST'])
@login_required
def single_player_game(game_type):
    """Record single player game result"""
    data = request.json
    score = data.get('score', 0)
    
    conn = get_db()
    c = conn.cursor()
    c.execute('''INSERT INTO game_scores (user_id, game_type, score, is_win, opponent_id) 
                 VALUES (?, ?, ?, 1, NULL)''',
              (session['user_id'], game_type, score))
    
    c.execute('''SELECT MAX(score) FROM game_scores 
                 WHERE user_id = ? AND game_type = ?''',
              (session['user_id'], game_type))
    high_score = c.fetchone()[0]
    
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'new_high_score': high_score == score})

# Debug endpoint
@app.route('/api/debug/data')
def debug_data():
    """Debug endpoint to verify data persistence"""
    info = {
        'base_dir': str(BASE_DIR.absolute()),
        'database_path': str(DATABASE.absolute()),
        'database_exists': DATABASE.exists(),
        'upload_folder': str(UPLOAD_FOLDER.absolute()),
        'tables': []
    }
    
    if DATABASE.exists():
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='table'")
        info['tables'] = [row[0] for row in c.fetchall()]
        try:
            c.execute("SELECT COUNT(*) FROM users")
            info['user_count'] = c.fetchone()[0]
        except:
            info['user_count'] = 0
        conn.close()
    
    return jsonify(info)

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
            .auth-box { padding: 25px; border-radius: 15px; }
        }
        
        .auth-box h1 { color: #667eea; margin-bottom: 10px; font-size: 32px; }
        .auth-box p { color: #666; margin-bottom: 30px; }
        
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 5px; color: #333; font-weight: 500; }
        .form-group input {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        .form-group input:focus { outline: none; border-color: #667eea; }
        
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
        .btn:hover { transform: translateY(-2px); }
        .btn:active { transform: translateY(0); }
        
        .switch-auth { text-align: center; margin-top: 20px; color: #666; }
        .switch-auth a { color: #667eea; text-decoration: none; font-weight: 600; }
        
        .error {
            background: #fee;
            color: #c33;
            padding: 10px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: none;
        }
        
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
        
        .app-header h1 { color: #667eea; font-size: 20px; }
        @media (max-width: 768px) { .app-header h1 { font-size: 18px; } }
        
        .user-info { display: flex; align-items: center; gap: 15px; }
        
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
            .mobile-menu-btn { display: block; }
            .sidebar {
                position: fixed;
                left: 0;
                top: 70px;
                bottom: 0;
                z-index: 999;
                transform: translateX(-100%);
                box-shadow: 2px 0 10px rgba(0,0,0,0.2);
            }
            .sidebar.open { transform: translateX(0); }
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
            .sidebar-overlay.show { display: block; }
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
        .nav-item:hover { background: #f0f0f0; }
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
        @media (max-width: 768px) { .content { padding: 15px; width: 100%; } }
        
        .panel { display: none; }
        .panel.active { display: block; }
        
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
        .post-author { font-weight: 600; color: #333; }
        .post-time { color: #999; font-size: 12px; }
        .post-content {
            color: #333;
            line-height: 1.6;
            margin-bottom: 10px;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .post-actions { display: flex; gap: 15px; color: #666; font-size: 14px; }
        .like-btn { cursor: pointer; transition: color 0.2s; }
        .like-btn:hover, .like-btn.liked { color: #e91e63; }
        
        .message {
            padding: 10px 15px;
            background: #f5f5f5;
            border-radius: 8px;
            margin-bottom: 10px;
        }
        .message-sender { font-weight: 600; color: #667eea; font-size: 13px; }
        .message-content { color: #333; margin-top: 5px; }
        
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
        .file-info h4 { color: #333; margin-bottom: 5px; }
        .file-meta { color: #999; font-size: 12px; }
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
        @media (max-width: 768px) { .media-grid { grid-template-columns: 1fr; } }
        
        .media-item {
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }
        .media-item video, .media-item audio { width: 100%; }
        .media-info { padding: 15px; }
        .media-title { font-weight: 600; color: #333; margin-bottom: 5px; }
        .media-meta { color: #999; font-size: 12px; }
        
        .input-group { margin-bottom: 15px; }
        .input-group label { display: block; margin-bottom: 5px; font-weight: 500; color: #333; }
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
            .chat-container { flex-direction: column; height: auto; max-height: calc(100vh - 120px); }
        }
        
        .chat-sidebar {
            width: 250px;
            background: white;
            border-radius: 12px;
            padding: 15px;
            overflow-y: auto;
        }
        @media (max-width: 768px) { .chat-sidebar { width: 100%; max-height: 200px; } }
        
        .chat-main {
            flex: 1;
            background: white;
            border-radius: 12px;
            display: flex;
            flex-direction: column;
            min-height: 400px;
        }
        @media (max-width: 768px) { .chat-main { min-height: 300px; } }
        
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
        .user-item:hover { background: #f5f5f5; }
        .user-item.active { background: #667eea; color: white; }
        
        .upload-area {
            border: 2px dashed #e0e0e0;
            border-radius: 12px;
            padding: 40px;
            text-align: center;
            cursor: pointer;
            transition: border-color 0.3s;
        }
        .upload-area:hover { border-color: #667eea; }
        .upload-area.dragover { border-color: #667eea; background: #f0f0ff; }
        
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
        .notification-panel.show { display: flex; }
        @media (max-width: 768px) {
            .notification-panel { right: 10px; left: 10px; width: auto; }
        }
        
        .notification-header {
            padding: 15px;
            border-bottom: 1px solid #e0e0e0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .notification-header h3 { font-size: 16px; }
        .mark-all-read { color: #667eea; font-size: 12px; cursor: pointer; }
        
        .notification-list { flex: 1; overflow-y: auto; max-height: 400px; }
        
        .notification-item {
            padding: 15px;
            border-bottom: 1px solid #f0f0f0;
            cursor: pointer;
            transition: background 0.2s;
        }
        .notification-item:hover { background: #f8f8f8; }
        .notification-item.unread { background: #f0f0ff; }
        .notification-title { font-weight: 600; color: #333; margin-bottom: 5px; }
        .notification-message { color: #666; font-size: 13px; margin-bottom: 5px; }
        .notification-time { color: #999; font-size: 11px; }
        
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
        .call-modal.show { display: flex; }
        
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
        .call-username { font-size: 28px; color: white; margin-bottom: 10px; }
        .call-status { color: #aaa; margin-bottom: 30px; }
        .call-timer { color: #667eea; font-size: 18px; margin-bottom: 20px; display: none; }
        .call-buttons { display: flex; gap: 20px; justify-content: center; }
        
        .call-btn {
            width: 60px;
            height: 60px;
            border-radius: 50%;
            border: none;
            font-size: 24px;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .call-btn:hover { transform: scale(1.1); }
        .call-btn-answer { background: #4caf50; color: white; }
        .call-btn-reject, .call-btn-end { background: #f44336; color: white; }
        .call-btn-mute { background: #555; color: white; }
        .call-btn-video { background: #667eea; color: white; }
        
        .video-container { position: relative; width: 100%; max-width: 800px; margin: 20px auto; }
        .video-main { width: 100%; border-radius: 12px; background: #000; }
        .video-self {
            position: absolute;
            bottom: 20px;
            right: 20px;
            width: 150px;
            border-radius: 8px;
            border: 2px solid white;
        }
        @media (max-width: 768px) {
            .call-container { padding: 30px 20px; }
            .call-avatar { width: 100px; height: 100px; font-size: 40px; }
            .call-username { font-size: 22px; }
            .video-self { width: 100px; bottom: 10px; right: 10px; }
        }
        
        /* COMMENTS & FORUM STYLES */
        .comments-section { margin-top: 15px; border-top: 1px solid #e0e0e0; padding-top: 15px; }
        .comment {
            display: flex;
            gap: 12px;
            margin-bottom: 15px;
            animation: fadeIn 0.3s ease-in;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .comment-avatar {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
            font-weight: bold;
            flex-shrink: 0;
        }
        .comment-content {
            flex: 1;
            background: #f5f5f5;
            padding: 10px 15px;
            border-radius: 12px;
            border-bottom-left-radius: 4px;
        }
        .comment-header { display: flex; justify-content: space-between; margin-bottom: 5px; font-size: 13px; }
        .comment-author { font-weight: 600; color: #667eea; }
        .comment-time { color: #999; font-size: 11px; }
        .comment-text { color: #333; line-height: 1.4; word-wrap: break-word; }
        .comment-actions { display: flex; gap: 15px; margin-top: 8px; font-size: 12px; color: #666; }
        .comment-action { cursor: pointer; transition: color 0.2s; }
        .comment-action:hover { color: #667eea; }
        .comment-action.liked { color: #e91e63; }
        .nested-comments { margin-left: 44px; margin-top: 10px; border-left: 2px solid #e0e0e0; padding-left: 15px; }
        .comment-input-area { display: flex; gap: 10px; margin-top: 15px; }
        .comment-input-area input {
            flex: 1;
            padding: 10px 15px;
            border: 1px solid #e0e0e0;
            border-radius: 20px;
            font-size: 14px;
        }
        .comment-input-area button {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 20px;
            cursor: pointer;
        }
        .reply-form { margin-top: 10px; display: none; }
        .reply-form.active { display: block; }
        
        /* MODALS */
        .post-detail-modal {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.8);
            z-index: 2000;
            display: none;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .post-detail-modal.show { display: flex; }
        .post-detail-container {
            background: white;
            border-radius: 16px;
            max-width: 600px;
            width: 100%;
            max-height: 90vh;
            overflow-y: auto;
            position: relative;
        }
        .close-modal {
            position: absolute;
            top: 15px;
            right: 15px;
            font-size: 24px;
            cursor: pointer;
            z-index: 10;
        }
        .stats-bar {
            display: flex;
            gap: 20px;
            padding: 15px 20px;
            border-top: 1px solid #e0e0e0;
            border-bottom: 1px solid #e0e0e0;
            color: #666;
            font-size: 14px;
        }
        .stat-item { cursor: pointer; transition: color 0.2s; }
        .stat-item:hover { color: #667eea; }
        
        .status-indicator {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 5px;
        }
        .status-online { background: #4caf50; }
        .status-offline { background: #999; }
        .status-in-call { background: #ff9800; }
        
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
        
        /* GAMING STYLES */
        .game-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 12px;
            cursor: pointer;
            transition: transform 0.2s;
            text-align: center;
        }
        .game-card:hover { transform: translateY(-5px); }
        .game-tag {
            background: rgba(255,255,255,0.2);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            display: inline-block;
            margin-top: 10px;
        }
        .game-room-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px;
            background: #f5f5f5;
            border-radius: 8px;
            margin-bottom: 10px;
        }
        .chess-board {
            display: grid;
            grid-template-columns: repeat(8, 1fr);
            max-width: 400px;
            aspect-ratio: 1;
            border: 2px solid #333;
            margin: 0 auto;
        }
        .chess-cell {
            aspect-ratio: 1;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2em;
            cursor: pointer;
        }
        .chess-cell:nth-child(16n+1), .chess-cell:nth-child(16n+3), 
        .chess-cell:nth-child(16n+5), .chess-cell:nth-child(16n+7),
        .chess-cell:nth-child(16n+10), .chess-cell:nth-child(16n+12),
        .chess-cell:nth-child(16n+14), .chess-cell:nth-child(16n+16) {
            background: #769656;
        }
        .chess-cell:nth-child(16n+2), .chess-cell:nth-child(16n+4),
        .chess-cell:nth-child(16n+6), .chess-cell:nth-child(16n+8),
        .chess-cell:nth-child(16n+9), .chess-cell:nth-child(16n+11),
        .chess-cell:nth-child(16n+13), .chess-cell:nth-child(16n+15) {
            background: #eeeed2;
        }
        .chess-cell.selected { background: rgba(255,255,0,0.5) !important; }
        .tictactoe-board {
            display: grid;
            grid-template-columns: repeat(3, 100px);
            gap: 5px;
            margin: 20px auto;
            width: fit-content;
        }
        .tictactoe-cell {
            width: 100px;
            height: 100px;
            background: #f0f0f0;
            border: 2px solid #667eea;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2em;
            cursor: pointer;
            border-radius: 8px;
        }
        .tictactoe-cell:hover { background: #e0e0ff; }
        #snakeCanvas { background: #000; border-radius: 8px; display: block; margin: 0 auto; }
        
        .forum-thread-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
        }
        .forum-thread-content { padding: 20px; line-height: 1.6; font-size: 16px; border-bottom: 1px solid #e0e0e0; }
        .forum-comments-section { padding: 20px; background: #fafafa; }
        .forum-comment { background: white; padding: 15px; border-radius: 8px; margin-bottom: 15px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
    </style>
</head>
<body>
    <!-- AUTH UI -->
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
    
    <!-- MAIN APP -->
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
        
        <!-- NOTIFICATION PANEL -->
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
                <div class="nav-item active" onclick="showPanel('discover'); closeMobileMenu();">🔍 Discover</div>
                <div class="nav-item" onclick="showPanel('posts'); closeMobileMenu();">🐦 Posts</div>
                <div class="nav-item" onclick="showPanel('forums'); closeMobileMenu();">💬 Forums</div>
                <div class="nav-item" onclick="showPanel('chat'); closeMobileMenu();">💭 Chat</div>
                <div class="nav-item" onclick="showPanel('games'); closeMobileMenu();">🎮 Games</div>
                <div class="nav-item" onclick="showPanel('photos'); closeMobileMenu();">📷 Photos</div>
                <div class="nav-item" onclick="showPanel('streaming'); closeMobileMenu();">📺 Live</div>
                <div class="nav-item" onclick="showPanel('media'); closeMobileMenu();">🎬 Media</div>
                <div class="nav-item" onclick="showPanel('pastebin'); closeMobileMenu();">📋 Pastebin</div>
                <div class="nav-item" onclick="showPanel('notes'); closeMobileMenu();">📝 Notes</div>
                <div class="nav-item" onclick="showPanel('tasks'); closeMobileMenu();">✅ Tasks</div>
                <div class="nav-item" onclick="showPanel('calendar'); closeMobileMenu();">📅 Calendar</div>
                <div class="nav-item" onclick="showPanel('files'); closeMobileMenu();">📁 Files</div>
            </div>
            <button class="mobile-menu-btn" id="mobileMenuBtn" onclick="toggleMobileMenu()">☰</button>
            
            <div class="content">
                <!-- DISCOVER -->
                <div id="discoverPanel" class="panel active">
                    <div class="card">
                        <h2>🎉 Welcome to LAN World!</h2>
                        <p>Your complete digital ecosystem, running entirely on your local network.</p>
                        <br>
                        <h3>🎮 Featured:</h3>
                        <ul style="margin-left: 20px; margin-top: 10px; line-height: 1.8;">
                            <li><strong>🐦 Posts</strong> - Microblogging with threaded comments</li>
                            <li><strong>💬 Forums</strong> - Deep discussions with nested replies</li>
                            <li><strong>🎮 Games</strong> - Chess, Tic-Tac-Toe, Snake Battles</li>
                            <li><strong>💭 Chat</strong> - Real-time messaging with voice/video</li>
                        </ul>
                    </div>
                </div>
                
                <!-- POSTS -->
                <div id="postsPanel" class="panel">
                    <div class="card">
                        <h2>Create a Post</h2>
                        <textarea id="postContent" class="post-input" placeholder="What's on your mind?"></textarea>
                        <button class="post-btn" onclick="createPost()">Post</button>
                    </div>
                    <div id="postsFeed"></div>
                </div>
                
                <!-- FORUMS -->
                <div id="forumsPanel" class="panel">
                    <div class="card">
                        <h2>Create Forum Thread</h2>
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
                            </select>
                        </div>
                        <div class="input-group">
                            <label>Content</label>
                            <textarea id="forumContent" class="forum-input" placeholder="Discussion content..."></textarea>
                        </div>
                        <button class="submit-btn" onclick="createForum()">Create Thread</button>
                    </div>
                    <div id="forumsList"></div>
                </div>
                
                <!-- CHAT -->
                <div id="chatPanel" class="panel">
                    <div class="chat-container">
                        <div class="chat-sidebar">
                            <h3 style="margin-bottom: 15px;">Channels</h3>
                            <div class="user-item active" onclick="selectChannel('general')"># general</div>
                            <div class="user-item" onclick="selectChannel('random')"># random</div>
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
                
                <!-- GAMES -->
                <div id="gamesPanel" class="panel">
                    <div class="card">
                        <h2>🎮 Game Center</h2>
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px;">
                            <div class="game-card" onclick="createGameRoom('chess')">
                                <h3>♟️ Chess</h3>
                                <p>Classic strategy</p>
                                <span class="game-tag">2 Players</span>
                            </div>
                            <div class="game-card" onclick="createGameRoom('tictactoe')">
                                <h3>⭕ Tic-Tac-Toe</h3>
                                <p>Quick matches</p>
                                <span class="game-tag">2 Players</span>
                            </div>
                            <div class="game-card" onclick="startSnake()">
                                <h3>🐍 Snake</h3>
                                <p>Single player</p>
                                <span class="game-tag">Solo</span>
                            </div>
                        </div>
                    </div>
                    <div class="card">
                        <h3>🚪 Active Rooms</h3>
                        <div id="gameRoomsList"></div>
                    </div>
                </div>
                
                <!-- PHOTOS -->
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
                
                <!-- STREAMING -->
                <div id="streamingPanel" class="panel">
                    <div class="card">
                        <h2>📺 Go Live</h2>
                        <div id="streamControls">
                            <div class="input-group">
                                <label>Stream Title</label>
                                <input type="text" id="streamTitle" placeholder="What are you streaming?">
                            </div>
                            <button class="submit-btn" onclick="startStream()">🔴 Start Streaming</button>
                        </div>
                        <div id="streamView" style="display: none;">
                            <video id="streamVideo" autoplay playsinline style="width: 100%; border-radius: 12px; background: #000;"></video>
                            <button class="submit-btn" onclick="endStreamSession()" style="background: #f44336; margin-top: 10px;">End Stream</button>
                        </div>
                    </div>
                    <h3 style="margin: 20px 0;">Live Now:</h3>
                    <div id="liveStreams"></div>
                </div>
                
                <!-- MEDIA -->
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
                
                <!-- PASTEBIN -->
                <div id="pastebinPanel" class="panel">
                    <div class="card">
                        <h2>Create Paste</h2>
                        <div class="input-group">
                            <label>Title</label>
                            <input type="text" id="pasteTitle" placeholder="Untitled">
                        </div>
                        <div class="input-group">
                            <label>Content</label>
                            <textarea id="pasteContent" style="min-height: 200px; font-family: monospace;" placeholder="Paste your code..."></textarea>
                        </div>
                        <button class="submit-btn" onclick="createPaste()">Create Paste</button>
                    </div>
                    <div id="pastesList"></div>
                </div>
                
                <!-- NOTES -->
                <div id="notesPanel" class="panel">
                    <div class="card">
                        <h2>New Note</h2>
                        <div class="input-group">
                            <label>Content</label>
                            <textarea id="noteContent" style="min-height: 120px;" placeholder="Write your note..."></textarea>
                        </div>
                        <button class="submit-btn" onclick="createNote()">Create Note</button>
                    </div>
                    <div id="notesGrid"></div>
                </div>
                
                <!-- TASKS -->
                <div id="tasksPanel" class="panel">
                    <div class="card">
                        <h2>New Task</h2>
                        <div class="input-group">
                            <label>Task</label>
                            <input type="text" id="taskTitle" placeholder="What needs to be done?">
                        </div>
                        <button class="submit-btn" onclick="createTask()">Add Task</button>
                    </div>
                    <div id="tasksList"></div>
                </div>
                
                <!-- CALENDAR -->
                <div id="calendarPanel" class="panel">
                    <div class="card">
                        <h2>New Event</h2>
                        <div class="input-group">
                            <label>Event Title</label>
                            <input type="text" id="eventTitle" placeholder="Event name">
                        </div>
                        <div class="input-group">
                            <label>Start Time</label>
                            <input type="datetime-local" id="eventStart">
                        </div>
                        <button class="submit-btn" onclick="createEvent()">Create Event</button>
                    </div>
                    <div id="eventsList"></div>
                </div>
                
                <!-- FILES -->
                <div id="filesPanel" class="panel">
                    <div class="card">
                        <h2>Upload File</h2>
                        <div class="upload-area" onclick="document.getElementById('fileInput').click()">
                            <h3>📤 Click to upload</h3>
                        </div>
                        <input type="file" id="fileInput" style="display: none;" onchange="uploadFile()">
                    </div>
                    <div id="filesList"></div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- POST DETAIL MODAL -->
    <div id="postDetailModal" class="post-detail-modal" onclick="if(event.target === this) closePostDetail()">
        <div class="post-detail-container">
            <span class="close-modal" onclick="closePostDetail()">&times;</span>
            <div style="padding: 20px;">
                <div class="post-header">
                    <span class="post-author" id="detailPostAuthor">@user</span>
                    <span class="post-time" id="detailPostTime"></span>
                </div>
                <div class="post-content" id="detailPostContent" style="margin: 15px 0; font-size: 18px;"></div>
                <div class="stats-bar">
                    <span class="stat-item" id="detailLikeBtn" style="cursor: pointer;">
                        ❤️ <span id="detailPostLikes">0 likes</span>
                    </span>
                    <span class="stat-item">
                        💬 <span id="detailPostComments">0 comments</span>
                    </span>
                </div>
                <div class="comment-input-area" style="margin: 20px 0;">
                    <input type="text" id="mainCommentInput" placeholder="Write a comment..." onkeypress="if(event.key==='Enter') submitComment()">
                    <button onclick="submitComment()">Comment</button>
                </div>
                <h4 style="margin-bottom: 15px;">Comments</h4>
                <div id="detailCommentsList" style="max-height: 400px; overflow-y: auto;"></div>
            </div>
        </div>
    </div>
    
    <!-- FORUM THREAD MODAL -->
    <div id="forumThreadModal" class="post-detail-modal" onclick="if(event.target === this) closeForumThread()">
        <div class="post-detail-container">
            <span class="close-modal" onclick="closeForumThread()">&times;</span>
            <div id="forumThreadContentDiv">
                <!-- Content injected here -->
            </div>
        </div>
    </div>
    
    <!-- GAME ARENA -->
    <div id="gameArena" class="panel" style="display: none; padding: 20px;">
        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <h2 id="gameTitle">Game Room</h2>
                <button class="submit-btn" onclick="leaveGame()" style="background: #f44336;">Leave Game</button>
            </div>
            <div id="gameBoard" style="margin-top: 20px;"></div>
        </div>
    </div>
    
    <!-- CALL MODAL -->
    <div id="callModal" class="call-modal">
        <div class="call-container">
            <div class="video-container" id="videoContainer" style="display: none;">
                <video id="remoteVideo" class="video-main" autoplay playsinline></video>
                <video id="localVideo" class="video-self" autoplay playsinline muted></video>
            </div>
            <div class="call-avatar" id="callAvatar">👤</div>
            <div class="call-username" id="callUsername">User</div>
            <div class="call-status" id="callStatus">Calling...</div>
            <div class="call-timer" id="callTimer">00:00</div>
            <div class="call-buttons">
                <button class="call-btn call-btn-answer" id="answerBtn" onclick="answerCall()" style="display: none;">📞</button>
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
        let currentPostId = null;
        let currentForumId = null;
        let replyToCommentId = null;
        let currentGameRoom = null;
        let gameRefreshInterval = null;
        let currentCall = null;
        let localStream = null;
        let callTimerInterval = null;
        let callStartTime = null;
        let currentStream = null;
        
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
            location.reload();
        }
        
        function showApp() {
            document.getElementById('authContainer').style.display = 'none';
            document.getElementById('appContainer').style.display = 'flex';
            document.getElementById('currentUsername').textContent = currentUser.username;
            
            loadPosts();
            loadForums();
            loadUsers();
            loadMedia();
            loadFiles();
            loadMessages();
            loadNotifications();
            
            refreshInterval = setInterval(() => {
                if (currentChatMode === 'channel') loadMessages();
            }, 3000);
            
            setInterval(() => {
                loadNotifications();
            }, 10000);
        }
        
        function showPanel(panelName) {
            if (panelName === 'gameArena') {
                document.querySelectorAll('.panel').forEach(p => p.style.display = 'none');
                document.getElementById('gameArena').style.display = 'block';
                return;
            }
            
            document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            
            document.getElementById(panelName + 'Panel').classList.add('active');
            event.target.classList.add('active');
            
            if (panelName === 'posts') loadPosts();
            if (panelName === 'forums') loadForums();
            if (panelName === 'chat') loadMessages();
            if (panelName === 'games') { loadGameRooms(); }
            if (panelName === 'photos') loadPhotos();
            if (panelName === 'streaming') loadStreams();
            if (panelName === 'media') loadMedia();
            if (panelName === 'pastebin') loadPastes();
            if (panelName === 'notes') loadNotes();
            if (panelName === 'tasks') loadTasks();
            if (panelName === 'calendar') loadEvents();
            if (panelName === 'files') loadFiles();
        }
        
        // FORMATTING
        function formatPostContent(content) {
            return content
                .replace(/\\*\\*(.*?)\\*\\*/g, '<strong>$1</strong>')
                .replace(/\\*(.*?)\\*/g, '<em>$1</em>')
                .replace(/`([^`]+)`/g, '<code>$1</code>')
                .replace(/\\n/g, '<br>');
        }
        
        // POSTS
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
                <div class="post" onclick="openPostDetail(${post.id})" style="cursor: pointer;">
                    <div class="post-header">
                        <span class="post-author">@${post.username}</span>
                        <span class="post-time">${new Date(post.created_at).toLocaleString()}</span>
                    </div>
                    <div class="post-content">${formatPostContent(post.content)}</div>
                    <div class="post-actions" onclick="event.stopPropagation()">
                        <span class="like-btn ${post.user_liked ? 'liked' : ''}" onclick="likePost(${post.id})">
                            ❤️ ${post.likes}
                        </span>
                        <span style="color: #666;">💬 ${post.comment_count || 0}</span>
                    </div>
                </div>
            `).join('');
        }
        
        async function likePost(postId) {
            await fetch(`/api/posts/${postId}/like`, {method: 'POST'});
            loadPosts();
        }
        
        // POST DETAIL & COMMENTS
        async function openPostDetail(postId) {
            currentPostId = postId;
            document.getElementById('postDetailModal').classList.add('show');
            await loadPostDetail(postId);
        }
        
        function closePostDetail() {
            document.getElementById('postDetailModal').classList.remove('show');
            currentPostId = null;
        }
        
        async function loadPostDetail(postId) {
            const postRes = await fetch(`/api/posts/${postId}`);
            const post = await postRes.json();
            
            document.getElementById('detailPostContent').innerHTML = formatPostContent(post.content);
            document.getElementById('detailPostAuthor').textContent = '@' + post.username;
            document.getElementById('detailPostTime').textContent = new Date(post.created_at).toLocaleString();
            document.getElementById('detailPostLikes').textContent = post.likes + ' likes';
            document.getElementById('detailPostComments').textContent = (post.comment_count || 0) + ' comments';
            
            const likeBtn = document.getElementById('detailLikeBtn');
            likeBtn.style.color = post.user_liked ? '#e91e63' : '#666';
            likeBtn.onclick = () => { likePost(postId); loadPostDetail(postId); };
            
            loadPostComments(postId);
        }
        
        async function loadPostComments(postId) {
            const res = await fetch(`/api/posts/${postId}/comments`);
            const comments = await res.json();
            renderCommentsTree(comments, document.getElementById('detailCommentsList'));
        }
        
        function renderCommentsTree(comments, container, isNested = false) {
            container.innerHTML = '';
            
            if (comments.length === 0 && !isNested) {
                container.innerHTML = '<div style="text-align: center; color: #999; padding: 20px;">No comments yet</div>';
                return;
            }
            
            comments.forEach(comment => {
                const div = document.createElement('div');
                div.className = 'comment';
                if (isNested) div.style.marginLeft = '44px';
                
                div.innerHTML = `
                    <div class="comment-avatar">${comment.username[0].toUpperCase()}</div>
                    <div style="flex: 1;">
                        <div class="comment-content">
                            <div class="comment-header">
                                <span class="comment-author">@${comment.username}</span>
                                <span class="comment-time">${new Date(comment.created_at).toLocaleString()}</span>
                            </div>
                            <div class="comment-text">${formatPostContent(comment.content)}</div>
                            <div class="comment-actions">
                                <span class="comment-action" onclick="likeComment(${comment.id})">
                                    ❤️ ${comment.like_count || 0}
                                </span>
                                <span class="comment-action" onclick="showReplyForm(${comment.id})">
                                    💬 Reply
                                </span>
                            </div>
                        </div>
                        <div id="replyForm-${comment.id}" class="reply-form">
                            <div class="comment-input-area" style="margin-top: 10px;">
                                <input type="text" id="replyInput-${comment.id}" placeholder="Write a reply..." 
                                       onkeypress="if(event.key==='Enter') submitReply(${comment.id})">
                                <button onclick="submitReply(${comment.id})">Reply</button>
                            </div>
                        </div>
                        <div id="replies-${comment.id}"></div>
                    </div>
                `;
                
                container.appendChild(div);
                
                if (comment.replies && comment.replies.length > 0) {
                    const repliesContainer = div.querySelector(`#replies-${comment.id}`);
                    repliesContainer.className = 'nested-comments';
                    renderCommentsTree(comment.replies, repliesContainer, true);
                }
            });
        }
        
        async function submitComment() {
            const input = document.getElementById('mainCommentInput');
            const content = input.value.trim();
            if (!content || !currentPostId) return;
            
            await fetch(`/api/posts/${currentPostId}/comments`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({content, parent_id: replyToCommentId})
            });
            
            input.value = '';
            replyToCommentId = null;
            loadPostComments(currentPostId);
        }
        
        function showReplyForm(commentId) {
            document.querySelectorAll('.reply-form').forEach(f => f.classList.remove('active'));
            const form = document.getElementById(`replyForm-${commentId}`);
            if (form) form.classList.add('active');
            replyToCommentId = commentId;
        }
        
        async function submitReply(commentId) {
            const input = document.getElementById(`replyInput-${commentId}`);
            const content = input.value.trim();
            if (!content || !currentPostId) return;
            
            await fetch(`/api/posts/${currentPostId}/comments`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({content, parent_id: commentId})
            });
            
            loadPostComments(currentPostId);
        }
        
        async function likeComment(commentId) {
            await fetch(`/api/comments/${commentId}/like`, {method: 'POST'});
            if (currentPostId) loadPostComments(currentPostId);
        }
        
        // FORUMS
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
                <div class="post" onclick="openForumThread(${forum.id})" style="cursor: pointer;">
                    <div class="post-header">
                        <div>
                            <strong>${forum.title}</strong>
                            <span style="background: #667eea; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; margin-left: 10px;">
                                ${forum.category}
                            </span>
                        </div>
                    </div>
                    <div class="post-content" style="max-height: 60px; overflow: hidden;">${formatPostContent(forum.content)}</div>
                    <div class="post-actions">
                        <span>👤 ${forum.username}</span>
                        <span>💬 ${forum.comment_count} comments</span>
                    </div>
                </div>
            `).join('');
        }
        
        async function openForumThread(forumId) {
            currentForumId = forumId;
            const res = await fetch(`/api/forums/${forumId}`);
            const forum = await res.json();
            
            const modal = document.getElementById('forumThreadModal');
            const contentDiv = document.getElementById('forumThreadContentDiv');
            
            contentDiv.innerHTML = `
                <div class="forum-thread-header">
                    <span style="background: rgba(255,255,255,0.2); padding: 4px 12px; border-radius: 20px; font-size: 12px; display: inline-block; margin-bottom: 10px;">
                        ${forum.category}
                    </span>
                    <h2>${forum.title}</h2>
                    <div style="opacity: 0.9; font-size: 14px; margin-top: 10px;">
                        👤 @${forum.username} • 🕐 ${new Date(forum.created_at).toLocaleString()}
                    </div>
                </div>
                <div class="forum-thread-content">${formatPostContent(forum.content)}</div>
                <div class="forum-comments-section">
                    <h3>Discussion</h3>
                    <div style="margin: 15px 0;">
                        <textarea id="forumCommentInput" class="forum-input" placeholder="Add to the discussion..." style="min-height: 80px;"></textarea>
                        <button class="submit-btn" onclick="submitForumComment()" style="margin-top: 10px;">Post Comment</button>
                    </div>
                    <div id="forumCommentsList">
                        ${forum.comments.map(c => `
                            <div class="forum-comment">
                                <div class="forum-comment-header">
                                    <strong>@${c.username}</strong>
                                    <span>${new Date(c.created_at).toLocaleString()}</span>
                                </div>
                                <div>${formatPostContent(c.content)}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
            
            modal.classList.add('show');
        }
        
        function closeForumThread() {
            document.getElementById('forumThreadModal').classList.remove('show');
            currentForumId = null;
        }
        
        async function submitForumComment() {
            const content = document.getElementById('forumCommentInput').value.trim();
            if (!content || !currentForumId) return;
            
            await fetch(`/api/forums/${currentForumId}/comments`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({content})
            });
            
            openForumThread(currentForumId); // Refresh
        }
        
        // CHAT
        async function loadUsers() {
            const res = await fetch('/api/users');
            const users = await res.json();
            
            const list = document.getElementById('usersList');
            list.innerHTML = users.map(user => `
                <div class="user-item" onclick="selectUser(${user.id})">
                    @${user.username}
                    <button class="user-call-btn" onclick="event.stopPropagation(); initiateCall(${user.id}, '${user.username}')">📞</button>
                </div>
            `).join('');
        }
        
        function selectChannel(channel) {
            currentChatMode = 'channel';
            currentChannel = channel;
            currentRecipient = null;
            document.querySelectorAll('.chat-sidebar .user-item').forEach(el => el.classList.remove('active'));
            event.target.classList.add('active');
            loadMessages();
        }
        
        function selectUser(userId) {
            currentChatMode = 'dm';
            currentRecipient = userId;
            document.querySelectorAll('.chat-sidebar .user-item').forEach(el => el.classList.remove('active'));
            event.target.classList.add('active');
            loadMessages();
        }
        
        async function sendMessage() {
            const input = document.getElementById('messageInput');
            const content = input.value.trim();
            if (!content) return;
            
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
            
            input.value = '';
            loadMessages();
        }
        
        async function loadMessages() {
            const params = new URLSearchParams();
            if (currentChatMode === 'dm') {
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
        
        // GAMING
        async function createGameRoom(gameType) {
            const roomName = prompt('Name your game room:');
            if (!roomName) return;
            
            const res = await fetch('/api/games/rooms', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({game_type: gameType, room_name: roomName})
            });
            const data = await res.json();
            
            if (data.success) {
                enterGameRoom(data.room_id);
            }
        }
        
        async function loadGameRooms() {
            const res = await fetch('/api/games/rooms');
            const rooms = await res.json();
            
            const list = document.getElementById('gameRoomsList');
            if (rooms.length === 0) {
                list.innerHTML = '<p style="color: #999;">No active rooms</p>';
            } else {
                list.innerHTML = rooms.map(room => `
                    <div class="game-room-item">
                        <div>
                            <strong>${room.room_name}</strong>
                            <div style="font-size: 12px; color: #666;">${room.game_type} by ${room.host_name}</div>
                        </div>
                        <button class="btn" style="padding: 8px 20px;" onclick="joinGameRoom(${room.id})">Join</button>
                    </div>
                `).join('');
            }
        }
        
        async function joinGameRoom(roomId) {
            const res = await fetch(`/api/games/rooms/${roomId}/join`, {method: 'POST'});
            const data = await res.json();
            if (data.success) enterGameRoom(roomId);
        }
        
        async function enterGameRoom(roomId) {
            currentGameRoom = roomId;
            document.getElementById('gamesPanel').style.display = 'none';
            document.getElementById('gameArena').style.display = 'block';
            gameRefreshInterval = setInterval(() => refreshGameState(roomId), 1000);
            refreshGameState(roomId);
        }
        
        async function refreshGameState(roomId) {
            const res = await fetch(`/api/games/rooms/${roomId}/state`);
            const state = await res.json();
            renderGame(state);
        }
        
        function renderGame(state) {
            const board = document.getElementById('gameBoard');
            
            if (state.game_type === 'chess') {
                renderChess(state, board);
            } else if (state.game_type === 'tictactoe') {
                renderTicTacToe(state, board);
            }
        }
        
        function renderChess(state, container) {
            const pieces = {
                'r': '♜', 'n': '♞', 'b': '♝', 'q': '♛', 'k': '♚',
                'p': '♟', 'R': '♖', 'N': '♘', 'B': '♗', 'Q': '♕', 'K': '♔', 'P': '♙'
            };
            
            let html = '<div class="chess-board">';
            for (let row = 0; row < 8; row++) {
                for (let col = 0; col < 8; col++) {
                    const piece = state.board[row][col];
                    html += `<div class="chess-cell" onclick="chessClick(${row}, ${col})">${pieces[piece] || ''}</div>`;
                }
            }
            html += '</div>';
            html += `<div style="text-align: center; margin-top: 15px;">Turn: Player ${state.turn}</div>`;
            container.innerHTML = html;
        }
        
        let selectedChessSquare = null;
        function chessClick(row, col) {
            if (!selectedChessSquare) {
                selectedChessSquare = [row, col];
            } else {
                makeGameMove({from: selectedChessSquare, to: [row, col]});
                selectedChessSquare = null;
            }
        }
        
        function renderTicTacToe(state, container) {
            let html = '<div class="tictactoe-board">';
            for (let i = 0; i < 9; i++) {
                const val = state.board[i];
                html += `<div class="tictactoe-cell" onclick="makeGameMove({position: ${i}})">${val}</div>`;
            }
            html += '</div>';
            html += `<div style="text-align: center; margin-top: 15px;">Turn: ${state.turn === 1 ? '❌' : '⭕'}</div>`;
            container.innerHTML = html;
        }
        
        async function makeGameMove(move) {
            await fetch(`/api/games/rooms/${currentGameRoom}/move`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({move})
            });
            refreshGameState(currentGameRoom);
        }
        
        async function leaveGame() {
            if (currentGameRoom) {
                await fetch(`/api/games/rooms/${currentGameRoom}/leave`, {method: 'POST'});
                clearInterval(gameRefreshInterval);
                currentGameRoom = null;
            }
            document.getElementById('gameArena').style.display = 'none';
            document.getElementById('gamesPanel').style.display = 'block';
            loadGameRooms();
        }
        
        // Single player snake
        function startSnake() {
            showPanel('games');
            const board = document.getElementById('gameBoard');
            board.innerHTML = '<canvas id="snakeCanvas" width="400" height="400"></canvas><div style="text-align: center; margin-top: 10px;"><button class="btn" onclick="submitSnakeScore()">Save Score</button></div>';
            
            const canvas = document.getElementById('snakeCanvas');
            const ctx = canvas.getContext('2d');
            const gridSize = 20;
            let snake = [{x: 10, y: 10}];
            let food = {x: 15, y: 15};
            let dx = 1, dy = 0;
            let score = 0;
            let gameLoop = null;
            
            document.onkeydown = (e) => {
                if (e.key === 'ArrowUp' && dy === 0) { dx = 0; dy = -1; }
                if (e.key === 'ArrowDown' && dy === 0) { dx = 0; dy = 1; }
                if (e.key === 'ArrowLeft' && dx === 0) { dx = -1; dy = 0; }
                if (e.key === 'ArrowRight' && dx === 0) { dx = 1; dy = 0; }
            };
            
            function update() {
                const head = {x: snake[0].x + dx, y: snake[0].y + dy};
                
                if (head.x < 0 || head.x >= 20 || head.y < 0 || head.y >= 20 || snake.some(s => s.x === head.x && s.y === head.y)) {
                    clearInterval(gameLoop);
                    alert('Game Over! Score: ' + score);
                    return;
                }
                
                snake.unshift(head);
                
                if (head.x === food.x && head.y === food.y) {
                    score += 10;
                    food = {x: Math.floor(Math.random() * 20), y: Math.floor(Math.random() * 20)};
                } else {
                    snake.pop();
                }
                
                ctx.fillStyle = '#000';
                ctx.fillRect(0, 0, 400, 400);
                ctx.fillStyle = '#0f0';
                snake.forEach(s => ctx.fillRect(s.x * gridSize, s.y * gridSize, gridSize-2, gridSize-2));
                ctx.fillStyle = '#f00';
                ctx.fillRect(food.x * gridSize, food.y * gridSize, gridSize-2, gridSize-2);
            }
            
            gameLoop = setInterval(update, 100);
            window.currentSnakeScore = () => score;
        }
        
        async function submitSnakeScore() {
            const score = window.currentSnakeScore ? window.currentSnakeScore() : 0;
            await fetch('/api/games/singleplayer/snake', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({score})
            });
            alert('Score saved!');
        }
        
        // PHOTOS
        async function uploadPhoto() {
            const file = document.getElementById('photoFile').files[0];
            const caption = document.getElementById('photoCaption').value;
            const filter = document.getElementById('photoFilter').value;
            
            if (!file) return alert('Select a photo');
            
            const formData = new FormData();
            formData.append('file', file);
            formData.append('caption', caption);
            formData.append('filter', filter);
            
            await fetch('/api/photos', {method: 'POST', body: formData});
            document.getElementById('photoFile').value = '';
            loadPhotos();
        }
        
        async function loadPhotos() {
            const res = await fetch('/api/photos');
            const photos = await res.json();
            
            const grid = document.getElementById('photoGrid');
            grid.innerHTML = photos.map(photo => `
                <div class="card">
                    <img src="/api/photos/${photo.id}/view" style="width: 100%; border-radius: 8px; ${getPhotoFilter(photo.filter)}">
                    <p style="margin-top: 10px;"><strong>@${photo.username}</strong></p>
                    <p>${photo.caption || ''}</p>
                    <span onclick="likePhoto(${photo.id})">❤️ ${photo.likes}</span>
                </div>
            `).join('');
        }
        
        function getPhotoFilter(filter) {
            const filters = {
                'none': '',
                'grayscale': 'filter: grayscale(100%)',
                'sepia': 'filter: sepia(100%)',
                'vintage': 'filter: sepia(50%) contrast(120%)'
            };
            return filters[filter] || '';
        }
        
        async function likePhoto(photoId) {
            await fetch(`/api/photos/${photoId}/like`, {method: 'POST'});
            loadPhotos();
        }
        
        // STREAMING
        async function startStream() {
            const title = document.getElementById('streamTitle').value;
            if (!title) return alert('Enter title');
            
            try {
                const res = await fetch('/api/streams', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({title})
                });
                const data = await res.json();
                currentStream = data.stream_id;
                
                const stream = await navigator.mediaDevices.getUserMedia({video: true, audio: true});
                document.getElementById('streamVideo').srcObject = stream;
                document.getElementById('streamControls').style.display = 'none';
                document.getElementById('streamView').style.display = 'block';
            } catch (e) {
                alert('Camera access denied. Use HTTPS or localhost.');
            }
        }
        
        async function endStreamSession() {
            if (currentStream) {
                await fetch(`/api/streams/${currentStream}/end`, {method: 'POST'});
            }
            document.getElementById('streamControls').style.display = 'block';
            document.getElementById('streamView').style.display = 'none';
            currentStream = null;
            loadStreams();
        }
        
        async function loadStreams() {
            const res = await fetch('/api/streams');
            const streams = await res.json();
            document.getElementById('liveStreams').innerHTML = streams.map(s => `
                <div class="card">
                    <strong>${s.title}</strong>
                    <p>By @${s.username}</p>
                </div>
            `).join('');
        }
        
        // MEDIA
        async function uploadMedia() {
            const file = document.getElementById('mediaFile').files[0];
            const title = document.getElementById('mediaTitle').value;
            const type = document.getElementById('mediaType').value;
            
            if (!file) return;
            
            const formData = new FormData();
            formData.append('file', file);
            formData.append('title', title);
            formData.append('media_type', type);
            
            await fetch('/api/media', {method: 'POST', body: formData});
            loadMedia();
        }
        
        async function loadMedia() {
            const res = await fetch('/api/media');
            const media = await res.json();
            
            document.getElementById('mediaGrid').innerHTML = media.map(m => `
                <div class="media-item">
                    <${m.media_type === 'video' ? 'video controls' : 'audio controls'} src="/api/media/${m.id}/stream"></${m.media_type === 'video' ? 'video' : 'audio'}>
                    <div class="media-info">
                        <div class="media-title">${m.title}</div>
                        <div class="media-meta">By ${m.username}</div>
                    </div>
                </div>
            `).join('');
        }
        
        // PASTEBIN
        async function createPaste() {
            const title = document.getElementById('pasteTitle').value;
            const content = document.getElementById('pasteContent').value;
            
            await fetch('/api/pastes', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({title, content})
            });
            
            document.getElementById('pasteContent').value = '';
            loadPastes();
        }
        
        async function loadPastes() {
            const res = await fetch('/api/pastes');
            const pastes = await res.json();
            
            document.getElementById('pastesList').innerHTML = pastes.map(p => `
                <div class="card">
                    <strong>${p.title}</strong>
                    <pre style="background: #f5f5f5; padding: 10px; overflow-x: auto;"><code>${escapeHtml(p.content)}</code></pre>
                    <p style="font-size: 12px; color: #999;">By @${p.username}</p>
                </div>
            `).join('');
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        // NOTES
        async function createNote() {
            const content = document.getElementById('noteContent').value;
            if (!content) return;
            
            await fetch('/api/notes', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({title: 'Note', content})
            });
            
            document.getElementById('noteContent').value = '';
            loadNotes();
        }
        
        async function loadNotes() {
            const res = await fetch('/api/notes');
            const notes = await res.json();
            
            document.getElementById('notesGrid').innerHTML = notes.map(n => `
                <div class="card" style="background: ${n.color};">
                    <p style="white-space: pre-wrap;">${n.content}</p>
                    <button onclick="deleteNote(${n.id})" style="margin-top: 10px;">Delete</button>
                </div>
            `).join('');
        }
        
        async function deleteNote(id) {
            await fetch(`/api/notes/${id}`, {method: 'DELETE'});
            loadNotes();
        }
        
        // TASKS
        async function createTask() {
            const title = document.getElementById('taskTitle').value;
            if (!title) return;
            
            await fetch('/api/tasks', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({title})
            });
            
            document.getElementById('taskTitle').value = '';
            loadTasks();
        }
        
        async function loadTasks() {
            const res = await fetch('/api/tasks');
            const tasks = await res.json();
            
            document.getElementById('tasksList').innerHTML = tasks.map(t => `
                <div class="card" style="display: flex; align-items: center; gap: 10px;">
                    <input type="checkbox" ${t.completed ? 'checked' : ''} onchange="toggleTask(${t.id})">
                    <span style="${t.completed ? 'text-decoration: line-through;' : ''}">${t.title}</span>
                    <button onclick="deleteTask(${t.id})" style="margin-left: auto;">🗑️</button>
                </div>
            `).join('');
        }
        
        async function toggleTask(id) {
            await fetch(`/api/tasks/${id}/toggle`, {method: 'POST'});
            loadTasks();
        }
        
        async function deleteTask(id) {
            await fetch(`/api/tasks/${id}`, {method: 'DELETE'});
            loadTasks();
        }
        
        // CALENDAR
        async function createEvent() {
            const title = document.getElementById('eventTitle').value;
            const start = document.getElementById('eventStart').value;
            
            if (!title || !start) return alert('Title and date required');
            
            await fetch('/api/events', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({title, start_time: start})
            });
            
            loadEvents();
        }
        
        async function loadEvents() {
            const res = await fetch('/api/events');
            const events = await res.json();
            
            document.getElementById('eventsList').innerHTML = events.map(e => `
                <div class="card" style="border-left: 4px solid ${e.color};">
                    <strong>${e.title}</strong>
                    <p>${new Date(e.start_time).toLocaleString()}</p>
                    <button onclick="deleteEvent(${e.id})">Delete</button>
                </div>
            `).join('');
        }
        
        async function deleteEvent(id) {
            await fetch(`/api/events/${id}`, {method: 'DELETE'});
            loadEvents();
        }
        
        // FILES
        async function uploadFile() {
            const file = document.getElementById('fileInput').files[0];
            if (!file) return;
            
            const formData = new FormData();
            formData.append('file', file);
            
            await fetch('/api/files', {method: 'POST', body: formData});
            loadFiles();
        }
        
        async function loadFiles() {
            const res = await fetch('/api/files');
            const files = await res.json();
            
            document.getElementById('filesList').innerHTML = files.map(f => `
                <div class="file-item">
                    <div class="file-info">
                        <h4>${f.original_filename}</h4>
                        <div class="file-meta">By ${f.username} • ${(f.file_size / 1024).toFixed(1)} KB</div>
                    </div>
                    <button class="download-btn" onclick="location.href='/api/files/${f.id}/download'">Download</button>
                </div>
            `).join('');
        }
        
        // CALLS
        async function initiateCall(userId, username) {
            if (!confirm(`Call ${username}?`)) return;
            
            try {
                const res = await fetch('/api/calls/initiate', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({receiver_id: userId, call_type: 'video'})
                });
                const data = await res.json();
                
                if (data.success) {
                    currentCall = {id: data.call_id, role: 'caller'};
                    showCallUI(username, 'calling');
                    
                    try {
                        localStream = await navigator.mediaDevices.getUserMedia({video: true, audio: true});
                        document.getElementById('localVideo').srcObject = localStream;
                        document.getElementById('videoContainer').style.display = 'block';
                        document.getElementById('callAvatar').style.display = 'none';
                    } catch (e) {
                        alert('Camera blocked. Using audio only.');
                    }
                }
            } catch (e) {
                alert('Failed to initiate call');
            }
        }
        
        function showCallUI(username, status) {
            document.getElementById('callUsername').textContent = username;
            document.getElementById('callStatus').textContent = status;
            document.getElementById('callModal').classList.add('show');
        }
        
        function answerCall() {
            document.getElementById('answerBtn').style.display = 'none';
            document.getElementById('callStatus').textContent = 'Connected';
            callStartTime = Date.now();
            callTimerInterval = setInterval(() => {
                const elapsed = Math.floor((Date.now() - callStartTime) / 1000);
                const mins = String(Math.floor(elapsed / 60)).padStart(2, '0');
                const secs = String(elapsed % 60).padStart(2, '0');
                document.getElementById('callTimer').textContent = `${mins}:${secs}`;
            }, 1000);
            document.getElementById('callTimer').style.display = 'block';
        }
        
        async function endCall() {
            if (currentCall) {
                const duration = callStartTime ? Math.floor((Date.now() - callStartTime) / 1000) : 0;
                await fetch(`/api/calls/${currentCall.id}/end`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({duration})
                });
            }
            
            if (localStream) {
                localStream.getTracks().forEach(track => track.stop());
                localStream = null;
            }
            
            clearInterval(callTimerInterval);
            document.getElementById('callModal').classList.remove('show');
            document.getElementById('videoContainer').style.display = 'none';
            document.getElementById('callAvatar').style.display = 'block';
            document.getElementById('callTimer').style.display = 'none';
            currentCall = null;
        }
        
        // NOTIFICATIONS
        async function loadNotifications() {
            const res = await fetch('/api/notifications');
            const notifications = await res.json();
            
            const list = document.getElementById('notificationList');
            if (notifications.length === 0) {
                list.innerHTML = '<div style="padding: 20px; text-align: center;">No notifications</div>';
            } else {
                list.innerHTML = notifications.map(n => `
                    <div class="notification-item ${n.read ? '' : 'unread'}" onclick="markRead(${n.id})">
                        <div class="notification-title">${n.title}</div>
                        <div class="notification-message">${n.message}</div>
                    </div>
                `).join('');
            }
            
            const unreadRes = await fetch('/api/notifications/unread-count');
            const unreadData = await unreadRes.json();
            const badge = document.getElementById('notificationBadge');
            if (unreadData.count > 0) {
                badge.textContent = unreadData.count;
                badge.style.display = 'flex';
            } else {
                badge.style.display = 'none';
            }
        }
        
        function toggleNotifications() {
            document.getElementById('notificationPanel').classList.toggle('show');
        }
        
        async function markRead(id) {
            await fetch(`/api/notifications/${id}/read`, {method: 'POST'});
            loadNotifications();
        }
        
        async function markAllRead() {
            await fetch('/api/notifications/mark-all-read', {method: 'POST'});
            loadNotifications();
        }
        
        // Enter key handlers
        document.addEventListener('DOMContentLoaded', () => {
            const loginPass = document.getElementById('loginPassword');
            const signupPass = document.getElementById('signupPassword');
            if (loginPass) loginPass.addEventListener('keypress', (e) => { if(e.key==='Enter') login(); });
            if (signupPass) signupPass.addEventListener('keypress', (e) => { if(e.key==='Enter') signup(); });
        });
    </script>
</body>
</html>
'''

def create_self_signed_cert():
    """Generate self-signed cert for HTTPS"""
    cert_file = BASE_DIR / 'server.crt'
    key_file = BASE_DIR / 'server.key'
    
    if cert_file.exists() and key_file.exists():
        return str(cert_file), str(key_file)
    
    try:
        from OpenSSL import crypto
        print("🔐 Generating SSL certificate...")
        
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        
        cert = crypto.X509()
        cert.get_subject().C = "LAN"
        cert.get_subject().ST = "Local"
        cert.get_subject().L = "LAN World"
        cert.get_subject().O = "LAN World"
        cert.get_subject().OU = "LAN World"
        cert.get_subject().CN = "*"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365*24*60*60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')
        
        with open(cert_file, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(key_file, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
            
        return str(cert_file), str(key_file)
    except ImportError:
        return None, None

if __name__ == '__main__':
    print("=" * 60)
    print("🌐 LAN WORLD - Your Local Internet Experience")
    print("=" * 60)
    print("\nInitializing database...")
    init_db()
    print("✓ Database initialized")
    print(f"💾 Data directory: {BASE_DIR.absolute()}")
    
    cert, key = create_self_signed_cert()
    ssl_context = None
    if cert and key:
        ssl_context = (cert, key)
        print("\n🔒 HTTPS Enabled")
        print("   https://localhost:8080")
    else:
        print("\n⚠️  HTTP Mode (install pyopenssl for HTTPS)")
        print("   http://localhost:8080")
    
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=8080, debug=False, ssl_context=ssl_context)