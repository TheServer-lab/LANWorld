#!/usr/bin/env python3
"""
LanWorld 2.0 - Complete LAN Ecosystem
Secure, async, single-file implementation
"""

import asyncio
import json
import os
import secrets
import socket
import threading
import time
import uuid
import re
import sqlite3
import traceback
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set

# Third-party imports
try:
    import bcrypt
    import aiosqlite
    import uvicorn
    from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, UploadFile, File, Form, Depends, Request
    from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.params import Header
    from pydantic import BaseModel
    REQUIRED_PACKAGES_INSTALLED = True
except ImportError as e:
    print(f"Missing packages: {e}")
    print("Installing required packages...")
    import subprocess
    import sys
    
    packages = ["fastapi", "uvicorn", "bcrypt", "python-multipart", "aiosqlite"]
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + packages)
        print(f"Successfully installed packages: {packages}")
        print("Please restart the application.")
    except subprocess.CalledProcessError:
        print(f"Failed to install packages. Please install manually: pip install {' '.join(packages)}")
    exit(1)

# ==================== CONFIGURATION ====================
CONFIG = {
    "host": "0.0.0.0",
    "port": 8000,
    "discovery_port": 8888,
    "upload_dir": "lanworld_uploads",
    "db_path": "lanworld.db",
    "secret_key": secrets.token_hex(32),
    "max_upload_size": 100 * 1024 * 1024,  # 100MB
    "session_days": 7,
    "cleanup_interval": 300,  # 5 minutes
}

# ==================== MODELS ====================
class UserCreate(BaseModel):
    username: str
    password: str
    bio: str = ""

class UserLogin(BaseModel):
    username: str
    password: str

class MessageCreate(BaseModel):
    recipient_id: str
    content: str
    type: str = "text"

class PostCreate(BaseModel):
    content: str

# ==================== SQLITE STORAGE ====================
class SQLiteStorage:
    def __init__(self, db_path="lanworld.db"):
        self.db_path = db_path
        self.init_db()
        self.connection_lock = asyncio.Lock()
    
    def init_db(self):
        """Initialize SQLite database with tables and WAL mode."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Enable WAL mode for better concurrency
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA synchronous=NORMAL;")
            cursor.execute("PRAGMA foreign_keys=ON;")
            cursor.execute("PRAGMA busy_timeout=5000;")  # Add timeout
            
            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    avatar TEXT DEFAULT 'default.png',
                    bio TEXT DEFAULT '',
                    online BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP
                )
            ''')
            
            # Messages table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    sender_id TEXT NOT NULL,
                    recipient_id TEXT NOT NULL,
                    content TEXT NOT NULL,
                    type TEXT DEFAULT 'text',
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (sender_id) REFERENCES users(id),
                    FOREIGN KEY (recipient_id) REFERENCES users(id)
                )
            ''')
            
            # Files table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    id TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    filepath TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    visibility TEXT DEFAULT 'private',
                    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (owner_id) REFERENCES users(id)
                )
            ''')
            
            # Posts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS posts (
                    id TEXT PRIMARY KEY,
                    author_id TEXT NOT NULL,
                    author_username TEXT NOT NULL,
                    content TEXT NOT NULL,
                    likes INTEGER DEFAULT 0,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (author_id) REFERENCES users(id)
                )
            ''')
            
            # Sessions table with TTL
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_users ON messages(sender_id, recipient_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_online ON users(online)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_posts_timestamp ON posts(timestamp DESC)')
            
            conn.commit()
            conn.close()
            print(f"✅ Database initialized: {self.db_path}")
        except Exception as e:
            print(f"❌ Database initialization failed: {e}")
            raise
    
    @asynccontextmanager
    async def get_connection(self):
        """Async context manager for database connections."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA journal_mode=WAL;")
            await db.execute("PRAGMA synchronous=NORMAL;")
            await db.execute("PRAGMA foreign_keys=ON;")
            await db.execute("PRAGMA busy_timeout=5000;")  # Add timeout
            db.row_factory = aiosqlite.Row
            yield db
    
    # User operations
    async def get_user_by_username(self, username: str):
        try:
            async with self.get_connection() as db:
                cursor = await db.execute(
                    'SELECT * FROM users WHERE username = ?', (username,)
                )
                row = await cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            print(f"Error getting user by username: {e}")
            return None
    
    async def get_user_by_id(self, user_id: str):
        try:
            async with self.get_connection() as db:
                cursor = await db.execute(
                    'SELECT * FROM users WHERE id = ?', (user_id,)
                )
                row = await cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            print(f"Error getting user by id: {e}")
            return None
    
    async def create_user(self, user_id: str, user_data: dict):
        try:
            async with self.get_connection() as db:
                await db.execute('''
                    INSERT INTO users (id, username, password_hash, avatar, bio, online, created_at, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    user_id,
                    user_data['username'],
                    user_data['password_hash'],
                    user_data.get('avatar', 'default.png'),
                    user_data.get('bio', ''),
                    user_data.get('online', False),
                    datetime.now().isoformat(),
                    datetime.now().isoformat()
                ))
                await db.commit()
                return True
        except Exception as e:
            print(f"Error creating user: {e}")
            return False
    
    async def update_user(self, user_id: str, updates: dict):
        try:
            async with self.get_connection() as db:
                if not updates:
                    return True
                    
                set_clause = ", ".join([f"{k} = ?" for k in updates.keys()])
                values = list(updates.values()) + [user_id]
                
                await db.execute(f'''
                    UPDATE users SET {set_clause} WHERE id = ?
                ''', values)
                await db.commit()
                return True
        except Exception as e:
            print(f"Error updating user: {e}")
            return False
    
    # Message operations
    async def add_message(self, message: dict):
        try:
            async with self.get_connection() as db:
                await db.execute('''
                    INSERT INTO messages (id, sender_id, recipient_id, content, type, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    message['id'],
                    message['sender_id'],
                    message['recipient_id'],
                    message['content'],
                    message.get('type', 'text'),
                    message.get('timestamp', datetime.now().isoformat())
                ))
                await db.commit()
                return True
        except Exception as e:
            print(f"Error adding message: {e}")
            return False
    
    async def get_messages(self, user1_id: str, user2_id: str, limit: int = 100):
        try:
            async with self.get_connection() as db:
                cursor = await db.execute('''
                    SELECT * FROM messages 
                    WHERE (sender_id = ? AND recipient_id = ?)
                       OR (sender_id = ? AND recipient_id = ?)
                    ORDER BY timestamp ASC
                    LIMIT ?
                ''', (user1_id, user2_id, user2_id, user1_id, limit))
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            print(f"Error getting messages: {e}")
            return []
    
    # File operations
    async def add_file(self, file_data: dict):
        try:
            async with self.get_connection() as db:
                await db.execute('''
                    INSERT INTO files (id, owner_id, filename, filepath, size, visibility, uploaded_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    file_data["id"],
                    file_data["owner_id"],
                    file_data["filename"],
                    file_data["filepath"],
                    file_data["size"],
                    file_data.get("visibility", "private"),
                    file_data.get("uploaded_at", datetime.now().isoformat())
                ))
                await db.commit()
                return True
        except Exception as e:
            print(f"Error adding file: {e}")
            return False
    
    async def get_user_files(self, user_id: str):
        try:
            async with self.get_connection() as db:
                cursor = await db.execute('''
                    SELECT * FROM files 
                    WHERE owner_id = ? OR visibility = 'public'
                    ORDER BY uploaded_at DESC
                ''', (user_id,))
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            print(f"Error getting user files: {e}")
            return []
    
    async def get_file_by_id(self, file_id: str, user_id: str):
        try:
            async with self.get_connection() as db:
                cursor = await db.execute('''
                    SELECT * FROM files 
                    WHERE id = ? AND (owner_id = ? OR visibility = 'public')
                ''', (file_id, user_id))
                row = await cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            print(f"Error getting file by id: {e}")
            return None
    
    # Post operations
    async def add_post(self, post: dict):
        try:
            async with self.get_connection() as db:
                await db.execute('''
                    INSERT INTO posts (id, author_id, author_username, content, likes, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    post['id'],
                    post['author_id'],
                    post['author_username'],
                    post['content'],
                    post.get('likes', 0),
                    post.get('timestamp', datetime.now().isoformat())
                ))
                await db.commit()
                return True
        except Exception as e:
            print(f"Error adding post: {e}")
            return False
    
    async def get_posts(self, limit: int = 50):
        try:
            async with self.get_connection() as db:
                cursor = await db.execute('''
                    SELECT * FROM posts 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            print(f"Error getting posts: {e}")
            return []
    
    async def like_post(self, post_id: str):
        try:
            async with self.get_connection() as db:
                await db.execute('''
                    UPDATE posts SET likes = likes + 1 WHERE id = ?
                ''', (post_id,))
                await db.commit()
                return True
        except Exception as e:
            print(f"Error liking post: {e}")
            return False
    
    # Session operations
    async def add_session(self, token: str, user_id: str, expires_in_days: int = 7):
        try:
            expires_at = datetime.now() + timedelta(days=expires_in_days)
            async with self.get_connection() as db:
                await db.execute('''
                    INSERT INTO sessions (token, user_id, expires_at)
                    VALUES (?, ?, ?)
                ''', (token, user_id, expires_at.isoformat()))
                await db.commit()
                return True
        except Exception as e:
            print(f"Error adding session: {e}")
            return False
    
    async def get_session(self, token: str):
        try:
            async with self.get_connection() as db:
                # Clean expired sessions first
                now = datetime.now().isoformat()
                await db.execute('DELETE FROM sessions WHERE expires_at < ?', (now,))
                await db.commit()
                
                cursor = await db.execute('''
                    SELECT s.*, u.username 
                    FROM sessions s
                    JOIN users u ON s.user_id = u.id
                    WHERE s.token = ?
                ''', (token,))
                row = await cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            print(f"Error getting session: {e}")
            return None
    
    async def delete_session(self, token: str):
        try:
            async with self.get_connection() as db:
                await db.execute('DELETE FROM sessions WHERE token = ?', (token,))
                await db.commit()
                return True
        except Exception as e:
            print(f"Error deleting session: {e}")
            return False
    
    # Utility operations
    async def get_online_users(self):
        try:
            async with self.get_connection() as db:
                cursor = await db.execute('''
                    SELECT * FROM users 
                    WHERE online = TRUE
                    ORDER BY username
                ''')
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            print(f"Error getting online users: {e}")
            return []
    
    async def cleanup_expired_sessions(self):
        """Clean up expired sessions."""
        try:
            async with self.get_connection() as db:
                now = datetime.now().isoformat()
                await db.execute('DELETE FROM sessions WHERE expires_at < ?', (now,))
                await db.commit()
                cursor = await db.execute('SELECT COUNT(*) as count FROM sessions')
                row = await cursor.fetchone()
                return row['count'] if row else 0
        except Exception as e:
            print(f"Error cleaning up sessions: {e}")
            return 0

# Initialize storage
storage = SQLiteStorage(CONFIG["db_path"])

# ==================== AUTH UTILITIES ====================
def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    try:
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    except Exception as e:
        print(f"Error hashing password: {e}")
        raise

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against bcrypt hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode('utf-8'), 
            hashed_password.encode('utf-8')
        )
    except Exception as e:
        print(f"Error verifying password: {e}")
        return False

async def create_session_token(user_id: str) -> str:
    """Create and store session token."""
    try:
        token = secrets.token_urlsafe(48)
        await storage.add_session(token, user_id, CONFIG["session_days"])
        return token
    except Exception as e:
        print(f"Error creating session token: {e}")
        raise

async def verify_session_token(token: str) -> Optional[str]:
    """Verify and return user_id if valid session exists."""
    try:
        session = await storage.get_session(token)
        if session:
            return session["user_id"]
        return None
    except Exception as e:
        print(f"Error verifying session token: {e}")
        return None

async def get_current_user(authorization: Optional[str] = Header(None)):
    """Async user authentication dependency."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = authorization[7:]
    user_id = await verify_session_token(token)
    
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    return user_id

# ==================== WEBSOCKET MANAGER ====================
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.user_connections: Dict[str, str] = {}
        self.lock = threading.Lock()
    
    async def connect(self, websocket: WebSocket, user_id: str):
        try:
            await websocket.accept()
            conn_id = str(uuid.uuid4())
            
            with self.lock:
                self.active_connections[conn_id] = websocket
                self.user_connections[user_id] = conn_id
            
            # Update user as online
            await storage.update_user(user_id, {
                "online": True, 
                "last_seen": datetime.now().isoformat()
            })
            
            # Broadcast user online status
            await self.broadcast_user_status(user_id, True)
            print(f"✅ WebSocket connected: user={user_id}")
            return conn_id
        except Exception as e:
            print(f"❌ WebSocket connection error: {e}")
            raise
    
    def disconnect(self, user_id: str):
        try:
            with self.lock:
                if user_id in self.user_connections:
                    conn_id = self.user_connections[user_id]
                    if conn_id in self.active_connections:
                        del self.active_connections[conn_id]
                    del self.user_connections[user_id]
            
            # Update user as offline (async but fire-and-forget is okay here)
            asyncio.create_task(
                storage.update_user(user_id, {
                    "online": False, 
                    "last_seen": datetime.now().isoformat()
                })
            )
            print(f"📤 WebSocket disconnected: user={user_id}")
        except Exception as e:
            print(f"Error disconnecting WebSocket: {e}")
    
    async def send_personal_message(self, user_id: str, message: dict):
        try:
            with self.lock:
                if user_id in self.user_connections:
                    conn_id = self.user_connections[user_id]
                    if conn_id in self.active_connections:
                        websocket = self.active_connections[conn_id]
                        await websocket.send_json(message)
        except Exception as e:
            print(f"Error sending personal message: {e}")
    
    async def broadcast(self, message: dict, exclude_user: str = None):
        disconnected = []
        connections_copy = []
        
        with self.lock:
            connections_copy = list(self.user_connections.items())
        
        for user_id, conn_id in connections_copy:
            if user_id != exclude_user:
                websocket = None
                with self.lock:
                    websocket = self.active_connections.get(conn_id)
                if websocket:
                    try:
                        await websocket.send_json(message)
                    except Exception:
                        disconnected.append(user_id)
        
        # Clean up disconnected users
        for user_id in disconnected:
            self.disconnect(user_id)
    
    async def broadcast_user_status(self, user_id: str, online: bool):
        try:
            message = {
                "type": "user_status",
                "user_id": user_id,
                "online": online,
                "timestamp": datetime.now().isoformat()
            }
            await self.broadcast(message, exclude_user=user_id)
        except Exception as e:
            print(f"Error broadcasting user status: {e}")

manager = ConnectionManager()

# ==================== LAN DISCOVERY SERVICE ====================
class LanDiscovery:
    def __init__(self, port=8888):
        self.port = port
        self.running = False
        self.server_info = {
            "name": "LanWorld",
            "version": "2.0",
            "port": CONFIG["port"],
            "host": self.get_local_ip(),
            "timestamp": datetime.now().isoformat()
        }
        self.broadcast_addresses = self.get_broadcast_addresses()
    
    def get_local_ip(self):
        """Get local IP address."""
        try:
            # Try to get local IP by connecting to a dummy socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            try:
                return socket.gethostbyname(socket.gethostname())
            except:
                return "127.0.0.1"
    
    def get_broadcast_addresses(self):
        """Get broadcast addresses for all interfaces."""
        broadcast_addrs = []
        
        # Try to get network interfaces if netifaces is available
        try:
            import netifaces
            for iface in netifaces.interfaces():
                try:
                    # Skip loopback
                    if iface.startswith('lo'):
                        continue
                    
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        for addr_info in addrs[netifaces.AF_INET]:
                            broadcast = addr_info.get('broadcast')
                            if broadcast:
                                broadcast_addrs.append(broadcast)
                except:
                    continue
        except ImportError:
            print("⚠️  netifaces not installed. Using fallback for broadcast addresses.")
            print("   Install with: pip install netifaces")
            pass  # netifaces not available
        
        # Fallback: use local IP to guess broadcast
        try:
            local_ip = self.get_local_ip()
            if local_ip != '127.0.0.1':
                parts = local_ip.split('.')
                if len(parts) == 4:
                    broadcast_addrs.append(f"{parts[0]}.{parts[1]}.{parts[2]}.255")
        except:
            pass
        
        # Always include generic broadcast
        if '255.255.255.255' not in broadcast_addrs:
            broadcast_addrs.append('255.255.255.255')
        
        return list(set(broadcast_addrs))
    
    def start(self):
        self.running = True
        thread = threading.Thread(target=self._broadcast_service, daemon=True)
        thread.start()
        print(f"🔍 LAN Discovery started on port {self.port}")
        print(f"   Broadcast addresses: {', '.join(self.broadcast_addresses)}")
    
    def stop(self):
        self.running = False
    
    def _broadcast_service(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(0.2)
        
        while self.running:
            try:
                self.server_info["timestamp"] = datetime.now().isoformat()
                self.server_info["host"] = self.get_local_ip()
                message = json.dumps(self.server_info).encode('utf-8')
                
                # Send to all broadcast addresses
                for broadcast_addr in self.broadcast_addresses:
                    try:
                        sock.sendto(message, (broadcast_addr, self.port))
                    except Exception as e:
                        print(f"Broadcast error to {broadcast_addr}: {e}")
                        continue
            except Exception as e:
                print(f"Discovery error: {e}")
            
            time.sleep(30)

discovery = LanDiscovery(CONFIG["discovery_port"])

# ==================== FILE MANAGEMENT ====================
class FileManager:
    def __init__(self, upload_dir="lanworld_uploads"):
        self.upload_dir = Path(upload_dir)
        self.upload_dir.mkdir(exist_ok=True, parents=True)
        self.allowed_extensions = {
            '.txt', '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.bmp',
            '.doc', '.docx', '.xls', '.xlsx', '.zip', '.rar', '.7z',
            '.mp3', '.mp4', '.avi', '.mov', '.wav', '.ogg',
            '.py', '.js', '.html', '.css', '.json', '.xml'
        }
    
    def sanitize_filename(self, filename: str) -> str:
        """Remove dangerous characters from filename."""
        # Keep only alphanumeric, dots, hyphens, underscores, and spaces
        filename = re.sub(r'[^\w\.\-\s]', '_', filename)
        # Remove multiple dots
        filename = re.sub(r'\.+', '.', filename)
        # Remove leading/trailing spaces and dots
        filename = filename.strip('. ')
        # Limit length
        if len(filename) > 255:
            name, ext = os.path.splitext(filename)
            filename = name[:255-len(ext)] + ext
        return filename
    
    async def save_file(self, file: UploadFile, owner_id: str) -> Optional[dict]:
        try:
            # Sanitize filename
            if not file.filename:
                raise ValueError("No filename provided")
            
            safe_filename = self.sanitize_filename(file.filename)
            
            # Check extension
            file_ext = Path(safe_filename).suffix.lower()
            if not file_ext:
                raise ValueError("File has no extension")
            
            if file_ext not in self.allowed_extensions:
                raise ValueError(f"File type {file_ext} not allowed")
            
            # Generate unique filename
            file_id = str(uuid.uuid4())
            filename = f"{file_id}{file_ext}"
            filepath = self.upload_dir / filename
            
            # Save file in chunks to avoid memory issues
            CHUNK_SIZE = 1024 * 1024  # 1MB chunks
            total_size = 0
            
            with open(filepath, "wb") as f:
                while True:
                    chunk = await file.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    total_size += len(chunk)
                    if total_size > CONFIG["max_upload_size"]:
                        f.close()
                        if filepath.exists():
                            filepath.unlink()
                        raise HTTPException(status_code=413, detail="File too large (max 100MB)")
                    f.write(chunk)
            
            # Create file record
            file_data = {
                "id": file_id,
                "owner_id": owner_id,
                "filename": safe_filename,
                "filepath": str(filepath),
                "size": total_size,
                "visibility": "private",
                "uploaded_at": datetime.now().isoformat()
            }
            
            success = await storage.add_file(file_data)
            if not success:
                if filepath.exists():
                    filepath.unlink()
                raise HTTPException(status_code=500, detail="Failed to save file record")
            
            return file_data
        except HTTPException:
            raise
        except Exception as e:
            print(f"Error saving file: {e}")
            raise HTTPException(status_code=500, detail=f"File upload failed: {str(e)}")
    
    def get_file(self, file_id: str, user_id: str) -> Optional[Path]:
        # This is now handled by storage.get_file_by_id
        return None

file_manager = FileManager(CONFIG["upload_dir"])

# ==================== LIFESPAN & BACKGROUND TASKS ====================
async def periodic_cleanup():
    """Periodic cleanup of expired sessions."""
    while True:
        try:
            await asyncio.sleep(CONFIG["cleanup_interval"])
            remaining = await storage.cleanup_expired_sessions()
            if remaining > 0:
                print(f"🧹 Cleaned expired sessions, {remaining} sessions remaining")
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"Cleanup error: {e}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan with background tasks."""
    # Startup
    print("🚀 Starting LanWorld server...")
    
    # Start LAN discovery
    try:
        discovery.start()
    except Exception as e:
        print(f"⚠️  LAN Discovery failed to start: {e}")
    
    # Start background cleanup task
    cleanup_task = asyncio.create_task(periodic_cleanup())
    
    yield  # App runs here
    
    # Shutdown
    print("🛑 Shutting down...")
    discovery.stop()
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass

# ==================== FASTAPI APP ====================
app = FastAPI(
    title="LanWorld", 
    version="2.0", 
    lifespan=lifespan,
    debug=True  # Enable debug for better error messages
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== API ENDPOINTS ====================
@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    return HTML_TEMPLATE

# Authentication
@app.post("/api/auth/register")
async def register(user_data: UserCreate):
    try:
        # Check if username exists
        existing_user = await storage.get_user_by_username(user_data.username)
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already exists")
        
        # Validate username
        if len(user_data.username) < 3:
            raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
        
        if len(user_data.username) > 20:
            raise HTTPException(status_code=400, detail="Username must be at most 20 characters")
        
        # Validate password
        if len(user_data.password) < 6:
            raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
        
        # Create user
        user_id = str(uuid.uuid4())
        password_hash = hash_password(user_data.password)
        
        user_record = {
            "username": user_data.username,
            "password_hash": password_hash,
            "avatar": "default.png",
            "bio": user_data.bio[:500] if user_data.bio else "",  # Limit bio length
            "online": False,
        }
        
        success = await storage.create_user(user_id, user_record)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to create user")
        
        return {"message": "User created successfully"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Registration error: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@app.post("/api/auth/login")
async def login(user_data: UserLogin):
    try:
        # Find user
        user = await storage.get_user_by_username(user_data.username)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Check password
        if not verify_password(user_data.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Update user status
        await storage.update_user(user["id"], {
            "online": True, 
            "last_seen": datetime.now().isoformat()
        })
        
        # Create session
        token = await create_session_token(user["id"])
        
        return {
            "token": token,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "avatar": user["avatar"],
                "bio": user["bio"]
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"Login error: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")

@app.post("/api/auth/logout")
async def logout(current_user: str = Depends(get_current_user)):
    try:
        # In a real app, you might want to invalidate the token
        # For now, we just return success
        return {"message": "Logged out successfully"}
    except Exception as e:
        print(f"Logout error: {e}")
        raise HTTPException(status_code=500, detail="Logout failed")

@app.get("/api/auth/validate")
async def validate_token(current_user: str = Depends(get_current_user)):
    try:
        user = await storage.get_user_by_id(current_user)
        if user:
            # Remove sensitive data
            user.pop("password_hash", None)
            return {"user": user}
        raise HTTPException(status_code=404, detail="User not found")
    except HTTPException:
        raise
    except Exception as e:
        print(f"Validate token error: {e}")
        raise HTTPException(status_code=500, detail="Token validation failed")

# WebSocket
@app.websocket("/api/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = ""):
    if not token:
        await websocket.close(code=1008, reason="No token provided")
        return
    
    user_id = await verify_session_token(token)
    if not user_id:
        await websocket.close(code=1008, reason="Invalid token")
        return
    
    conn_id = await manager.connect(websocket, user_id)
    
    try:
        # Send initial online users list
        try:
            online_users = await storage.get_online_users()
            await websocket.send_json({
                "type": "online_users",
                "users": online_users
            })
        except Exception as e:
            print(f"Error sending initial online users: {e}")
        
        while True:
            try:
                data = await websocket.receive_json()
                
                if data.get("type") == "message":
                    # Store message
                    message_id = str(uuid.uuid4())
                    message = {
                        "id": message_id,
                        "sender_id": user_id,
                        "recipient_id": data.get("recipient_id"),
                        "content": data.get("content", ""),
                        "timestamp": datetime.now().isoformat(),
                        "type": "text"
                    }
                    
                    await storage.add_message(message)
                    
                    # Forward to recipient if online
                    await manager.send_personal_message(data["recipient_id"], {
                        "type": "message",
                        **message
                    })
                    
            except json.JSONDecodeError:
                await websocket.send_json({
                    "type": "error",
                    "message": "Invalid JSON format"
                })
            except KeyError as e:
                await websocket.send_json({
                    "type": "error",
                    "message": f"Missing required field: {e}"
                })
            except Exception as e:
                print(f"WebSocket message error: {e}")
                
    except WebSocketDisconnect:
        print(f"WebSocket disconnected: user={user_id}")
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        manager.disconnect(user_id)

# Users
@app.get("/api/users/online")
async def get_online_users(current_user: str = Depends(get_current_user)):
    try:
        online_users = await storage.get_online_users()
        # Remove current user from list
        online_users = [u for u in online_users if u["id"] != current_user]
        # Remove sensitive data
        for user in online_users:
            user.pop("password_hash", None)
        return online_users
    except Exception as e:
        print(f"Error getting online users: {e}")
        return []

@app.get("/api/users/{user_id}")
async def get_user(user_id: str, current_user: str = Depends(get_current_user)):
    try:
        user = await storage.get_user_by_id(user_id)
        if user:
            # Don't expose password hash
            user.pop("password_hash", None)
            return user
        raise HTTPException(status_code=404, detail="User not found")
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error getting user: {e}")
        raise HTTPException(status_code=500, detail="Failed to get user")

# Messages
@app.post("/api/messages")
async def send_message(message: MessageCreate, current_user: str = Depends(get_current_user)):
    try:
        message_id = str(uuid.uuid4())
        message_data = {
            "id": message_id,
            "sender_id": current_user,
            "recipient_id": message.recipient_id,
            "content": message.content[:1000],  # Limit message length
            "timestamp": datetime.now().isoformat(),
            "type": message.type
        }
        
        success = await storage.add_message(message_data)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to save message")
        
        # Try to send via WebSocket if recipient is online
        await manager.send_personal_message(message.recipient_id, {
            "type": "message",
            **message_data
        })
        
        return message_data
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error sending message: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to send message: {str(e)}")

@app.get("/api/messages/{user_id}")
async def get_messages(user_id: str, current_user: str = Depends(get_current_user)):
    try:
        messages = await storage.get_messages(current_user, user_id, limit=100)
        return messages
    except Exception as e:
        print(f"Error getting messages: {e}")
        return []

# Files
@app.post("/api/files/upload")
async def upload_file(
    file: UploadFile = File(...), 
    current_user: str = Depends(get_current_user)
):
    try:
        # Save file
        file_data = await file_manager.save_file(file, current_user)
        if not file_data:
            raise HTTPException(status_code=400, detail="Invalid file type")
        return file_data
    except HTTPException:
        raise
    except Exception as e:
        print(f"Upload error: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

@app.get("/api/files")
async def list_files(current_user: str = Depends(get_current_user)):
    try:
        files = await storage.get_user_files(current_user)
        return files
    except Exception as e:
        print(f"Error listing files: {e}")
        return []

@app.get("/api/files/{file_id}")
async def download_file(file_id: str, token: str):
    try:
        user_id = await verify_session_token(token)
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        file_record = await storage.get_file_by_id(file_id, user_id)
        if not file_record:
            raise HTTPException(status_code=404, detail="File not found")
        
        file_path = Path(file_record["filepath"])
        if not file_path.exists():
            # Clean up orphaned file record
            async with storage.get_connection() as db:
                await db.execute('DELETE FROM files WHERE id = ?', (file_id,))
                await db.commit()
            raise HTTPException(status_code=404, detail="File not found on disk")
        
        return FileResponse(
            path=file_path,
            filename=file_record["filename"],
            media_type="application/octet-stream"
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"Download error: {e}")
        raise HTTPException(status_code=500, detail=f"Download failed: {str(e)}")

# Feed
@app.post("/api/feed/posts")
async def create_post(post: PostCreate, current_user: str = Depends(get_current_user)):
    try:
        user = await storage.get_user_by_id(current_user)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        post_id = str(uuid.uuid4())
        
        post_data = {
            "id": post_id,
            "author_id": current_user,
            "author_username": user["username"],
            "content": post.content[:5000],  # Limit post length
            "likes": 0,
            "timestamp": datetime.now().isoformat()
        }
        
        success = await storage.add_post(post_data)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to create post")
        
        return post_data
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error creating post: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create post: {str(e)}")

@app.get("/api/feed/posts")
async def get_posts(current_user: str = Depends(get_current_user)):
    try:
        posts = await storage.get_posts(limit=50)
        return posts
    except Exception as e:
        print(f"Error getting posts: {e}")
        return []

@app.post("/api/feed/posts/{post_id}/like")
async def like_post(post_id: str, current_user: str = Depends(get_current_user)):
    try:
        success = await storage.like_post(post_id)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to like post")
        return {"message": "Post liked"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error liking post: {e}")
        raise HTTPException(status_code=500, detail="Failed to like post")

# Discovery
@app.get("/api/discovery/info")
async def get_discovery_info():
    try:
        online_users = await storage.get_online_users()
        local_ip = discovery.get_local_ip()
        
        return {
            "name": "LanWorld",
            "version": "2.0",
            "host": local_ip,
            "port": CONFIG["port"],
            "users_online": len(online_users),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        print(f"Error getting discovery info: {e}")
        return {
            "name": "LanWorld",
            "version": "2.0",
            "host": "127.0.0.1",
            "port": CONFIG["port"],
            "users_online": 0,
            "timestamp": datetime.now().isoformat()
        }

# ==================== TLS HELPER ====================
def generate_self_signed_cert():
    """Generate self-signed certificate only if missing."""
    cert_path = "lanworld_cert.pem"
    key_path = "lanworld_key.pem"
    
    # Return existing certs if they exist
    if os.path.exists(cert_path) and os.path.exists(key_path):
        print(f"📜 Using existing TLS certificate: {cert_path}")
        return cert_path, key_path
    
    print("🔐 Generating new TLS certificate...")
    
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
        
        # Generate private key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Generate self-signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LanWorld"),
            x509.NameAttribute(NameOID.COMMON_NAME, "lanworld.local"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=3650)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("127.0.0.1"),
                x509.DNSName("lanworld.local"),
            ]),
            critical=False,
        ).sign(key, hashes.SHA256())
        
        # Write certificate
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Write private key
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        print(f"✅ TLS certificate generated: {cert_path}")
        return cert_path, key_path
        
    except ImportError:
        print("⚠️  TLS disabled: install 'cryptography' for HTTPS: pip install cryptography")
        return None, None
    except Exception as e:
        print(f"⚠️  TLS certificate generation failed: {e}")
        return None, None

# ==================== BROWSER HELPER ====================
def open_browser():
    """Open browser after server starts."""
    import webbrowser
    time.sleep(3)  # Increased delay to ensure server is ready
    
    ssl_cert, ssl_key = generate_self_signed_cert()
    protocol = "https" if ssl_cert and ssl_key else "http"
    
    try:
        webbrowser.open(f"{protocol}://127.0.0.1:{CONFIG['port']}")
        print(f"🌐 Browser opened: {protocol}://127.0.0.1:{CONFIG['port']}")
    except Exception as e:
        print(f"⚠️  Could not open browser: {e}")

# ==================== MAIN ENTRY POINT ====================
async def main():
    print("""
    ╔══════════════════════════════════════════╗
    ║           LanWorld 2.0                   ║
    ║   Complete LAN Ecosystem                 ║
    ║   Secure • Async • Production-Ready      ║
    ╚══════════════════════════════════════════╝
    """)
    
    # Create upload directory
    upload_path = Path(CONFIG["upload_dir"])
    upload_path.mkdir(exist_ok=True, parents=True)
    print(f"📁 Upload directory: {upload_path.absolute()}")
    
    # Check if we can write to upload directory
    try:
        test_file = upload_path / ".test_write"
        test_file.touch()
        test_file.unlink()
        print("✅ Upload directory is writable")
    except Exception as e:
        print(f"❌ Cannot write to upload directory: {e}")
        print(f"   Please check permissions for: {upload_path.absolute()}")
    
    # Generate TLS certs if possible
    ssl_cert, ssl_key = generate_self_signed_cert()
    
    # Get IP addresses for display
    local_ip = discovery.get_local_ip()
    ips = [local_ip, "127.0.0.1", "localhost"]
    
    print(f"\n🌐 Server starting...")
    print(f"📡 Access URLs:")
    print(f"   http://127.0.0.1:{CONFIG['port']}")
    print(f"   http://localhost:{CONFIG['port']}")
    
    if ssl_cert and ssl_key:
        print(f"   https://127.0.0.1:{CONFIG['port']}")
        print(f"   https://localhost:{CONFIG['port']}")
    
    if local_ip not in ['127.0.0.1', 'localhost']:
        print(f"   http://{local_ip}:{CONFIG['port']}")
        if ssl_cert and ssl_key:
            print(f"   https://{local_ip}:{CONFIG['port']}")
    
    print(f"\n💡 Other users on your LAN can connect via:")
    print(f"   http://{local_ip}:{CONFIG['port']}")
    print(f"\n🔒 WebSocket Security: {'WSS (Secure)' if ssl_cert and ssl_key else 'WS (Insecure)'}")
    print(f"📊 Database: {CONFIG['db_path']} (WAL mode enabled)")
    print(f"🔍 Discovery: Port {CONFIG['discovery_port']}")
    print(f"\n🚀 Press Ctrl+C to stop the server\n")
    
    # Open browser in background
    try:
        import threading
        threading.Thread(target=open_browser, daemon=True).start()
    except:
        pass
    
    # Start server
    config = uvicorn.Config(
        app, 
        host=CONFIG["host"], 
        port=CONFIG["port"],
        ssl_certfile=ssl_cert if ssl_cert and os.path.exists(ssl_cert) else None,
        ssl_keyfile=ssl_key if ssl_key and os.path.exists(ssl_key) else None,
        log_level="info",
        access_log=True,
        reload=False  # Disable reload for single-file app
    )
    
    try:
        server = uvicorn.Server(config)
        await server.serve()
    except Exception as e:
        print(f"\n❌ Server error: {e}")
        print("\nTraceback:")
        traceback.print_exc()

        # ==================== FRONTEND HTML ====================
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LanWorld 2.0 - Local Network Ecosystem</title>
    <style>
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-tertiary: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #cbd5e1;
            --accent: #3b82f6;
            --accent-hover: #2563eb;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }
        
        .app {
            display: flex;
            height: 100vh;
            overflow: hidden;
        }
        
        .sidebar {
            width: 300px;
            background: var(--bg-secondary);
            border-right: 1px solid var(--bg-tertiary);
            display: flex;
            flex-direction: column;
        }
        
        .main-content {
            flex: 1;
            display: flex;
            flex-direction: column;
        }
        
        .header {
            padding: 1rem;
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--bg-tertiary);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .view-container {
            flex: 1;
            overflow: hidden;
            position: relative;
        }
        
        .view {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            padding: 1rem;
            overflow-y: auto;
            display: none;
        }
        
        .view.active {
            display: block;
        }
        
        /* Auth View */
        .auth-container {
            max-width: 400px;
            margin: 2rem auto;
            padding: 2rem;
            background: var(--bg-secondary);
            border-radius: 0.5rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .auth-tabs {
            display: flex;
            margin-bottom: 2rem;
            border-bottom: 1px solid var(--bg-tertiary);
        }
        
        .auth-tab {
            flex: 1;
            padding: 0.75rem;
            text-align: center;
            cursor: pointer;
            border-bottom: 2px solid transparent;
        }
        
        .auth-tab.active {
            border-bottom-color: var(--accent);
            color: var(--accent);
        }
        
        .form-group {
            margin-bottom: 1rem;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            color: var(--text-secondary);
        }
        
        .form-control {
            width: 100%;
            padding: 0.75rem;
            background: var(--bg-tertiary);
            border: 1px solid var(--bg-tertiary);
            border-radius: 0.375rem;
            color: var(--text-primary);
            font-size: 1rem;
        }
        
        .form-control:focus {
            outline: none;
            border-color: var(--accent);
        }
        
        .btn {
            display: inline-block;
            padding: 0.75rem 1.5rem;
            background: var(--accent);
            color: white;
            border: none;
            border-radius: 0.375rem;
            font-size: 1rem;
            font-weight: 500;
            cursor: pointer;
            text-decoration: none;
            transition: background 0.2s;
        }
        
        .btn:hover {
            background: var(--accent-hover);
        }
        
        .btn-block {
            width: 100%;
        }
        
        .btn-success {
            background: var(--success);
        }
        
        .btn-danger {
            background: var(--danger);
        }
        
        .btn-sm {
            padding: 0.5rem 1rem;
            font-size: 0.875rem;
        }
        
        /* Online Users */
        .online-users {
            padding: 1rem;
            flex: 1;
            overflow-y: auto;
        }
        
        .user-card {
            display: flex;
            align-items: center;
            padding: 0.75rem;
            background: var(--bg-tertiary);
            border-radius: 0.375rem;
            margin-bottom: 0.5rem;
            cursor: pointer;
            transition: background 0.2s;
        }
        
        .user-card:hover {
            background: #4b5563;
        }
        
        .user-card.active {
            background: var(--accent);
        }
        
        .user-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: var(--accent);
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 1rem;
            font-weight: bold;
        }
        
        .user-info {
            flex: 1;
        }
        
        .user-name {
            font-weight: 500;
        }
        
        .user-status {
            font-size: 0.875rem;
            color: var(--text-secondary);
        }
        
        .status-online {
            color: var(--success);
        }
        
        .status-offline {
            color: var(--text-secondary);
        }
        
        /* Chat View */
        .chat-container {
            display: flex;
            flex-direction: column;
            height: 100%;
        }
        
        .chat-header {
            padding: 1rem;
            border-bottom: 1px solid var(--bg-tertiary);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .chat-messages {
            flex: 1;
            overflow-y: auto;
            padding: 1rem;
        }
        
        .message {
            margin-bottom: 1rem;
            max-width: 70%;
        }
        
        .message.sent {
            margin-left: auto;
            text-align: right;
        }
        
        .message-content {
            display: inline-block;
            padding: 0.75rem 1rem;
            background: var(--bg-tertiary);
            border-radius: 1rem;
            word-break: break-word;
        }
        
        .message.sent .message-content {
            background: var(--accent);
        }
        
        .message-time {
            font-size: 0.75rem;
            color: var(--text-secondary);
            margin-top: 0.25rem;
        }
        
        .chat-input-container {
            padding: 1rem;
            border-top: 1px solid var(--bg-tertiary);
        }
        
        .chat-input {
            width: 100%;
            padding: 0.75rem;
            background: var(--bg-tertiary);
            border: 1px solid var(--bg-tertiary);
            border-radius: 0.375rem;
            color: var(--text-primary);
            font-size: 1rem;
            resize: none;
            min-height: 60px;
        }
        
        /* Files View */
        .files-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }
        
        .file-card {
            background: var(--bg-secondary);
            border-radius: 0.5rem;
            padding: 1rem;
            border: 1px solid var(--bg-tertiary);
            transition: transform 0.2s;
            cursor: pointer;
        }
        
        .file-card:hover {
            transform: translateY(-2px);
            border-color: var(--accent);
        }
        
        .file-icon {
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }
        
        .file-name {
            font-weight: 500;
            margin-bottom: 0.25rem;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        
        .file-size {
            font-size: 0.875rem;
            color: var(--text-secondary);
        }
        
        /* Feed View */
        .post-card {
            background: var(--bg-secondary);
            border-radius: 0.5rem;
            padding: 1.5rem;
            margin-bottom: 1rem;
            border: 1px solid var(--bg-tertiary);
        }
        
        .post-header {
            display: flex;
            align-items: center;
            margin-bottom: 1rem;
        }
        
        .post-content {
            margin-bottom: 1rem;
            line-height: 1.6;
        }
        
        .post-actions {
            display: flex;
            gap: 1rem;
            border-top: 1px solid var(--bg-tertiary);
            padding-top: 1rem;
        }
        
        .post-action {
            background: none;
            border: none;
            color: var(--text-secondary);
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .post-action:hover {
            color: var(--accent);
        }
        
        /* Utilities */
        .hidden {
            display: none !important;
        }
        
        .text-center {
            text-align: center;
        }
        
        .mt-2 { margin-top: 0.5rem; }
        .mt-4 { margin-top: 1rem; }
        .mb-2 { margin-bottom: 0.5rem; }
        .mb-4 { margin-bottom: 1rem; }
        .ml-2 { margin-left: 0.5rem; }
        .p-4 { padding: 1rem; }
        
        .notification {
            position: fixed;
            top: 1rem;
            right: 1rem;
            padding: 1rem;
            background: var(--success);
            color: white;
            border-radius: 0.375rem;
            animation: slideIn 0.3s ease;
            z-index: 1000;
        }
        
        .notification.error {
            background: var(--danger);
        }
        
        @keyframes slideIn {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        .loading {
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
        }
        
        .error-message {
            background: var(--danger);
            color: white;
            padding: 1rem;
            border-radius: 0.375rem;
            margin: 1rem 0;
        }
    </style>
</head>
<body>
    <div id="authView" class="auth-container">
        <div class="auth-tabs">
            <div class="auth-tab active" onclick="showAuthTab('login')">Login</div>
            <div class="auth-tab" onclick="showAuthTab('register')">Register</div>
        </div>
        
        <div id="loginForm">
            <div class="form-group">
                <label for="loginUsername">Username</label>
                <input type="text" id="loginUsername" class="form-control" placeholder="Enter username">
            </div>
            <div class="form-group">
                <label for="loginPassword">Password</label>
                <input type="password" id="loginPassword" class="form-control" placeholder="Enter password">
            </div>
            <button onclick="login()" class="btn btn-block">Sign In</button>
        </div>
        
        <div id="registerForm" class="hidden">
            <div class="form-group">
                <label for="registerUsername">Username</label>
                <input type="text" id="registerUsername" class="form-control" placeholder="Choose username (3-20 chars)">
            </div>
            <div class="form-group">
                <label for="registerPassword">Password</label>
                <input type="password" id="registerPassword" class="form-control" placeholder="Choose password (min 6 chars)">
            </div>
            <div class="form-group">
                <label for="registerBio">Bio (Optional)</label>
                <textarea id="registerBio" class="form-control" placeholder="Tell us about yourself" rows="3"></textarea>
            </div>
            <button onclick="register()" class="btn btn-block btn-success">Create Account</button>
        </div>
    </div>
    
    <div id="app" class="app hidden">
        <div class="sidebar">
            <div class="header">
                <h2>🌐 LanWorld</h2>
                <div id="userMenu">
                    <span id="currentUsername"></span>
                    <button onclick="logout()" class="btn btn-danger btn-sm ml-2">Logout</button>
                </div>
            </div>
            
            <div class="online-users" id="onlineUsers">
                <h3>👥 Online Users</h3>
                <div id="usersList" class="loading">Loading...</div>
            </div>
            
            <div class="p-4">
                <div class="btn-group">
                    <button onclick="showView('chat')" class="btn btn-block mb-2">💬 Chat</button>
                    <button onclick="showView('files')" class="btn btn-block mb-2">📁 Files</button>
                    <button onclick="showView('feed')" class="btn btn-block mb-2">📝 Feed</button>
                    <button onclick="showView('discover')" class="btn btn-block">🔍 Discover</button>
                </div>
            </div>
        </div>
        
        <div class="main-content">
            <div class="view-container">
                <!-- Chat View -->
                <div id="chatView" class="view">
                    <div class="chat-container">
                        <div class="chat-header">
                            <h3 id="chatWith">Select a user to chat with</h3>
                        </div>
                        <div class="chat-messages" id="chatMessages"></div>
                        <div class="chat-input-container">
                            <textarea 
                                id="messageInput" 
                                class="chat-input" 
                                placeholder="Type your message here..."
                                onkeydown="if(event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); sendMessage(); }"
                                disabled
                            ></textarea>
                            <button onclick="sendMessage()" class="btn mt-2" disabled id="sendButton">Send</button>
                        </div>
                    </div>
                </div>
                
                <!-- Files View -->
                <div id="filesView" class="view">
                    <h3>📁 File Sharing</h3>
                    <div class="mb-4">
                        <input type="file" id="fileUpload" class="form-control mb-2">
                        <button onclick="uploadFile()" class="btn">Upload File</button>
                        <small style="color: var(--text-secondary); display: block; margin-top: 0.5rem;">
                            Max 100MB. Allowed: documents, images, archives, media files
                        </small>
                    </div>
                    <div id="filesList" class="files-grid loading">Loading files...</div>
                </div>
                
                <!-- Feed View -->
                <div id="feedView" class="view">
                    <h3>📝 LAN Feed</h3>
                    <div class="mb-4">
                        <textarea id="postContent" class="form-control mb-2" placeholder="What's happening on the LAN?" rows="3"></textarea>
                        <button onclick="createPost()" class="btn">Post Update</button>
                    </div>
                    <div id="postsList" class="loading">Loading posts...</div>
                </div>
                
                <!-- Discover View -->
                <div id="discoverView" class="view">
                    <h3>🔍 LAN Discovery</h3>
                    <div class="post-card">
                        <h4>Server Information</h4>
                        <p id="serverInfo">Loading...</p>
                    </div>
                    <div class="post-card">
                        <h4>Connected Users</h4>
                        <div id="connectedUsers">Loading...</div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let currentUser = null;
        let currentToken = null;
        let websocket = null;
        let currentChatUser = null;
        let reconnectAttempts = 0;
        const maxReconnectAttempts = 5;
        
        // Auth functions
        function showAuthTab(tab) {
            document.querySelectorAll('.auth-tab').forEach(t => t.classList.remove('active'));
            document.getElementById('loginForm').classList.add('hidden');
            document.getElementById('registerForm').classList.add('hidden');
            
            if (tab === 'login') {
                document.querySelector('.auth-tab:nth-child(1)').classList.add('active');
                document.getElementById('loginForm').classList.remove('hidden');
            } else {
                document.querySelector('.auth-tab:nth-child(2)').classList.add('active');
                document.getElementById('registerForm').classList.remove('hidden');
            }
        }
        
        function showNotification(message, type = 'success') {
            const notification = document.createElement('div');
            notification.className = `notification ${type === 'error' ? 'error' : ''}`;
            notification.textContent = message;
            
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.remove();
            }, 3000);
        }
        
        async function login() {
            const username = document.getElementById('loginUsername').value;
            const password = document.getElementById('loginPassword').value;
            
            if (!username || !password) {
                showNotification('Please enter both username and password', 'error');
                return;
            }
            
            try {
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username, password})
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    currentUser = data.user;
                    currentToken = data.token;
                    localStorage.setItem('lanworld_token', data.token);
                    showMainApp();
                    connectWebSocket();
                    showNotification('Login successful!');
                } else {
                    showNotification('Login failed: ' + (data.detail || 'Unknown error'), 'error');
                }
            } catch(e) {
                showNotification('Login error: ' + e.message, 'error');
                console.error('Login error:', e);
            }
        }
        
        async function register() {
            const username = document.getElementById('registerUsername').value;
            const password = document.getElementById('registerPassword').value;
            const bio = document.getElementById('registerBio').value || '';
            
            if (!username || !password) {
                showNotification('Please enter both username and password', 'error');
                return;
            }
            
            if (username.length < 3 || username.length > 20) {
                showNotification('Username must be 3-20 characters', 'error');
                return;
            }
            
            if (password.length < 6) {
                showNotification('Password must be at least 6 characters', 'error');
                return;
            }
            
            try {
                const response = await fetch('/api/auth/register', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username, password, bio})
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    showNotification('Registration successful! Please login.');
                    showAuthTab('login');
                    document.getElementById('loginUsername').value = username;
                    document.getElementById('loginPassword').value = '';
                } else {
                    showNotification('Registration failed: ' + (data.detail || 'Unknown error'), 'error');
                }
            } catch(e) {
                showNotification('Registration error: ' + e.message, 'error');
                console.error('Registration error:', e);
            }
        }
        
        function logout() {
            if (websocket) {
                websocket.close();
            }
            localStorage.removeItem('lanworld_token');
            currentUser = null;
            currentToken = null;
            document.getElementById('app').classList.add('hidden');
            document.getElementById('authView').classList.remove('hidden');
            showNotification('Logged out successfully');
        }
        
        // Main app functions
        function showMainApp() {
            document.getElementById('authView').classList.add('hidden');
            document.getElementById('app').classList.remove('hidden');
            document.getElementById('currentUsername').textContent = currentUser.username;
            showView('chat');
            loadOnlineUsers();
            loadFiles();
            loadPosts();
        }
        
        function showView(viewName) {
            document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
            document.getElementById(viewName + 'View').classList.add('active');
            
            if (viewName === 'discover') {
                loadDiscoveryInfo();
            }
        }
        
        // WebSocket connection
        function connectWebSocket() {
            if (!currentToken) return;
            
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/api/ws?token=${currentToken}`;
            
            websocket = new WebSocket(wsUrl);
            
            websocket.onopen = () => {
                console.log('WebSocket connected');
                reconnectAttempts = 0;
                showNotification('Connected to server');
            };
            
            websocket.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    handleWebSocketMessage(data);
                } catch (e) {
                    console.error('Error parsing WebSocket message:', e);
                }
            };
            
            websocket.onclose = (event) => {
                console.log('WebSocket disconnected:', event.code, event.reason);
                
                if (currentToken && reconnectAttempts < maxReconnectAttempts) {
                    reconnectAttempts++;
                    const delay = Math.min(1000 * reconnectAttempts, 10000);
                    console.log(`Reconnecting in ${delay}ms... (attempt ${reconnectAttempts}/${maxReconnectAttempts})`);
                    
                    setTimeout(() => {
                        if (currentToken) {
                            connectWebSocket();
                        }
                    }, delay);
                } else if (reconnectAttempts >= maxReconnectAttempts) {
                    showNotification('Lost connection to server. Please refresh the page.', 'error');
                }
            };
            
            websocket.onerror = (error) => {
                console.error('WebSocket error:', error);
            };
        }
        
        function handleWebSocketMessage(data) {
            switch(data.type) {
                case 'user_status':
                    updateUserStatus(data.user_id, data.online);
                    break;
                case 'message':
                    if (data.sender_id === currentChatUser) {
                        addMessageToChat(data, false);
                    } else {
                        showNotification(`New message from ${data.sender_username || 'user'}`);
                    }
                    break;
                case 'online_users':
                    updateOnlineUsers(data.users);
                    break;
                case 'error':
                    showNotification(data.message || 'WebSocket error', 'error');
                    break;
            }
        }
        
        // User management
        async function loadOnlineUsers() {
            try {
                const response = await fetch('/api/users/online', {
                    headers: {'Authorization': `Bearer ${currentToken}`}
                });
                if (response.ok) {
                    const users = await response.json();
                    updateOnlineUsers(users);
                } else {
                    document.getElementById('usersList').innerHTML = '<div class="error-message">Failed to load users</div>';
                }
            } catch(e) {
                console.error('Error loading users:', e);
                document.getElementById('usersList').innerHTML = '<div class="error-message">Network error loading users</div>';
            }
        }
        
        function updateOnlineUsers(users) {
            const container = document.getElementById('usersList');
            
            if (!users || users.length === 0) {
                container.innerHTML = '<p style="color: var(--text-secondary); padding: 1rem;">No other users online</p>';
                return;
            }
            
            container.innerHTML = '';
            
            users.forEach(user => {
                if (user.id === currentUser.id) return;
                
                const userCard = document.createElement('div');
                userCard.className = `user-card ${user.id === currentChatUser ? 'active' : ''}`;
                userCard.onclick = () => startChat(user);
                
                const avatar = document.createElement('div');
                avatar.className = 'user-avatar';
                avatar.textContent = user.username.charAt(0).toUpperCase();
                
                const info = document.createElement('div');
                info.className = 'user-info';
                
                const name = document.createElement('div');
                name.className = 'user-name';
                name.textContent = user.username;
                
                const status = document.createElement('div');
                status.className = `user-status ${user.online ? 'status-online' : 'status-offline'}`;
                status.textContent = user.online ? 'Online' : 'Offline';
                
                info.appendChild(name);
                info.appendChild(status);
                userCard.appendChild(avatar);
                userCard.appendChild(info);
                container.appendChild(userCard);
            });
        }
        
        function updateUserStatus(userId, online) {
            loadOnlineUsers();
        }
        
        // Chat functions
        function startChat(user) {
            currentChatUser = user.id;
            document.getElementById('chatWith').textContent = `Chat with ${user.username}`;
            document.getElementById('messageInput').disabled = false;
            document.getElementById('sendButton').disabled = false;
            loadChatHistory(user.id);
            updateOnlineUsers();
        }
        
        async function loadChatHistory(userId) {
            try {
                const response = await fetch(`/api/messages/${userId}`, {
                    headers: {'Authorization': `Bearer ${currentToken}`}
                });
                
                if (response.ok) {
                    const messages = await response.json();
                    const container = document.getElementById('chatMessages');
                    container.innerHTML = '';
                    
                    if (messages.length === 0) {
                        container.innerHTML = '<p style="color: var(--text-secondary); text-align: center; padding: 2rem;">No messages yet. Start the conversation!</p>';
                        return;
                    }
                    
                    messages.forEach(msg => {
                        addMessageToChat(msg, msg.sender_id === currentUser.id);
                    });
                    container.scrollTop = container.scrollHeight;
                }
            } catch(e) {
                console.error('Error loading chat:', e);
                document.getElementById('chatMessages').innerHTML = '<div class="error-message">Failed to load chat history</div>';
            }
        }
        
        function addMessageToChat(message, isSent) {
            const container = document.getElementById('chatMessages');
            const messageDiv = document.createElement('div');
            messageDiv.className = `message ${isSent ? 'sent' : 'received'}`;
            
            const content = document.createElement('div');
            content.className = 'message-content';
            content.textContent = message.content;
            
            const time = document.createElement('div');
            time.className = 'message-time';
            time.textContent = new Date(message.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
            
            messageDiv.appendChild(content);
            messageDiv.appendChild(time);
            container.appendChild(messageDiv);
            container.scrollTop = container.scrollHeight;
        }
        
        async function sendMessage() {
            const input = document.getElementById('messageInput');
            const content = input.value.trim();
            
            if (!content || !currentChatUser) return;
            
            try {
                const response = await fetch('/api/messages', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${currentToken}`
                    },
                    body: JSON.stringify({
                        recipient_id: currentChatUser,
                        content: content,
                        type: 'text'
                    })
                });
                
                if (response.ok) {
                    const message = await response.json();
                    addMessageToChat(message, true);
                    input.value = '';
                    
                    // Send via WebSocket if connected
                    if (websocket && websocket.readyState === WebSocket.OPEN) {
                        websocket.send(JSON.stringify({
                            type: 'message',
                            recipient_id: currentChatUser,
                            content: content
                        }));
                    }
                } else {
                    const error = await response.json();
                    showNotification('Failed to send message: ' + (error.detail || 'Unknown error'), 'error');
                }
            } catch(e) {
                console.error('Error sending message:', e);
                showNotification('Failed to send message: ' + e.message, 'error');
            }
        }
        
        // File functions
        async function uploadFile() {
            const input = document.getElementById('fileUpload');
            if (!input.files.length) {
                showNotification('Please select a file first', 'error');
                return;
            }
            
            const file = input.files[0];
            if (file.size > 100 * 1024 * 1024) {
                showNotification('File too large (max 100MB)', 'error');
                return;
            }
            
            try {
                const formData = new FormData();
                formData.append('file', file);
                
                const response = await fetch('/api/files/upload', {
                    method: 'POST',
                    headers: {'Authorization': `Bearer ${currentToken}`},
                    body: formData
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    loadFiles();
                    input.value = '';
                    showNotification(`File "${data.filename}" uploaded successfully!`);
                } else {
                    showNotification('Upload failed: ' + (data.detail || 'Unknown error'), 'error');
                }
            } catch(e) {
                showNotification('Upload error: ' + e.message, 'error');
                console.error('Upload error:', e);
            }
        }
        
        async function loadFiles() {
            try {
                const response = await fetch('/api/files', {
                    headers: {'Authorization': `Bearer ${currentToken}`}
                });
                
                if (response.ok) {
                    const files = await response.json();
                    const container = document.getElementById('filesList');
                    container.innerHTML = '';
                    
                    if (files.length === 0) {
                        container.innerHTML = '<p style="color: var(--text-secondary);">No files uploaded yet</p>';
                        return;
                    }
                    
                    files.forEach(file => {
                        const fileCard = document.createElement('div');
                        fileCard.className = 'file-card';
                        fileCard.onclick = () => downloadFile(file.id);
                        
                        fileCard.innerHTML = `
                            <div class="file-icon">📄</div>
                            <div class="file-name" title="${file.filename}">${file.filename}</div>
                            <div class="file-size">${formatFileSize(file.size)}</div>
                        `;
                        
                        container.appendChild(fileCard);
                    });
                }
            } catch(e) {
                console.error('Error loading files:', e);
                document.getElementById('filesList').innerHTML = '<div class="error-message">Failed to load files</div>';
            }
        }
        
        async function downloadFile(fileId) {
            window.open(`/api/files/${fileId}?token=${currentToken}`, '_blank');
        }
        
        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        // Feed functions
        async function createPost() {
            const content = document.getElementById('postContent').value.trim();
            if (!content) {
                showNotification('Please enter some content for your post', 'error');
                return;
            }
            
            try {
                const response = await fetch('/api/feed/posts', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${currentToken}`
                    },
                    body: JSON.stringify({content})
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    document.getElementById('postContent').value = '';
                    loadPosts();
                    showNotification('Post created successfully!');
                } else {
                    showNotification('Failed to create post: ' + (data.detail || 'Unknown error'), 'error');
                }
            } catch(e) {
                showNotification('Error creating post: ' + e.message, 'error');
                console.error('Error creating post:', e);
            }
        }
        
        async function loadPosts() {
            try {
                const response = await fetch('/api/feed/posts', {
                    headers: {'Authorization': `Bearer ${currentToken}`}
                });
                
                if (response.ok) {
                    const posts = await response.json();
                    const container = document.getElementById('postsList');
                    container.innerHTML = '';
                    
                    if (posts.length === 0) {
                        container.innerHTML = '<p style="color: var(--text-secondary);">No posts yet. Be the first to post!</p>';
                        return;
                    }
                    
                    posts.forEach(post => {
                        const postCard = document.createElement('div');
                        postCard.className = 'post-card';
                        
                        postCard.innerHTML = `
                            <div class="post-header">
                                <div class="user-avatar" style="margin-right: 1rem;">
                                    ${post.author_username?.charAt(0).toUpperCase() || 'U'}
                                </div>
                                <div>
                                    <div class="user-name">${post.author_username || 'Unknown'}</div>
                                    <div class="user-status">${new Date(post.timestamp).toLocaleString()}</div>
                                </div>
                            </div>
                            <div class="post-content">${escapeHtml(post.content)}</div>
                            <div class="post-actions">
                                <button class="post-action" onclick="likePost('${post.id}')">
                                    👍 ${post.likes || 0}
                                </button>
                            </div>
                        `;
                        
                        container.appendChild(postCard);
                    });
                }
            } catch(e) {
                console.error('Error loading posts:', e);
                document.getElementById('postsList').innerHTML = '<div class="error-message">Failed to load posts</div>';
            }
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        async function likePost(postId) {
            try {
                await fetch(`/api/feed/posts/${postId}/like`, {
                    method: 'POST',
                    headers: {'Authorization': `Bearer ${currentToken}`}
                });
                loadPosts();
            } catch(e) {
                console.error('Error liking post:', e);
                showNotification('Failed to like post', 'error');
            }
        }
        
        // Discovery functions
        async function loadDiscoveryInfo() {
            try {
                const response = await fetch('/api/discovery/info');
                if (response.ok) {
                    const info = await response.json();
                    document.getElementById('serverInfo').innerHTML = `
                        <p><strong>Host:</strong> ${info.host}</p>
                        <p><strong>Port:</strong> ${info.port}</p>
                        <p><strong>Users Online:</strong> ${info.users_online}</p>
                        <p><strong>Version:</strong> ${info.version}</p>
                    `;
                }
            } catch(e) {
                console.error('Error loading discovery info:', e);
                document.getElementById('serverInfo').innerHTML = '<div class="error-message">Failed to load server info</div>';
            }
        }
        
        // Auto-login from localStorage
        async function tryAutoLogin() {
            const token = localStorage.getItem('lanworld_token');
            if (!token) return false;
            
            try {
                const response = await fetch('/api/auth/validate', {
                    headers: {'Authorization': `Bearer ${token}`}
                });
                
                if (response.ok) {
                    const data = await response.json();
                    currentUser = data.user;
                    currentToken = token;
                    showMainApp();
                    connectWebSocket();
                    return true;
                }
            } catch(e) {
                console.error('Auto-login failed:', e);
            }
            
            localStorage.removeItem('lanworld_token');
            return false;
        }
        
        // Initialize app
        window.onload = async () => {
            console.log('LanWorld loaded');
            showAuthTab('login');
            
            // Try auto-login
            await tryAutoLogin();
        };
    </script>
</body>
</html>"""


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n👋 LanWorld server stopped gracefully")
        print("Thank you for using LanWorld!")
    except Exception as e:
        print(f"\n❌ Fatal error starting LanWorld: {e}")
        print("\nTraceback:")
        traceback.print_exc()
        print("\nTry installing dependencies with:")
        print("pip install fastapi uvicorn bcrypt python-multipart aiosqlite")
        print("\nOptional for HTTPS and better network discovery:")
        print("pip install cryptography netifaces")
        input("\nPress Enter to exit...")

