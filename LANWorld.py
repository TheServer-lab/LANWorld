#!/usr/bin/env python3
"""
LanWorld - Complete LAN Ecosystem in a single file
Simplified version with text file account storage
"""

import asyncio
import base64
import hashlib
import json
import os
import secrets
import socket
import threading
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set

# Third-party imports
try:
    from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, UploadFile, File, Form, Depends, Request, Header
    from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    import uvicorn
    import bcrypt
    import websockets
    from pydantic import BaseModel
    from typing import Union
except ImportError:
    print("Installing required packages...")
    import subprocess
    import sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", 
                          "fastapi", "uvicorn", "websockets", "bcrypt", "python-multipart"])
    print("Packages installed. Please restart.")
    exit()

# ==================== CONFIGURATION ====================
CONFIG = {
    "host": "0.0.0.0",
    "port": 8000,
    "discovery_port": 8888,
    "upload_dir": "lanworld_uploads",
    "accounts_file": "accounts.txt",
    "data_file": "lanworld_data.json",
    "secret_key": secrets.token_hex(32),
    "max_upload_size": 100 * 1024 * 1024,  # 100MB
    "admin_password": "admin123",  # Change this!
}

# ==================== DATA STORAGE ====================
class DataStorage:
    def __init__(self, data_file="lanworld_data.json", accounts_file="accounts.txt"):
        self.data_file = data_file
        self.accounts_file = accounts_file
        self.lock = threading.Lock()
        self.init_storage()
    
    def init_storage(self):
        with self.lock:
            # Initialize accounts file
            if not os.path.exists(self.accounts_file):
                with open(self.accounts_file, "w") as f:
                    pass  # Create empty file
            
            # Initialize data file
            if not os.path.exists(self.data_file):
                default_data = {
                    "users": {},
                    "messages": [],
                    "files": [],
                    "posts": [],
                    "sessions": {}
                }
                with open(self.data_file, "w") as f:
                    json.dump(default_data, f, indent=2)
    
    def read_accounts(self):
        with self.lock:
            accounts = {}
            if os.path.exists(self.accounts_file):
                with open(self.accounts_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and ":" in line:
                            username, password = line.split(":", 1)
                            accounts[username] = password
            return accounts
    
    def write_account(self, username: str, password: str):
        with self.lock:
            with open(self.accounts_file, "a") as f:
                f.write(f"{username}:{password}\n")
    
    def read_data(self):
        with self.lock:
            with open(self.data_file, "r") as f:
                return json.load(f)
    
    def write_data(self, data):
        with self.lock:
            with open(self.data_file, "w") as f:
                json.dump(data, f, indent=2)
    
    def get_user_by_username(self, username: str):
        data = self.read_data()
        for user_id, user in data["users"].items():
            if user["username"] == username:
                return {"id": user_id, **user}
        return None
    
    def get_user_by_id(self, user_id: str):
        data = self.read_data()
        return data["users"].get(user_id)
    
    def create_user(self, user_id: str, user_data: dict):
        data = self.read_data()
        data["users"][user_id] = user_data
        self.write_data(data)
    
    def update_user(self, user_id: str, updates: dict):
        data = self.read_data()
        if user_id in data["users"]:
            data["users"][user_id].update(updates)
            self.write_data(data)
            return True
        return False
    
    def add_message(self, message: dict):
        data = self.read_data()
        data["messages"].append(message)
        self.write_data(data)
    
    def get_messages(self, user1_id: str, user2_id: str):
        data = self.read_data()
        messages = []
        for msg in data["messages"]:
            if (msg["sender_id"] == user1_id and msg["recipient_id"] == user2_id) or \
               (msg["sender_id"] == user2_id and msg["recipient_id"] == user1_id):
                messages.append(msg)
        return sorted(messages, key=lambda x: x.get("timestamp", ""))
    
    def add_file(self, file_data: dict):
        data = self.read_data()
        data["files"].append(file_data)
        self.write_data(data)
    
    def get_user_files(self, user_id: str):
        data = self.read_data()
        return [f for f in data["files"] if f["owner_id"] == user_id or f.get("visibility") == "public"]
    
    def add_post(self, post: dict):
        data = self.read_data()
        data["posts"].append(post)
        self.write_data(data)
    
    def get_posts(self):
        data = self.read_data()
        return sorted(data["posts"], key=lambda x: x.get("timestamp", ""), reverse=True)[:50]
    
    def add_session(self, token: str, user_id: str, expires_at: str):
        data = self.read_data()
        data["sessions"][token] = {"user_id": user_id, "expires_at": expires_at}
        self.write_data(data)
    
    def get_session(self, token: str):
        data = self.read_data()
        return data["sessions"].get(token)
    
    def delete_session(self, token: str):
        data = self.read_data()
        if token in data["sessions"]:
            del data["sessions"][token]
            self.write_data(data)
    
    def get_online_users(self):
        data = self.read_data()
        online_users = []
        for user_id, user in data["users"].items():
            if user.get("online", False):
                online_users.append({"id": user_id, **user})
        return online_users

storage = DataStorage(CONFIG["data_file"], CONFIG["accounts_file"])

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

# ==================== WEBSOCKET MANAGER ====================
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.user_connections: Dict[str, str] = {}
        self.lock = threading.Lock()
    
    async def connect(self, websocket: WebSocket, user_id: str):
        await websocket.accept()
        conn_id = str(uuid.uuid4())
        
        with self.lock:
            self.active_connections[conn_id] = websocket
            self.user_connections[user_id] = conn_id
        
        # Update user as online
        storage.update_user(user_id, {"online": True, "last_seen": datetime.now().isoformat()})
        
        # Broadcast user online status
        await self.broadcast_user_status(user_id, True)
        return conn_id
    
    def disconnect(self, user_id: str):
        with self.lock:
            if user_id in self.user_connections:
                conn_id = self.user_connections[user_id]
                if conn_id in self.active_connections:
                    del self.active_connections[conn_id]
                del self.user_connections[user_id]
        
        # Update user as offline
        storage.update_user(user_id, {"online": False, "last_seen": datetime.now().isoformat()})
    
    async def send_personal_message(self, user_id: str, message: dict):
        with self.lock:
            if user_id in self.user_connections:
                conn_id = self.user_connections[user_id]
                if conn_id in self.active_connections:
                    websocket = self.active_connections[conn_id]
                    try:
                        await websocket.send_json(message)
                    except:
                        pass
    
    async def broadcast(self, message: dict, exclude_user: str = None):
        disconnected = []
        with self.lock:
            connections_copy = list(self.user_connections.items())
        
        for user_id, conn_id in connections_copy:
            if user_id != exclude_user:
                with self.lock:
                    websocket = self.active_connections.get(conn_id)
                if websocket:
                    try:
                        await websocket.send_json(message)
                    except:
                        disconnected.append(user_id)
        
        # Clean up disconnected users
        for user_id in disconnected:
            self.disconnect(user_id)
    
    async def broadcast_user_status(self, user_id: str, online: bool):
        message = {
            "type": "user_status",
            "user_id": user_id,
            "online": online,
            "timestamp": datetime.now().isoformat()
        }
        await self.broadcast(message, exclude_user=user_id)

manager = ConnectionManager()

# ==================== LAN DISCOVERY SERVICE ====================
class LanDiscovery:
    def __init__(self, port=8888):
        self.port = port
        self.running = False
        self.server_info = {
            "name": "LanWorld",
            "version": "1.0",
            "port": CONFIG["port"],
            "host": socket.gethostbyname(socket.gethostname())
        }
    
    def start(self):
        self.running = True
        thread = threading.Thread(target=self._broadcast_service, daemon=True)
        thread.start()
    
    def stop(self):
        self.running = False
    
    def _broadcast_service(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(0.2)
        
        while self.running:
            try:
                message = json.dumps(self.server_info).encode('utf-8')
                sock.sendto(message, ('255.255.255.255', self.port))
            except:
                pass
            
            time.sleep(30)

discovery = LanDiscovery(CONFIG["discovery_port"])

# ==================== AUTH UTILITIES ====================
def hash_password(password: str) -> str:
    # Simple hash for demonstration (use bcrypt in production)
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return hash_password(plain_password) == hashed_password

def create_session_token(user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.now() + timedelta(days=7)).isoformat()
    storage.add_session(token, user_id, expires_at)
    return token

def verify_session_token(token: str) -> Optional[str]:
    session = storage.get_session(token)
    if session:
        expires_at = datetime.fromisoformat(session["expires_at"])
        if expires_at > datetime.now():
            return session["user_id"]
    return None

async def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = authorization[7:]
    user_id = verify_session_token(token)
    
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    return user_id

# ==================== FILE MANAGEMENT ====================
class FileManager:
    def __init__(self, upload_dir="lanworld_uploads"):
        self.upload_dir = Path(upload_dir)
        self.upload_dir.mkdir(exist_ok=True)
    
    def save_file(self, file: UploadFile, owner_id: str) -> dict:
        # Generate unique filename
        file_ext = Path(file.filename).suffix if Path(file.filename).suffix else ".bin"
        file_id = str(uuid.uuid4())
        filename = f"{file_id}{file_ext}"
        filepath = self.upload_dir / filename
        
        # Save file
        content = file.file.read()
        with open(filepath, "wb") as f:
            f.write(content)
        
        # Create file record
        file_data = {
            "id": file_id,
            "owner_id": owner_id,
            "filename": file.filename,
            "filepath": str(filepath),
            "size": len(content),
            "visibility": "private",
            "uploaded_at": datetime.now().isoformat()
        }
        
        storage.add_file(file_data)
        return file_data
    
    def get_file(self, file_id: str, user_id: str) -> Optional[Path]:
        files = storage.get_user_files(user_id)
        for file in files:
            if file["id"] == file_id:
                return Path(file["filepath"])
        return None

file_manager = FileManager(CONFIG["upload_dir"])

# ==================== FASTAPI APP ====================
app = FastAPI(title="LanWorld", version="1.0")

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

@app.post("/api/auth/register")
async def register(user_data: UserCreate):
    try:
        # Check if username exists
        existing_user = storage.get_user_by_username(user_data.username)
        if existing_user:
            return JSONResponse(
                status_code=400,
                content={"detail": "Username already exists"}
            )
        
        # Create user
        user_id = str(uuid.uuid4())
        password_hash = hash_password(user_data.password)
        
        user_record = {
            "id": user_id,
            "username": user_data.username,
            "password_hash": password_hash,
            "avatar": "default.png",
            "bio": user_data.bio,
            "online": False,
            "created_at": datetime.now().isoformat(),
            "last_seen": datetime.now().isoformat()
        }
        
        storage.create_user(user_id, user_record)
        
        # Store in accounts.txt
        storage.write_account(user_data.username, password_hash)
        
        return {"message": "User created successfully"}
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"detail": f"Registration failed: {str(e)}"}
        )

@app.post("/api/auth/login")
async def login(user_data: UserLogin):
    try:
        # Find user
        user = storage.get_user_by_username(user_data.username)
        if not user:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid credentials"}
            )
        
        # Check password
        if not verify_password(user_data.password, user["password_hash"]):
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid credentials"}
            )
        
        # Update user status
        storage.update_user(user["id"], {"online": True, "last_seen": datetime.now().isoformat()})
        
        # Create session
        token = create_session_token(user["id"])
        
        return {
            "token": token,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "avatar": user["avatar"],
                "bio": user["bio"]
            }
        }
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"detail": f"Login failed: {str(e)}"}
        )

@app.get("/api/auth/validate")
async def validate_token(current_user: str = Depends(get_current_user)):
    user = storage.get_user_by_id(current_user)
    if user:
        return {"user": user}
    raise HTTPException(status_code=404, detail="User not found")

@app.websocket("/api/ws")
async def websocket_endpoint(websocket: WebSocket, token: str):
    user_id = verify_session_token(token)
    if not user_id:
        await websocket.close(code=1008)
        return
    
    conn_id = await manager.connect(websocket, user_id)
    
    try:
        # Send initial online users list
        online_users = storage.get_online_users()
        await websocket.send_json({
            "type": "online_users",
            "users": online_users
        })
        
        while True:
            try:
                data = await websocket.receive_json()
                
                if data["type"] == "message":
                    # Store message
                    message_id = str(uuid.uuid4())
                    message = {
                        "id": message_id,
                        "sender_id": user_id,
                        "recipient_id": data["recipient_id"],
                        "content": data["content"],
                        "timestamp": datetime.now().isoformat(),
                        "type": "text"
                    }
                    
                    storage.add_message(message)
                    
                    # Forward to recipient if online
                    await manager.send_personal_message(data["recipient_id"], {
                        "type": "message",
                        **message
                    })
                    
            except json.JSONDecodeError:
                pass
            except KeyError:
                pass
            except WebSocketDisconnect:
                break
                
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        manager.disconnect(user_id)

@app.get("/api/users/online")
async def get_online_users(current_user: str = Depends(get_current_user)):
    try:
        online_users = storage.get_online_users()
        # Remove current user from list
        online_users = [u for u in online_users if u["id"] != current_user]
        return online_users
    except:
        return []

@app.post("/api/messages")
async def send_message(message: MessageCreate, current_user: str = Depends(get_current_user)):
    try:
        message_id = str(uuid.uuid4())
        message_data = {
            "id": message_id,
            "sender_id": current_user,
            "recipient_id": message.recipient_id,
            "content": message.content,
            "timestamp": datetime.now().isoformat(),
            "type": message.type
        }
        
        storage.add_message(message_data)
        return message_data
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"detail": f"Failed to send message: {str(e)}"}
        )

@app.get("/api/messages/{user_id}")
async def get_messages(user_id: str, current_user: str = Depends(get_current_user)):
    try:
        messages = storage.get_messages(current_user, user_id)
        return messages
    except:
        return []

@app.post("/api/files/upload")
async def upload_file(file: UploadFile = File(...), current_user: str = Depends(get_current_user)):
    try:
        # Check file size
        content = await file.read()
        if len(content) > CONFIG["max_upload_size"]:
            return JSONResponse(
                status_code=413,
                content={"detail": "File too large"}
            )
        
        # Reset file pointer
        file.file.seek(0)
        
        # Save file
        file_data = file_manager.save_file(file, current_user)
        return file_data
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"detail": f"Upload failed: {str(e)}"}
        )

@app.get("/api/files")
async def list_files(current_user: str = Depends(get_current_user)):
    try:
        files = storage.get_user_files(current_user)
        return files
    except:
        return []

@app.get("/api/files/{file_id}")
async def download_file(file_id: str, token: str):
    try:
        user_id = verify_session_token(token)
        if not user_id:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid token"}
            )
        
        file_path = file_manager.get_file(file_id, user_id)
        if not file_path or not file_path.exists():
            return JSONResponse(
                status_code=404,
                content={"detail": "File not found"}
            )
        
        return FileResponse(
            path=file_path,
            filename=file_path.name,
            media_type="application/octet-stream"
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"detail": f"Download failed: {str(e)}"}
        )

@app.post("/api/feed/posts")
async def create_post(post: PostCreate, current_user: str = Depends(get_current_user)):
    try:
        post_id = str(uuid.uuid4())
        user = storage.get_user_by_id(current_user)
        
        post_data = {
            "id": post_id,
            "author_id": current_user,
            "author_username": user.get("username", "Unknown") if user else "Unknown",
            "content": post.content,
            "likes": 0,
            "timestamp": datetime.now().isoformat()
        }
        
        storage.add_post(post_data)
        return post_data
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"detail": f"Failed to create post: {str(e)}"}
        )

@app.get("/api/feed/posts")
async def get_posts(current_user: str = Depends(get_current_user)):
    try:
        posts = storage.get_posts()
        return posts
    except:
        return []

@app.post("/api/feed/posts/{post_id}/like")
async def like_post(post_id: str, current_user: str = Depends(get_current_user)):
    try:
        # In a real app, you'd update the specific post's like count
        # For simplicity, we'll just return success
        return {"message": "Post liked"}
    except:
        return JSONResponse(
            status_code=500,
            content={"detail": "Failed to like post"}
        )

@app.get("/api/discovery/info")
async def get_discovery_info():
    try:
        online_users = storage.get_online_users()
        return {
            "name": "LanWorld",
            "version": "1.0",
            "host": socket.gethostbyname(socket.gethostname()),
            "port": CONFIG["port"],
            "users_online": len(online_users)
        }
    except:
        return {
            "name": "LanWorld",
            "version": "1.0",
            "host": "localhost",
            "port": CONFIG["port"],
            "users_online": 0
        }

# ==================== FRONTEND HTML ====================
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LanWorld - Local Network Ecosystem</title>
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
                <input type="text" id="registerUsername" class="form-control" placeholder="Choose username">
            </div>
            <div class="form-group">
                <label for="registerPassword">Password</label>
                <input type="password" id="registerPassword" class="form-control" placeholder="Choose password">
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
                <div id="usersList"></div>
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
                    </div>
                    <div id="filesList" class="files-grid"></div>
                </div>
                
                <!-- Feed View -->
                <div id="feedView" class="view">
                    <h3>📝 LAN Feed</h3>
                    <div class="mb-4">
                        <textarea id="postContent" class="form-control mb-2" placeholder="What's happening on the LAN?" rows="3"></textarea>
                        <button onclick="createPost()" class="btn">Post Update</button>
                    </div>
                    <div id="postsList"></div>
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
                        <div id="connectedUsers"></div>
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
        
        async function login() {
            const username = document.getElementById('loginUsername').value;
            const password = document.getElementById('loginPassword').value;
            
            if (!username || !password) {
                alert('Please enter both username and password');
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
                    showMainApp();
                    connectWebSocket();
                } else {
                    alert('Login failed: ' + (data.detail || 'Unknown error'));
                }
            } catch(e) {
                alert('Login error: ' + e.message);
                console.error('Login error:', e);
            }
        }
        
        async function register() {
            const username = document.getElementById('registerUsername').value;
            const password = document.getElementById('registerPassword').value;
            const bio = document.getElementById('registerBio').value || '';
            
            if (!username || !password) {
                alert('Please enter both username and password');
                return;
            }
            
            if (username.length < 3) {
                alert('Username must be at least 3 characters');
                return;
            }
            
            if (password.length < 6) {
                alert('Password must be at least 6 characters');
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
                    alert('Registration successful! Please login.');
                    showAuthTab('login');
                    document.getElementById('loginUsername').value = username;
                    document.getElementById('loginPassword').value = '';
                } else {
                    alert('Registration failed: ' + (data.detail || 'Unknown error'));
                }
            } catch(e) {
                alert('Registration error: ' + e.message);
                console.error('Registration error:', e);
            }
        }
        
        function logout() {
            if (websocket) {
                websocket.close();
            }
            currentUser = null;
            currentToken = null;
            document.getElementById('app').classList.add('hidden');
            document.getElementById('authView').classList.remove('hidden');
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
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/api/ws?token=${currentToken}`;
            
            websocket = new WebSocket(wsUrl);
            
            websocket.onopen = () => {
                console.log('WebSocket connected');
            };
            
            websocket.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    handleWebSocketMessage(data);
                } catch (e) {
                    console.error('Error parsing WebSocket message:', e);
                }
            };
            
            websocket.onclose = () => {
                console.log('WebSocket disconnected');
                setTimeout(() => {
                    if (currentToken) {
                        connectWebSocket();
                    }
                }, 3000);
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
                    }
                    break;
                case 'online_users':
                    updateOnlineUsers(data.users);
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
                }
            } catch(e) {
                console.error('Error loading users:', e);
            }
        }
        
        function updateOnlineUsers(users) {
            const container = document.getElementById('usersList');
            container.innerHTML = '';
            
            if (users.length === 0) {
                container.innerHTML = '<p style="color: var(--text-secondary); padding: 1rem;">No other users online</p>';
                return;
            }
            
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
                    
                    messages.forEach(msg => {
                        addMessageToChat(msg, msg.sender_id === currentUser.id);
                    });
                    container.scrollTop = container.scrollHeight;
                }
            } catch(e) {
                console.error('Error loading chat:', e);
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
                }
            } catch(e) {
                console.error('Error sending message:', e);
            }
        }
        
        // File functions
        async function uploadFile() {
            const input = document.getElementById('fileUpload');
            if (!input.files.length) {
                alert('Please select a file first');
                return;
            }
            
            try {
                const formData = new FormData();
                formData.append('file', input.files[0]);
                
                const response = await fetch('/api/files/upload', {
                    method: 'POST',
                    headers: {'Authorization': `Bearer ${currentToken}`},
                    body: formData
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    loadFiles();
                    input.value = '';
                    alert(`File "${data.filename}" uploaded successfully!`);
                } else {
                    alert('Upload failed: ' + (data.detail || 'Unknown error'));
                }
            } catch(e) {
                alert('Upload error: ' + e.message);
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
                alert('Please enter some content for your post');
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
                } else {
                    alert('Failed to create post: ' + (data.detail || 'Unknown error'));
                }
            } catch(e) {
                alert('Error creating post: ' + e.message);
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
            }
        }
        
        // Initialize app
        window.onload = () => {
            console.log('LanWorld loaded');
            showAuthTab('login');
        };
    </script>
</body>
</html>"""

# ==================== MAIN ENTRY POINT ====================
def open_browser():
    import webbrowser
    import time
    time.sleep(2)
    webbrowser.open(f"http://localhost:{CONFIG['port']}")

def main():
    print("""
    ╔══════════════════════════════════════════╗
    ║           LanWorld 1.0                   ║
    ║   Complete LAN Ecosystem                 ║
    ║   100% Local - Zero Cloud                ║
    ╚══════════════════════════════════════════╝
    """)
    
    # Start LAN discovery
    discovery.start()
    print(f"🔍 LAN Discovery started on port {CONFIG['discovery_port']}")
    
    # Create upload directory
    Path(CONFIG["upload_dir"]).mkdir(exist_ok=True, parents=True)
    
    # Open browser
    import threading
    threading.Thread(target=open_browser, daemon=True).start()
    
    # Get IP addresses
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        ips = [local_ip]
    except:
        ips = []
    
    print(f"\n🌐 Server starting...")
    print(f"📡 Local URLs:")
    print(f"   http://localhost:{CONFIG['port']}")
    print(f"   http://127.0.0.1:{CONFIG['port']}")
    for ip in ips:
        if ip not in ['127.0.0.1', 'localhost']:
            print(f"   http://{ip}:{CONFIG['port']}")
    
    print(f"\n💡 Other users on your LAN can connect via:")
    print(f"   http://<YOUR-IP>:{CONFIG['port']}")
    print(f"\n🚀 Press Ctrl+C to stop the server\n")
    
    # Start server
    uvicorn.run(app, host=CONFIG["host"], port=CONFIG["port"], log_level="info")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 LanWorld server stopped")
        print("Thank you for using LanWorld!")
    except Exception as e:
        print(f"\n❌ Error starting LanWorld: {e}")
        print("\nTry installing dependencies with:")
        print("pip install fastapi uvicorn websockets bcrypt python-multipart")
        input("\nPress Enter to exit...")