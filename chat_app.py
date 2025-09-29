import streamlit as st
import datetime
import sqlite3
import base64
import hashlib
from cryptography.fernet import Fernet
from typing import List, Dict, Optional
from streamlit_autorefresh import st_autorefresh
import time

# Configure the page
st.set_page_config(
    page_title="Secure Chat App",
    page_icon="🔒",
    layout="wide"
)

# Database configuration
DATABASE_FILE = "db.sqlite3"

class EncryptionHandler:
    """Handles encryption and decryption of messages using Fernet (AES)."""
    
    @staticmethod
    def generate_key_from_password(password: str) -> bytes:
        """Generate Fernet key from password using SHA-256 and base64."""
        key = hashlib.sha256(password.encode()).digest()
        return base64.urlsafe_b64encode(key)
    
    @staticmethod
    def encrypt_message(message: str, key: bytes) -> str:
        """Encrypt a message using Fernet (AES)."""
        try:
            f = Fernet(key)
            encrypted = f.encrypt(message.encode('utf-8'))
            return encrypted.decode('utf-8')
        except Exception as e:
            st.error(f"Encryption error: {e}")
            return "[🔒 ENCRYPTION ERROR]"
    
    @staticmethod
    def decrypt_message(encrypted_text: str, key: bytes) -> str:
        """Decrypt a message using Fernet (AES)."""
        try:
            f = Fernet(key)
            decrypted = f.decrypt(encrypted_text.encode('utf-8'))
            return decrypted.decode('utf-8')
        except Exception:
            return "[🔒 ENCRYPTED - Cannot decrypt with this password]"

class SecureChatDatabase:
    """Handles all database operations for the secure chat app."""
    def __init__(self, db_file: str = DATABASE_FILE):
        """Initialize the database connection and create tables if needed."""
        self.db_file = db_file
        self.init_database()
    
    def init_database(self):
        """Initialize the database and create tables."""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Create messages table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT NOT NULL,
                    receiver TEXT NOT NULL,
                    message TEXT NOT NULL,
                    is_encrypted INTEGER DEFAULT 0,
                    timestamp TEXT NOT NULL,
                    read INTEGER DEFAULT 0
                )
            ''')
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            st.error(f"Database error: {e}")
            return False
    
    def add_message(self, sender: str, receiver: str, message: str, encryption_key: Optional[bytes] = None) -> bool:
        """Add a new message to the database."""
        timestamp = datetime.datetime.now().isoformat()
        
        is_encrypted = 0
        stored_message = message
        
        # Encrypt if key is provided
        if encryption_key is not None:
            stored_message = EncryptionHandler.encrypt_message(message, encryption_key)
            is_encrypted = 1
            
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO messages (sender, receiver, message, is_encrypted, timestamp, read)
                VALUES (?, ?, ?, ?, ?, 0)
            ''', (sender, receiver, stored_message, is_encrypted, timestamp))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            st.error(f"Error adding message: {e}")
            return False
    
    def get_conversation(self, user1: str, user2: str, encryption_key: Optional[bytes] = None) -> List[Dict[str, object]]:
        """Retrieve conversation between two users."""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            query = '''
                SELECT sender, receiver, message, is_encrypted, timestamp, read 
                FROM messages 
                WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
                ORDER BY timestamp ASC
            '''
            
            cursor.execute(query, (user1, user2, user2, user1))
            rows = cursor.fetchall()
            conn.close()
            
            messages: List[Dict[str, object]] = []
            for row in rows:
                message_text = row[2]
                is_encrypted = row[3]
                
                # Decrypt if message is encrypted and key is provided
                if is_encrypted:
                    if encryption_key is not None:
                        message_text = EncryptionHandler.decrypt_message(message_text, encryption_key)
                    else:
                        message_text = "[🔒 ENCRYPTED - Enter password to view]"
                
                messages.append({
                    'sender': row[0],
                    'receiver': row[1],
                    'message': message_text,
                    'is_encrypted': bool(is_encrypted),
                    'timestamp': datetime.datetime.fromisoformat(row[4]),
                    'read': row[5]
                })
            
            return messages
        except Exception as e:
            st.error(f"Error loading messages: {e}")
            return []
    
    def get_user_conversations(self, username: str) -> List[str]:
        """Get list of users that have conversation with given user."""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT DISTINCT 
                    CASE 
                        WHEN sender = ? THEN receiver
                        ELSE sender 
                    END as other_user
                FROM messages
                WHERE sender = ? OR receiver = ?
                ORDER BY other_user
            ''', (username, username, username))
            
            users = [row[0] for row in cursor.fetchall()]
            conn.close()
            return users
        except Exception:
            return []
    
    def get_message_count(self, user1: str, user2: str) -> int:
        """Get message count between two users."""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT COUNT(*) FROM messages 
                WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
            ''', (user1, user2, user2, user1))
            
            count = cursor.fetchone()[0]
            conn.close()
            return count
        except Exception:
            return 0
    
    def get_latest_message_id(self, user1: str, user2: str) -> int:
        """Get the ID of the latest message between two users."""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT MAX(id) FROM messages 
                WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
            ''', (user1, user2, user2, user1))
            
            result = cursor.fetchone()[0]
            conn.close()
            return result if result else 0
        except Exception:
            return 0
    
    def clear_conversation(self, user1: str, user2: str):
        """Clear conversation between two users."""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('''
                DELETE FROM messages 
                WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
            ''', (user1, user2, user2, user1))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            st.error(f"Error clearing: {e}")
            return False

    def mark_messages_as_read(self, sender: str, receiver: str):
        """Mark messages from sender to receiver as read."""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE messages SET read = 1
                WHERE sender = ? AND receiver = ? AND read = 0
            ''', (sender, receiver))
            conn.commit()
            conn.close()
        except Exception as e:
            st.error(f"Error marking messages as read: {e}")

# Initialize database
@st.cache_resource
def get_database():
    return SecureChatDatabase()

db = get_database()

# Initialize session state
def init_session_state():
    """Initialize the session state variables."""
    if "user_name" not in st.session_state:
        st.session_state.user_name = ""
    if "chat_partner" not in st.session_state:
        st.session_state.chat_partner = ""
    if "encryption_password" not in st.session_state:
        st.session_state.encryption_password = ""
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "last_message_id" not in st.session_state:
        st.session_state.last_message_id = 0
    if "last_refresh_time" not in st.session_state:
        st.session_state.last_refresh_time = time.time()

init_session_state()

def get_encryption_key() -> Optional[bytes]:
    """Get current encryption key if password is set."""
    if st.session_state.encryption_password:
        return EncryptionHandler.generate_key_from_password(st.session_state.encryption_password)
    return None

def load_conversation():
    """Load conversation between current users."""
    if st.session_state.user_name and st.session_state.chat_partner:
        encryption_key = get_encryption_key()
        st.session_state.messages = db.get_conversation(
            st.session_state.user_name,
            st.session_state.chat_partner,
            encryption_key
        )
        # Update last message ID
        st.session_state.last_message_id = db.get_latest_message_id(
            st.session_state.user_name,
            st.session_state.chat_partner
        )
        # Mark as read
        db.mark_messages_as_read(st.session_state.chat_partner, st.session_state.user_name)

def check_for_new_messages() -> bool:
    """Check if there are new messages since last check."""
    if st.session_state.user_name and st.session_state.chat_partner:
        current_latest_id = db.get_latest_message_id(
            st.session_state.user_name,
            st.session_state.chat_partner
        )
        return current_latest_id > st.session_state.last_message_id
    return False

def get_avatar(sender: str) -> str:
    """Return the avatar initials for a sender."""
    return sender[:2].upper() if sender else "?"

def display_messages():
    """Display all messages in the chat with avatars, full timestamps, and grouping."""
    import html
    last_sender = None
    for msg in st.session_state.messages:
        timestamp_str = msg["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        encryption_badge = "🔒 " if msg.get("is_encrypted", False) else ""
        sender = msg["sender"]
        is_self = sender == st.session_state.user_name
        # Avatar: use initials
        avatar = get_avatar(sender)
        # Escape HTML in message and sender
        message_escaped = html.escape(msg["message"])
        sender_escaped = html.escape(sender)
        avatar_escaped = html.escape(avatar)
        # Grouping: only show sender/avatar if sender changes
        show_sender = sender != last_sender
        last_sender = sender
        
        if is_self:
            # User's own messages (right aligned, blue)
            st.markdown(f"""
            <div style='display: flex; justify-content: flex-end; margin-bottom: 8px;'>
                <div style='background-color: #0084ff; color: white; padding: 10px 15px; border-radius: 20px; max-width: 70%; word-wrap: break-word;'>
                    {f"<div style='font-size: 10px; text-align: right; margin-bottom: 2px;'>{avatar_escaped}</div>" if show_sender else ""}
                    <div style='font-size: 14px;'>{encryption_badge}{message_escaped}</div>
                    <div style='font-size: 10px; opacity: 0.8; text-align: right; margin-top: 5px;'>{timestamp_str}</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            # Other user's messages (left aligned, gray)
            st.markdown(f"""
            <div style='display: flex; justify-content: flex-start; margin-bottom: 8px;'>
                <div style='background-color: #e9ecef; color: black; padding: 10px 15px; border-radius: 20px; max-width: 70%; word-wrap: break-word;'>
                    {f"<div style='font-size: 12px; font-weight: bold; color: #495057; margin-bottom: 2px;'>{avatar_escaped} {sender_escaped if show_sender else ''}</div>" if show_sender else ""}
                    <div style='font-size: 14px;'>{encryption_badge}{message_escaped}</div>
                    <div style='font-size: 10px; opacity: 0.6; margin-top: 5px;'>{timestamp_str}</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

    # Show 'Seen' for last message sent by user and read by partner
    last_seen_idx = None
    for i, msg in enumerate(st.session_state.messages):
        if msg['sender'] == st.session_state.user_name and msg.get('read'):
            last_seen_idx = i
    
    if last_seen_idx is not None:
        st.caption('✅ Seen')

def main():
    """Main entry point for the Streamlit chat app UI."""
    st.title("🔒 Secure Chat App")
    
    # Sidebar
    with st.sidebar:
        st.header("⚙️ Settings")
        
        # User name input
        user_name = st.text_input(
            "Your Username", 
            value=st.session_state.user_name,
            placeholder="Enter your username"
        )
        
        if user_name != st.session_state.user_name:
            st.session_state.user_name = user_name
            st.session_state.last_message_id = 0
            if st.session_state.chat_partner:
                load_conversation()
        
        # Chat partner selection
        chat_partner = st.text_input(
            "Chat With", 
            value=st.session_state.chat_partner,
            placeholder="Enter partner's username"
        )
        
        if chat_partner != st.session_state.chat_partner:
            st.session_state.chat_partner = chat_partner
            st.session_state.last_message_id = 0
            if st.session_state.user_name and chat_partner:
                load_conversation()
        
        st.markdown("---")
        
        # Encryption settings
        st.subheader("🔐 Encryption")
        
        password = st.text_input(
            "Password (optional)",
            type="password",
            value=st.session_state.encryption_password,
            placeholder="Enter password for encryption",
            help="Both users must use the same password to encrypt/decrypt"
        )
        
        # Check if password changed
        password_changed = password != st.session_state.encryption_password
        
        if password_changed:
            st.session_state.encryption_password = password
            # Reload conversation with new password
            if st.session_state.user_name and st.session_state.chat_partner:
                load_conversation()
                if password:
                    st.success("🔒 Encryption enabled! Messages will be encrypted.")
                else:
                    st.info("🔓 Encryption disabled. Messages will be plain text.")
                st.rerun()
        
        if password:
            st.success("✅ Encryption: ON")
            st.caption("Messages will be encrypted with this password")
        else:
            st.info("🔓 Encryption: OFF")
            st.caption("Messages will be sent as plain text")
        
        st.markdown("---")
        
        # Conversation stats
        if st.session_state.user_name and st.session_state.chat_partner:
            st.subheader("💬 Chat Info")
            msg_count = db.get_message_count(
                st.session_state.user_name,
                st.session_state.chat_partner
            )
            st.metric("Total Messages", msg_count)
            
            encrypted_count = sum(1 for msg in st.session_state.messages if msg.get('is_encrypted'))
            if encrypted_count > 0:
                st.metric("Encrypted", encrypted_count)
        
        # Your conversations
        if st.session_state.user_name:
            st.markdown("---")
            st.subheader("📱 Your Chats")
            conversations = db.get_user_conversations(st.session_state.user_name)
            if conversations:
                for user in conversations:
                    if st.button(f"💬 {user}", key=f"conv_{user}", use_container_width=True):
                        st.session_state.chat_partner = user
                        st.session_state.last_message_id = 0
                        load_conversation()
                        st.rerun()
            else:
                st.info("No conversations yet")
        
        st.markdown("---")
        
        # Actions
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("🔄 Refresh", use_container_width=True):
                load_conversation()
                st.rerun()
        
        with col2:
            if st.button("🗑️ Clear", use_container_width=True):
                if st.session_state.user_name and st.session_state.chat_partner:
                    if db.clear_conversation(st.session_state.user_name, st.session_state.chat_partner):
                        st.session_state.messages = []
                        st.session_state.last_message_id = 0
                        st.success("Cleared!")
                        st.rerun()
        
        # Test encryption
        if password:
            st.markdown("---")
            st.subheader("🧪 Test Encryption")
            test_msg = "Hello World"
            key = get_encryption_key()
            if key is not None:
                encrypted = EncryptionHandler.encrypt_message(test_msg, key)
                decrypted = EncryptionHandler.decrypt_message(encrypted, key)
                st.caption(f"Original: {test_msg}")
                st.caption(f"Encrypted: {encrypted[:20]}...")
                st.caption(f"Decrypted: {decrypted}")
    
    # Main chat area
    if not st.session_state.user_name:
        st.info("👈 Please enter your username in the sidebar to start")
        st.markdown("""
        ### How to use:
        1. Enter your username
        2. Enter your chat partner's username
        3. (Optional) Enter a password for encryption
        4. Start chatting!
        
        **Note:** Both users must use the same password to read encrypted messages.
        """)
        return
    
    if not st.session_state.chat_partner:
        st.info("👈 Enter your chat partner's username in the sidebar")
        return
    
    # Chat header
    encryption_status = "🔒 ENCRYPTED" if st.session_state.encryption_password else "🔓 PLAIN TEXT"
    st.subheader(f"Chat with **{st.session_state.chat_partner}** • {encryption_status}")
    
    # Auto-refresh every 2 seconds - THIS IS THE KEY FOR REAL-TIME
    refresh_count = st_autorefresh(interval=2000, limit=None, key="chatrefresh")
    
    # Check for new messages and reload if needed
    if check_for_new_messages():
        load_conversation()
    
    # Load messages on first render
    if not st.session_state.messages and st.session_state.user_name and st.session_state.chat_partner:
        load_conversation()
    
    # Chat container with scrollable messages
    chat_container = st.container()
    with chat_container:
        if st.session_state.messages:
            display_messages()
        else:
            st.info("💬 No messages yet. Start the conversation!")
    
    # Message input area
    st.markdown("---")
    
    with st.form(key="message_form", clear_on_submit=True):
        col1, col2 = st.columns([5, 1])
        
        with col1:
            new_message = st.text_input(
                "Message",
                placeholder="Type your message here...",
                label_visibility="collapsed",
                key="message_input"
            )
        
        with col2:
            send_clicked = st.form_submit_button("Send 📤", use_container_width=True, type="primary")
        
        # Handle sending message
        if send_clicked and new_message and new_message.strip():
            encryption_key = get_encryption_key()
            
            success = db.add_message(
                st.session_state.user_name,
                st.session_state.chat_partner,
                new_message.strip(),
                encryption_key
            )
            
            if success:
                load_conversation()
                st.rerun()
            else:
                st.error("Failed to send message")

if __name__ == "__main__":
    main()