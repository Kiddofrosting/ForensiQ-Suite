import os
import hashlib
import random
import string
from datetime import datetime, timedelta
from functools import wraps
from flask import session, redirect, url_for, flash, request
from cryptography.fernet import Fernet
from app.config import Config


def get_encryption_key():
    """
    Get or create encryption key
    Returns bytes, not string
    """
    key = Config.ENCRYPTION_KEY

    if not key:
        # Generate new key if not exists
        key = Fernet.generate_key()
        print(f"⚠️  Warning: Generated temporary encryption key. Add to .env:")
        print(f"ENCRYPTION_KEY={key.decode()}")

    # Ensure key is bytes
    if isinstance(key, str):
        key = key.encode()

    return key


def encrypt_file(file_path, key=None):
    """
    Encrypt a file using Fernet symmetric encryption

    Args:
        file_path: Path to file to encrypt
        key: Optional encryption key (will use default if not provided)

    Returns:
        Path to encrypted file
    """
    if key is None:
        key = get_encryption_key()

    if isinstance(key, str):
        key = key.encode()

    try:
        f = Fernet(key)

        # Read original file
        with open(file_path, 'rb') as file:
            file_data = file.read()

        # Encrypt
        encrypted_data = f.encrypt(file_data)

        # Save encrypted file
        encrypted_path = file_path + '.encrypted'
        with open(encrypted_path, 'wb') as file:
            file.write(encrypted_data)

        return encrypted_path

    except Exception as e:
        print(f"❌ Encryption error: {e}")
        raise Exception(f"Failed to encrypt file: {str(e)}")


def decrypt_file(encrypted_path, key=None, output_path=None):
    """
    Decrypt a file using Fernet symmetric encryption

    Args:
        encrypted_path: Path to encrypted file
        key: Optional encryption key (will use default if not provided)
        output_path: Optional output path for decrypted file

    Returns:
        Decrypted data (bytes) or output path if specified
    """
    if key is None:
        key = get_encryption_key()

    if isinstance(key, str):
        key = key.encode()

    try:
        f = Fernet(key)

        # Read encrypted file
        with open(encrypted_path, 'rb') as file:
            encrypted_data = file.read()

        # Decrypt
        decrypted_data = f.decrypt(encrypted_data)

        # Save to file if output path provided
        if output_path:
            with open(output_path, 'wb') as file:
                file.write(decrypted_data)
            return output_path

        return decrypted_data

    except Exception as e:
        print(f"❌ Decryption error: {e}")
        raise Exception(f"Failed to decrypt file: {str(e)}")


def test_encryption():
    """Test encryption/decryption functionality"""
    import tempfile

    try:
        # Create test file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            test_file = f.name
            f.write("Test encryption content")

        print("🔐 Testing encryption...")

        # Test encryption
        encrypted = encrypt_file(test_file)
        print(f"✓ Encrypted: {encrypted}")

        # Test decryption
        decrypted = decrypt_file(encrypted)
        print(f"✓ Decrypted: {decrypted.decode()}")

        # Cleanup
        os.remove(test_file)
        os.remove(encrypted)

        print("✅ Encryption test passed!")
        return True

    except Exception as e:
        print(f"❌ Encryption test failed: {e}")
        return False

def compute_file_hash(file_path, algorithm='sha256'):
    """Compute hash of a file"""
    hash_func = getattr(hashlib, algorithm)()

    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_func.update(chunk)

    return hash_func.hexdigest()


def compute_hashes(file_path):
    """Compute multiple hashes for a file"""
    return {
        'sha256': compute_file_hash(file_path, 'sha256'),
        'md5': compute_file_hash(file_path, 'md5'),
        'sha1': compute_file_hash(file_path, 'sha1')
    }


def generate_case_number():
    """Generate unique case number"""
    timestamp = datetime.utcnow().strftime('%Y%m%d')
    random_part = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    return f"CASE-{timestamp}-{random_part}"


def generate_otp(length=6):
    """Generate random OTP code"""
    return ''.join(random.choices(string.digits, k=length))


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS


def format_file_size(size_bytes):
    """Format file size in human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


def get_client_ip():
    """Get client IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr


def login_required(f):
    """Decorator to require login"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)

    return decorated_function


def role_required(*roles):
    """Decorator to require specific role(s)"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('auth.login'))

            if session.get('role') not in roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('main.dashboard'))

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def has_permission(role, permission):
    """Check if a role has a specific permission"""
    permissions = Config.ROLE_PERMISSIONS.get(role, [])
    return permission in permissions


def mfa_required(f):
    """Decorator to require MFA verification"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login'))

        if session.get('mfa_verified') != True:
            flash('Please complete MFA verification.', 'warning')
            return redirect(url_for('auth.verify_mfa'))

        return f(*args, **kwargs)

    return decorated_function


def safe_filename(filename):
    """Create safe filename"""
    keepcharacters = (' ', '.', '_', '-')
    return "".join(c for c in filename if c.isalnum() or c in keepcharacters).rstrip()


def create_directory_structure(case_id):
    """Create directory structure for case evidence"""
    base_path = os.path.join(Config.UPLOAD_FOLDER, str(case_id))
    os.makedirs(base_path, exist_ok=True)

    subdirs = ['raw', 'encrypted', 'extracted', 'reports']
    for subdir in subdirs:
        os.makedirs(os.path.join(base_path, subdir), exist_ok=True)

    return base_path


def validate_password_strength(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)

    if not (has_upper and has_lower and has_digit and has_special):
        return False, "Password must contain uppercase, lowercase, digit, and special character"

    return True, "Password is strong"


def format_datetime(dt):
    """Format datetime for display"""
    if not dt:
        return 'N/A'
    if isinstance(dt, str):
        return dt
    return dt.strftime('%Y-%m-%d %H:%M:%S UTC')


def time_ago(dt):
    """Convert datetime to relative time"""
    if not dt:
        return 'N/A'

    if isinstance(dt, str):
        dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))

    now = datetime.utcnow()
    diff = now - dt

    seconds = diff.total_seconds()

    if seconds < 60:
        return f"{int(seconds)} seconds ago"
    elif seconds < 3600:
        return f"{int(seconds / 60)} minutes ago"
    elif seconds < 86400:
        return f"{int(seconds / 3600)} hours ago"
    elif seconds < 604800:
        return f"{int(seconds / 86400)} days ago"
    else:
        return dt.strftime('%Y-%m-%d')


def sanitize_input(text):
    """Sanitize user input to prevent XSS"""
    if not text:
        return ''

    dangerous_chars = ['<', '>', '"', "'", '&']
    safe_chars = ['&lt;', '&gt;', '&quot;', '&#x27;', '&amp;']

    for i, char in enumerate(dangerous_chars):
        text = text.replace(char, safe_chars[i])

    return text


def generate_report_filename(case_number, report_type):
    """Generate report filename"""
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    return f"{case_number}_{report_type}_{timestamp}.pdf"


def get_last_audit_log_hash():
    """Get the hash of the most recent audit log"""
    from app import get_db

    db = get_db()
    last_log = db.audit_logs.find_one(sort=[('timestamp', -1)])

    if last_log:
        return last_log.get('current_hash', '0' * 64)
    return '0' * 64