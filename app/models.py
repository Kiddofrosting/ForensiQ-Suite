from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId
import hashlib
import json


class User:
    """User model for MongoDB"""

    def __init__(self, username, email, password, role='investigator', full_name='',
                 mfa_enabled=False, status='active', created_by=None):
        self.username = username
        self.email = email
        self.password_hash = generate_password_hash(password)
        self.role = role
        self.full_name = full_name
        self.mfa_enabled = mfa_enabled
        self.mfa_secret = None
        self.status = status
        self.created_at = datetime.utcnow()
        self.created_by = created_by
        self.last_login = None
        self.failed_login_attempts = 0
        self.locked_until = None

    def to_dict(self):
        return {
            'username': self.username,
            'email': self.email,
            'password_hash': self.password_hash,
            'role': self.role,
            'full_name': self.full_name,
            'mfa_enabled': self.mfa_enabled,
            'mfa_secret': self.mfa_secret,
            'status': self.status,
            'created_at': self.created_at,
            'created_by': self.created_by,
            'last_login': self.last_login,
            'failed_login_attempts': self.failed_login_attempts,
            'locked_until': self.locked_until
        }

    @staticmethod
    def verify_password(password_hash, password):
        return check_password_hash(password_hash, password)


class Case:
    """Case model for MongoDB"""

    def __init__(self, case_number, title, description, created_by, assigned_to=None,
                 priority='medium', case_type='cybercrime'):
        self.case_number = case_number
        self.title = title
        self.description = description
        self.created_by = created_by
        self.assigned_to = assigned_to or []
        self.priority = priority  # low, medium, high, critical
        self.case_type = case_type
        self.status = 'open'  # open, in_progress, closed, archived
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        self.closed_at = None
        self.tags = []
        self.evidence_ids = []
        self.osint_query_ids = []
        self.notes = []

    def to_dict(self):
        return {
            'case_number': self.case_number,
            'title': self.title,
            'description': self.description,
            'created_by': self.created_by,
            'assigned_to': self.assigned_to,
            'priority': self.priority,
            'case_type': self.case_type,
            'status': self.status,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'closed_at': self.closed_at,
            'tags': self.tags,
            'evidence_ids': self.evidence_ids,
            'osint_query_ids': self.osint_query_ids,
            'notes': self.notes
        }


class Evidence:
    """Evidence model for MongoDB"""

    def __init__(self, case_id, file_name, file_path, file_size, file_type,
                 uploaded_by, description=''):
        self.case_id = case_id
        self.file_name = file_name
        self.file_path = file_path
        self.encrypted_path = None
        self.file_size = file_size
        self.file_type = file_type
        self.uploaded_by = uploaded_by
        self.description = description
        self.uploaded_at = datetime.utcnow()
        self.sha256_hash = None
        self.md5_hash = None
        self.sha1_hash = None
        self.metadata = {}
        self.chain_of_custody = []
        self.tags = []
        self.status = 'active'  # active, archived, deleted
        self.retention_until = None
        self.verified_by = None
        self.verified_at = None

    def to_dict(self):
        return {
            'case_id': self.case_id,
            'file_name': self.file_name,
            'file_path': self.file_path,
            'encrypted_path': self.encrypted_path,
            'file_size': self.file_size,
            'file_type': self.file_type,
            'uploaded_by': self.uploaded_by,
            'description': self.description,
            'uploaded_at': self.uploaded_at,
            'sha256_hash': self.sha256_hash,
            'md5_hash': self.md5_hash,
            'sha1_hash': self.sha1_hash,
            'metadata': self.metadata,
            'chain_of_custody': self.chain_of_custody,
            'tags': self.tags,
            'status': self.status,
            'retention_until': self.retention_until,
            'verified_by': self.verified_by,
            'verified_at': self.verified_at
        }


class AuditLog:
    """Tamper-evident audit log model with blockchain-style hash chain"""

    def __init__(self, user_id, username, role, action, ip_address,
                 metadata=None, previous_hash=None):
        self.user_id = user_id
        self.username = username
        self.role = role
        self.action = action
        self.timestamp = datetime.utcnow()
        self.ip_address = ip_address
        self.metadata = metadata or {}
        self.previous_hash = previous_hash or '0' * 64
        self.current_hash = self._compute_hash()

    def _compute_hash(self):
        """Compute SHA-256 hash of log entry"""
        log_data = {
            'user_id': self.user_id,
            'username': self.username,
            'role': self.role,
            'action': self.action,
            'timestamp': self.timestamp.isoformat(),
            'ip_address': self.ip_address,
            'metadata': self.metadata,
            'previous_hash': self.previous_hash
        }
        log_string = json.dumps(log_data, sort_keys=True)
        return hashlib.sha256(log_string.encode()).hexdigest()

    def to_dict(self):
        return {
            'user_id': self.user_id,
            'username': self.username,
            'role': self.role,
            'action': self.action,
            'timestamp': self.timestamp,
            'ip_address': self.ip_address,
            'metadata': self.metadata,
            'previous_hash': self.previous_hash,
            'current_hash': self.current_hash
        }

    @staticmethod
    def verify_chain(logs):
        """Verify integrity of audit log chain"""
        if not logs or len(logs) == 0:
            return True, "No logs to verify"

        if len(logs) == 1:
            # Single log - verify it has genesis hash
            if logs[0].get('previous_hash') == '0' * 64:
                return True, "Single log with valid genesis hash"
            else:
                return False, "Single log does not have genesis hash"

        # Verify each log's hash matches the next log's previous_hash
        for i in range(len(logs) - 1):
            current_log = logs[i]
            next_log = logs[i + 1]

            # Get hashes safely
            current_hash = current_log.get('current_hash')
            next_previous_hash = next_log.get('previous_hash')

            if not current_hash or not next_previous_hash:
                return False, f"Missing hash at log {i}"

            if current_hash != next_previous_hash:
                return False, f"Chain broken at log {i + 1}"

        return True, "Chain intact"


class OSINTQuery:
    """OSINT query model for MongoDB"""

    def __init__(self, case_id, query_type, query_term, performed_by):
        self.case_id = case_id
        self.query_type = query_type  # whois, dns, ip, email, url, file, username
        self.query_term = query_term
        self.performed_by = performed_by
        self.performed_at = datetime.utcnow()
        self.results = {}
        self.status = 'pending'  # pending, completed, failed
        self.error_message = None
        self.cached = False

    def to_dict(self):
        return {
            'case_id': self.case_id,
            'query_type': self.query_type,
            'query_term': self.query_term,
            'performed_by': self.performed_by,
            'performed_at': self.performed_at,
            'results': self.results,
            'status': self.status,
            'error_message': self.error_message,
            'cached': self.cached
        }


class AnomalyAlert:
    """Anomaly detection alert model"""

    def __init__(self, user_id, username, anomaly_type, anomaly_score,
                 details, detected_at=None):
        self.user_id = user_id
        self.username = username
        self.anomaly_type = anomaly_type
        self.anomaly_score = anomaly_score
        self.details = details
        self.detected_at = detected_at or datetime.utcnow()
        self.status = 'open'  # open, investigating, resolved, false_positive
        self.investigated_by = None
        self.investigated_at = None
        self.resolution_notes = None
        self.audit_log_ids = []

    def to_dict(self):
        return {
            'user_id': self.user_id,
            'username': self.username,
            'anomaly_type': self.anomaly_type,
            'anomaly_score': self.anomaly_score,
            'details': self.details,
            'detected_at': self.detected_at,
            'status': self.status,
            'investigated_by': self.investigated_by,
            'investigated_at': self.investigated_at,
            'resolution_notes': self.resolution_notes,
            'audit_log_ids': self.audit_log_ids
        }


class MFASession:
    """MFA session model for temporary OTP storage"""

    def __init__(self, user_id, code, expires_at):
        self.user_id = user_id
        self.code = code
        self.created_at = datetime.utcnow()
        self.expires_at = expires_at
        self.attempts = 0
        self.verified = False

    def to_dict(self):
        return {
            'user_id': self.user_id,
            'code': self.code,
            'created_at': self.created_at,
            'expires_at': self.expires_at,
            'attempts': self.attempts,
            'verified': self.verified
        }