import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration"""
    SECRET_KEY = os.getenv('SECRET_KEY', 'forensiq-dev-secret-key-change-in-production')

    # MongoDB Configuration
    MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
    MONGO_DB = 'FSUITE'

    # Session Configuration
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # Flask-WTF Configuration
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None

    # File Upload Configuration
    MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500MB max upload
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'evidence')
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx',
                          'xls', 'xlsx', 'zip', 'rar', '7z', 'eml', 'msg', 'log',
                          'pcap', 'pcapng', 'csv', 'json', 'xml'}

    # Encryption Configuration
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY").encode()

    # MFA Configuration
    MFA_ENABLED = True
    MFA_CODE_EXPIRY = 600  # 10 minutes

    # Email Configuration (Mock for development)
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'localhost')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'true').lower() == 'true'
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@forensiq.local')

    # Anomaly Detection Configuration
    ANOMALY_DETECTION_ENABLED = True
    ANOMALY_CHECK_INTERVAL = 300  # 5 minutes
    ANOMALY_THRESHOLD = 0.7  # Anomaly score threshold

    # OSINT Configuration
    OSINT_CACHE_ENABLED = True
    OSINT_CACHE_TTL = 3600  # 1 hour

    # Logging Configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

    # Role Permissions
    ROLE_PERMISSIONS = {
        'admin': [
            'view_all', 'manage_users', 'assign_roles', 'configure_system',
            'view_logs', 'view_anomalies', 'manage_cases', 'view_evidence',
            'manage_mfa'
        ],
        'case_manager': [
            'create_case', 'assign_case', 'approve_reports', 'manage_case_lifecycle',
            'export_case', 'view_evidence', 'view_logs'
        ],
        'investigator': [
            'create_case', 'upload_evidence', 'analyze_evidence', 'osint_basic',
            'add_notes', 'view_case', 'extract_metadata'
        ],
        'osint_analyst': [
            'osint_advanced', 'domain_recon', 'email_recon', 'network_recon',
            'file_intel', 'view_case', 'add_notes', 'generate_reports'
        ],
        'legal_reviewer': [
            'view_finalized_evidence', 'view_chain_custody', 'view_timeline',
            'view_reports', 'approve_legal', 'download_bundles'
        ]
    }


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True


class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    WTF_CSRF_ENABLED = False


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}