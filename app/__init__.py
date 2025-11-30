from flask import Flask
from pymongo import MongoClient
from app.config import config
import os

# Global MongoDB client
mongo_client = None
db = None


def create_app(config_name='default'):
    """Application factory"""
    app = Flask(__name__)

    # Load configuration
    app.config.from_object(config[config_name])

    # Initialize MongoDB
    global mongo_client, db
    mongo_client = MongoClient(app.config['MONGO_URI'])
    db = mongo_client[app.config['MONGO_DB']]

    # Create indexes for better performance
    create_indexes(db)

    # Create upload directory
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Register blueprints
    from app.auth.routes import auth_bp
    from app.cases.routes import cases_bp
    from app.evidence.routes import evidence_bp
    from app.osint.routes import osint_bp
    from app.logs.routes import logs_bp
    from app.ml.routes import ml_bp
    from app.admin.routes import admin_bp

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(cases_bp, url_prefix='/cases')
    app.register_blueprint(evidence_bp, url_prefix='/evidence')
    app.register_blueprint(osint_bp, url_prefix='/osint')
    app.register_blueprint(logs_bp, url_prefix='/logs')
    app.register_blueprint(ml_bp, url_prefix='/ml')
    app.register_blueprint(admin_bp, url_prefix='/admin')

    # Register main routes
    from app.main import routes
    app.register_blueprint(routes.main_bp)

    # Initialize default admin user if not exists
    initialize_default_users(db)

    return app


def create_indexes(db):
    """Create MongoDB indexes for performance"""
    # User indexes
    db.users.create_index('username', unique=True)
    db.users.create_index('email', unique=True)
    db.users.create_index('role')

    # Case indexes
    db.cases.create_index('case_number', unique=True)
    db.cases.create_index('created_by')
    db.cases.create_index('status')
    db.cases.create_index('created_at')

    # Evidence indexes
    db.evidence.create_index('case_id')
    db.evidence.create_index('sha256_hash')
    db.evidence.create_index('uploaded_by')
    db.evidence.create_index('uploaded_at')

    # Audit log indexes
    db.audit_logs.create_index('user_id')
    db.audit_logs.create_index('timestamp')
    db.audit_logs.create_index('action')

    # OSINT query indexes
    db.osint_queries.create_index('case_id')
    db.osint_queries.create_index('query_type')
    db.osint_queries.create_index('performed_at')

    # Anomaly alert indexes
    db.anomaly_alerts.create_index('user_id')
    db.anomaly_alerts.create_index('detected_at')
    db.anomaly_alerts.create_index('status')

    # MFA session indexes with TTL
    db.mfa_sessions.create_index('expires_at', expireAfterSeconds=0)
    db.mfa_sessions.create_index('user_id')


def initialize_default_users(db):
    """Initialize default admin user"""
    from app.models import User

    # Check if admin exists
    if db.users.find_one({'username': 'admin'}):
        return

    # Create default admin
    admin = User(
        username='admin',
        email='admin@forensiq.local',
        password='Admin@123',
        role='admin',
        full_name='System Administrator',
        mfa_enabled=False,
        status='active'
    )

    db.users.insert_one(admin.to_dict())

    # Create sample users for each role
    sample_users = [
        {
            'username': 'case_manager',
            'email': 'manager@forensiq.local',
            'password': 'Manager@123',
            'role': 'case_manager',
            'full_name': 'John Manager'
        },
        {
            'username': 'investigator',
            'email': 'investigator@forensiq.local',
            'password': 'Investigator@123',
            'role': 'investigator',
            'full_name': 'Jane Investigator'
        },
        {
            'username': 'osint_analyst',
            'email': 'osint@forensiq.local',
            'password': 'Osint@123',
            'role': 'osint_analyst',
            'full_name': 'Bob Analyst'
        },
        {
            'username': 'legal_reviewer',
            'email': 'legal@forensiq.local',
            'password': 'Legal@123',
            'role': 'legal_reviewer',
            'full_name': 'Alice Reviewer'
        }
    ]

    for user_data in sample_users:
        user = User(**user_data)
        db.users.insert_one(user.to_dict())


def get_db():
    """Get database instance"""
    return db