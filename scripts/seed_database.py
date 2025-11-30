"""
Database seeding script for ForensIQ Suite
Creates initial users, sample cases, and test data
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pymongo import MongoClient
from datetime import datetime, timedelta
from app.models import User, Case, AuditLog
from app.config import Config
import random


def seed_database():
    """Seed the database with initial data"""

    # Connect to MongoDB
    client = MongoClient(Config.MONGO_URI)
    db = client[Config.MONGO_DB]

    print("🌱 Starting database seeding...")

    # Clear existing data (optional - comment out in production)
    print("⚠️  Clearing existing data...")
    db.users.delete_many({})
    db.cases.delete_many({})
    db.evidence.delete_many({})
    db.audit_logs.delete_many({})
    db.osint_queries.delete_many({})
    db.anomaly_alerts.delete_many({})
    db.mfa_sessions.delete_many({})

    # Create users
    print("👥 Creating users...")

    users = [
        {
            'username': 'admin',
            'email': 'admin@forensiq.local',
            'password': 'Admin@123',
            'role': 'admin',
            'full_name': 'System Administrator',
            'mfa_enabled': False
        },
        {
            'username': 'case_manager',
            'email': 'manager@forensiq.local',
            'password': 'Manager@123',
            'role': 'case_manager',
            'full_name': 'John Manager',
            'mfa_enabled': True
        },
        {
            'username': 'investigator1',
            'email': 'investigator1@forensiq.local',
            'password': 'Investigator@123',
            'role': 'investigator',
            'full_name': 'Jane Investigator',
            'mfa_enabled': False
        },
        {
            'username': 'investigator2',
            'email': 'investigator2@forensiq.local',
            'password': 'Investigator@123',
            'role': 'investigator',
            'full_name': 'Mike Detective',
            'mfa_enabled': False
        },
        {
            'username': 'osint_analyst',
            'email': 'osint@forensiq.local',
            'password': 'Osint@123',
            'role': 'osint_analyst',
            'full_name': 'Bob Analyst',
            'mfa_enabled': True
        },
        {
            'username': 'legal_reviewer',
            'email': 'legal@forensiq.local',
            'password': 'Legal@123',
            'role': 'legal_reviewer',
            'full_name': 'Alice Reviewer',
            'mfa_enabled': False
        }
    ]

    user_ids = {}

    for user_data in users:
        user = User(**user_data)
        result = db.users.insert_one(user.to_dict())
        user_ids[user_data['username']] = str(result.inserted_id)
        print(f"  ✓ Created user: {user_data['username']} ({user_data['role']})")

    # Create sample cases
    print("📁 Creating sample cases...")

    cases_data = [
        {
            'title': 'Corporate Data Breach Investigation',
            'description': 'Investigation into unauthorized access to company database containing customer PII',
            'priority': 'critical',
            'case_type': 'cybercrime',
            'created_by': user_ids['investigator1'],
            'assigned_to': [user_ids['investigator1'], user_ids['osint_analyst']]
        },
        {
            'title': 'Phishing Campaign Analysis',
            'description': 'Analysis of coordinated phishing emails targeting financial institutions',
            'priority': 'high',
            'case_type': 'fraud',
            'created_by': user_ids['case_manager'],
            'assigned_to': [user_ids['investigator2'], user_ids['osint_analyst']]
        },
        {
            'title': 'Ransomware Incident Response',
            'description': 'Response to ransomware attack on healthcare facility systems',
            'priority': 'critical',
            'case_type': 'cybercrime',
            'created_by': user_ids['investigator2'],
            'assigned_to': [user_ids['investigator2']]
        },
        {
            'title': 'Insider Threat Investigation',
            'description': 'Investigation of potential data exfiltration by former employee',
            'priority': 'high',
            'case_type': 'internal',
            'created_by': user_ids['case_manager'],
            'assigned_to': [user_ids['investigator1']]
        },
        {
            'title': 'Social Media Fraud Case',
            'description': 'Investigation of fraudulent social media accounts impersonating executives',
            'priority': 'medium',
            'case_type': 'fraud',
            'created_by': user_ids['investigator1'],
            'assigned_to': [user_ids['osint_analyst']]
        }
    ]

    case_ids = []

    for case_data in cases_data:
        from app.utils import generate_case_number
        case_number = generate_case_number()

        case = Case(
            case_number=case_number,
            title=case_data['title'],
            description=case_data['description'],
            created_by=case_data['created_by'],
            assigned_to=case_data['assigned_to'],
            priority=case_data['priority'],
            case_type=case_data['case_type']
        )

        # Randomly set some cases to in_progress or closed
        if random.random() > 0.6:
            case.status = 'in_progress'
        elif random.random() > 0.8:
            case.status = 'closed'
            case.closed_at = datetime.utcnow() - timedelta(days=random.randint(1, 30))

        case.tags = ['investigation', case_data['case_type']]

        result = db.cases.insert_one(case.to_dict())
        case_ids.append(str(result.inserted_id))
        print(f"  ✓ Created case: {case_number} - {case_data['title']}")

    # Create sample audit logs
    print("📝 Creating sample audit logs...")

    actions = [
        'login', 'logout', 'case_created', 'evidence_uploaded',
        'evidence_viewed', 'osint_query_performed', 'case_updated'
    ]

    previous_hash = '0' * 64

    for i in range(50):
        user_key = random.choice(list(user_ids.keys()))
        user_id = user_ids[user_key]
        user = db.users.find_one({'_id': ObjectId(user_id)})

        timestamp = datetime.utcnow() - timedelta(
            days=random.randint(0, 30),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )

        log_entry = AuditLog(
            user_id=user_id,
            username=user_key,
            role=user['role'],
            action=random.choice(actions),
            ip_address=f"192.168.1.{random.randint(1, 255)}",
            metadata={'sample': True},
            previous_hash=previous_hash
        )

        log_dict = log_entry.to_dict()
        log_dict['timestamp'] = timestamp

        db.audit_logs.insert_one(log_dict)
        previous_hash = log_entry.current_hash

    print(f"  ✓ Created 50 audit log entries")

    # Create indexes
    print("🔍 Creating database indexes...")
    from app import create_indexes
    create_indexes(db)
    print("  ✓ Indexes created")

    print("\n✅ Database seeding completed successfully!")
    print("\n📋 Default credentials:")
    print("=" * 50)
    for user_data in users:
        print(f"Username: {user_data['username']:20} Password: {user_data['password']}")
    print("=" * 50)
    print("\n⚠️  Remember to change default passwords in production!")

    client.close()


if __name__ == '__main__':
    from bson import ObjectId

    seed_database()