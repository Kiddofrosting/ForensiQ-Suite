"""
Setup script for ForensIQ Suite
Automated installation and configuration
"""

import os
import sys
import subprocess
from pathlib import Path


def print_header(text):
    """Print formatted header"""
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70 + "\n")


def run_command(command, description):
    """Run shell command with error handling"""
    print(f"▶️  {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error: {e.stderr}")
        return False


def create_directories():
    """Create required directory structure"""
    print_header("Creating Directory Structure")

    directories = [
        'data/evidence',
        'backups',
        'logs',
        'app/templates/auth',
        'app/templates/cases',
        'app/templates/evidence',
        'app/templates/osint',
        'app/templates/ml',
        'app/templates/logs',
        'app/templates/admin',
        'app/static/css',
        'app/static/js',
        'app/static/img'
    ]

    for directory in directories:
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)
        print(f"✓ Created: {directory}")

    print("\n✅ Directory structure created successfully!")


def check_python_version():
    """Check Python version"""
    print_header("Checking Python Version")

    version = sys.version_info
    print(f"Python version: {version.major}.{version.minor}.{version.micro}")

    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("❌ Python 3.8 or higher is required!")
        return False

    print("✅ Python version is compatible")
    return True


def check_mongodb():
    """Check if MongoDB is running"""
    print_header("Checking MongoDB Connection")

    try:
        from pymongo import MongoClient
        client = MongoClient('mongodb://localhost:27017/', serverSelectionTimeoutMS=3000)
        client.server_info()
        print("✅ MongoDB is running and accessible")
        client.close()
        return True
    except Exception as e:
        print(f"❌ MongoDB connection failed: {e}")
        print("Please ensure MongoDB is installed and running:")
        print("  - Install: https://www.mongodb.com/try/download/community")
        print("  - Start: mongod --dbpath /path/to/data/db")
        return False


def install_dependencies():
    """Install Python dependencies"""
    print_header("Installing Python Dependencies")

    if not os.path.exists('requirements.txt'):
        print("❌ requirements.txt not found!")
        return False

    return run_command(
        f"{sys.executable} -m pip install -r requirements.txt",
        "Installing dependencies"
    )


def generate_env_file():
    """Generate .env file if not exists"""
    print_header("Configuring Environment")

    if os.path.exists('.env'):
        print("⚠️  .env file already exists, skipping generation")
        return True

    print("Generating new .env file...")

    import secrets
    from cryptography.fernet import Fernet

    secret_key = secrets.token_urlsafe(32)
    encryption_key = Fernet.generate_key().decode()

    env_content = f"""# Flask Configuration
SECRET_KEY={secret_key}
FLASK_ENV=development

# MongoDB Configuration
MONGO_URI=mongodb://localhost:27017/
MONGO_DB=FSUITE

# Encryption Configuration
ENCRYPTION_KEY={encryption_key}

# Email Configuration (Mock for development)
MAIL_SERVER=localhost
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=your-email@example.com
MAIL_PASSWORD=your-email-password
MAIL_DEFAULT_SENDER=noreply@forensiq.local

# Logging
LOG_LEVEL=INFO
"""

    with open('.env', 'w') as f:
        f.write(env_content)

    print("✅ .env file created successfully!")
    print("\n⚠️  Important: Keep your .env file secure and never commit it to version control!")

    return True


def seed_database():
    """Seed database with initial data"""
    print_header("Seeding Database")

    confirm = input("Do you want to seed the database with sample data? (y/n): ")

    if confirm.lower() != 'y':
        print("⏭️  Skipping database seeding")
        return True

    return run_command(
        f"{sys.executable} scripts/seed_database.py",
        "Seeding database"
    )


def create_gitignore():
    """Create .gitignore file"""
    print_header("Creating .gitignore")

    gitignore_content = """# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
venv/
env/
ENV/

# Flask
instance/
.webassets-cache

# Environment
.env
.env.local

# Database backups
backups/

# Evidence files
data/evidence/*
!data/evidence/.gitkeep

# Logs
logs/
*.log

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Encryption keys
*.key
*.pem
"""

    with open('.gitignore', 'w') as f:
        f.write(gitignore_content)

    # Create .gitkeep files
    Path('data/evidence/.gitkeep').touch()
    Path('logs/.gitkeep').touch()

    print("✅ .gitignore created")
    return True


def run_tests():
    """Run basic system tests"""
    print_header("Running System Tests")

    print("Testing imports...")
    try:
        import flask
        import pymongo
        import cryptography
        import pyod
        import whois
        print("✅ All required packages imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False


def print_summary():
    """Print setup summary"""
    print_header("Setup Complete!")

    summary = """
🎉 ForensIQ Suite has been set up successfully!

📋 Next Steps:

1. Start MongoDB (if not already running):
   mongod --dbpath /path/to/data/db

2. Run the application:
   python run.py

3. Access the application:
   Open your browser to: http://localhost:5000

4. Login with default credentials:
   Username: admin
   Password: Admin@123

⚠️  IMPORTANT SECURITY NOTES:
- Change all default passwords immediately after first login
- Keep your .env file secure and never commit it
- Review security settings in app/config.py
- Backup your encryption key - encrypted data cannot be recovered without it!

📚 Documentation:
- README.md - Full documentation
- app/config.py - Configuration options
- scripts/ - Utility scripts

💡 Useful Commands:
- python scripts/backup_database.py - Backup database
- python scripts/seed_database.py - Re-seed database
- python scripts/generate_keys.py - Generate new keys

For issues or questions, refer to the documentation or contact support.
"""

    print(summary)


def main():
    """Main setup function"""
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║                     ForensIQ Suite Setup                          ║
║            Digital Evidence Management System                     ║
║                                                                   ║
║                     Kabarak University                            ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
    """)

    # Run setup steps
    steps = [
        ("Checking Python version", check_python_version),
        ("Creating directories", create_directories),
        ("Checking MongoDB", check_mongodb),
        ("Installing dependencies", install_dependencies),
        ("Generating environment file", generate_env_file),
        ("Creating .gitignore", create_gitignore),
        ("Running tests", run_tests),
        ("Seeding database", seed_database)
    ]

    failed_steps = []

    for step_name, step_func in steps:
        try:
            if not step_func():
                failed_steps.append(step_name)
        except Exception as e:
            print(f"❌ Error in {step_name}: {e}")
            failed_steps.append(step_name)

    # Print results
    if failed_steps:
        print("\n⚠️  Setup completed with errors:")
        for step in failed_steps:
            print(f"  - {step}")
        print("\nPlease resolve these issues before running the application.")
        sys.exit(1)
    else:
        print_summary()
        sys.exit(0)


if __name__ == '__main__':
    main()