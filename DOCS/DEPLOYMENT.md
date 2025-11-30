# ForensIQ Suite - Deployment Guide

## Table of Contents
1. [Development Deployment](#development-deployment)
2. [Production Deployment](#production-deployment)
3. [Security Hardening](#security-hardening)
4. [Backup and Recovery](#backup-and-recovery)
5. [Monitoring](#monitoring)
6. [Troubleshooting](#troubleshooting)

---

## Development Deployment

### Prerequisites
- Python 3.8 or higher
- MongoDB 4.4 or higher
- 4GB RAM minimum
- 20GB disk space

### Quick Start

1. **Clone the repository**
```bash
git clone <repository-url>
cd ForensIQ-Suite
```

2. **Run automated setup**
```bash
python scripts/setup.py
```

Or use Make commands:
```bash
make setup
```

3. **Start the application**
```bash
python run.py
# or
make run
```

4. **Access the application**
```
http://localhost:5000
```

### Manual Setup

If automated setup fails:

1. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Generate encryption keys**
```bash
python scripts/generate_keys.py
```

4. **Create .env file**
Copy the output from generate_keys.py to a new `.env` file

5. **Start MongoDB**
```bash
mongod --dbpath /path/to/data/db
```

6. **Seed database**
```bash
python scripts/seed_database.py
```

7. **Run application**
```bash
python run.py
```

---

## Production Deployment

### System Requirements
- Ubuntu 20.04 LTS or CentOS 8 (recommended)
- Python 3.8+
- MongoDB 4.4+
- Nginx (reverse proxy)
- SSL certificate
- 8GB RAM minimum
- 100GB disk space

### Production Setup

#### 1. System Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install python3-pip python3-venv nginx mongodb-org git -y
```

#### 2. Application Setup

```bash
# Create application user
sudo useradd -m -s /bin/bash forensiq
sudo su - forensiq

# Clone repository
git clone <repository-url>
cd ForensIQ-Suite

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt gunicorn
```

#### 3. Configuration

Create production `.env`:
```bash
SECRET_KEY=<generate-secure-key>
FLASK_ENV=production
MONGO_URI=mongodb://localhost:27017/
MONGO_DB=FSUITE_PROD
ENCRYPTION_KEY=<generate-secure-fernet-key>
```

#### 4. Gunicorn Configuration

Create `/etc/systemd/system/forensiq.service`:
```ini
[Unit]
Description=ForensIQ Suite
After=network.target

[Service]
User=forensiq
Group=forensiq
WorkingDirectory=/home/forensiq/ForensIQ-Suite
Environment="PATH=/home/forensiq/ForensIQ-Suite/venv/bin"
ExecStart=/home/forensiq/ForensIQ-Suite/venv/bin/gunicorn --workers 4 --bind 127.0.0.1:5000 run:app

[Install]
WantedBy=multi-user.target
```

Enable and start service:
```bash
sudo systemctl enable forensiq
sudo systemctl start forensiq
```

#### 5. Nginx Configuration

Create `/etc/nginx/sites-available/forensiq`:
```nginx
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /etc/ssl/certs/forensiq.crt;
    ssl_certificate_key /etc/ssl/private/forensiq.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    client_max_body_size 500M;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static {
        alias /home/forensiq/ForensIQ-Suite/app/static;
        expires 30d;
    }
}
```

Enable site:
```bash
sudo ln -s /etc/nginx/sites-available/forensiq /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

#### 6. MongoDB Security

```bash
# Create MongoDB admin user
mongo
use admin
db.createUser({
  user: "forensiq_admin",
  pwd: "<strong-password>",
  roles: ["userAdminAnyDatabase", "dbAdminAnyDatabase"]
})

# Create database user
use FSUITE_PROD
db.createUser({
  user: "forensiq_user",
  pwd: "<strong-password>",
  roles: ["readWrite"]
})

# Enable authentication in /etc/mongod.conf
security:
  authorization: enabled

# Restart MongoDB
sudo systemctl restart mongod
```

Update `.env`:
```
MONGO_URI=mongodb://forensiq_user:<password>@localhost:27017/FSUITE_PROD
```

---

## Security Hardening

### 1. Firewall Configuration

```bash
# UFW (Ubuntu)
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# Block direct access to MongoDB
sudo ufw deny 27017
```

### 2. Application Security

**app/config.py production settings:**
```python
class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
```

### 3. Password Policies

- Enforce MFA for all admin accounts
- Require password changes every 90 days
- Implement account lockout after 5 failed attempts
- Use strong password requirements (already implemented)

### 4. Audit Logging

- Enable all audit logging
- Monitor for suspicious activities
- Regular log review and analysis
- Implement log rotation

### 5. Backup Encryption

```bash
# Encrypt backups with GPG
gpg --symmetric --cipher-algo AES256 backup_file.tar.gz
```

---

## Backup and Recovery

### Automated Backups

Create `/home/forensiq/backup.sh`:
```bash
#!/bin/bash
cd /home/forensiq/ForensIQ-Suite
source venv/bin/activate
python scripts/backup_database.py
tar -czf /backups/forensiq_$(date +%Y%m%d).tar.gz backups/
find /backups -name "forensiq_*.tar.gz" -mtime +30 -delete
```

Add to crontab:
```bash
# Daily backup at 2 AM
0 2 * * * /home/forensiq/backup.sh
```

### Recovery Process

1. **Stop application**
```bash
sudo systemctl stop forensiq
```

2. **Restore database**
```bash
cd /home/forensiq/ForensIQ-Suite
source venv/bin/activate
python scripts/backup_database.py restore backups/backup_20220801_120000
```

3. **Restore files**
```bash
tar -xzf /backups/forensiq_20220801.tar.gz
```

4. **Start application**
```bash
sudo systemctl start forensiq
```

---

## Monitoring

### 1. Application Monitoring

Monitor logs:
```bash
# Application logs
tail -f logs/forensiq.log

# Nginx logs
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log

# Gunicorn logs
journalctl -u forensiq -f
```

### 2. System Monitoring

```bash
# CPU and Memory
htop

# Disk usage
df -h

# MongoDB stats
mongo --eval "db.serverStatus()"
```

### 3. Anomaly Detection

- Enable automated anomaly detection in settings
- Review anomaly alerts daily
- Configure email notifications for critical anomalies

### 4. Performance Monitoring

```bash
# Monitor response times
tail -f /var/log/nginx/access.log | awk '{print $NF}'

# Database performance
mongostat
mongotop
```

---

## Troubleshooting

### Common Issues

#### Application won't start

1. Check Python version:
```bash
python --version
```

2. Check dependencies:
```bash
pip list
```

3. Check logs:
```bash
tail -f logs/forensiq.log
journalctl -u forensiq -n 50
```

#### MongoDB connection failed

1. Check MongoDB status:
```bash
sudo systemctl status mongod
```

2. Check connection:
```bash
mongo --host localhost --port 27017
```

3. Check authentication:
```bash
mongo -u forensiq_user -p --authenticationDatabase FSUITE_PROD
```

#### High memory usage

1. Reduce Gunicorn workers:
```bash
# Edit /etc/systemd/system/forensiq.service
ExecStart=... --workers 2 ...
```

2. Enable MongoDB memory limit:
```yaml
# /etc/mongod.conf
storage:
  wiredTiger:
    engineConfig:
      cacheSizeGB: 2
```

#### Slow performance

1. Check MongoDB indexes:
```javascript
db.collection.getIndexes()
```

2. Analyze slow queries:
```javascript
db.setProfilingLevel(1, { slowms: 100 })
db.system.profile.find().limit(10).sort({ ts: -1 })
```

3. Optimize queries:
- Add appropriate indexes
- Use projection to limit fields
- Implement pagination

#### SSL certificate issues

1. Check certificate validity:
```bash
openssl x509 -in /etc/ssl/certs/forensiq.crt -text -noout
```

2. Verify Nginx configuration:
```bash
sudo nginx -t
```

3. Renew Let's Encrypt certificate:
```bash
sudo certbot renew
```

---

## Maintenance

### Regular Tasks

**Daily:**
- Review audit logs
- Check anomaly alerts
- Monitor system resources

**Weekly:**
- Review user accounts
- Check backup integrity
- Update security patches

**Monthly:**
- Test disaster recovery
- Review access controls
- Update documentation
- Performance optimization

### Updating the Application

```bash
# Backup first
python scripts/backup_database.py

# Pull updates
git pull origin main

# Install new dependencies
pip install -r requirements.txt

# Run migrations (if any)
python scripts/migrate.py

# Restart application
sudo systemctl restart forensiq
```

---

## Support and Contact

For issues or questions:
- Check documentation in `/docs`
- Review logs in `/logs`
- Contact system administrator
- Submit issue to repository

---

**Last Updated:** 2025-01-26  
**Version:** 1.0.0  
**Author:** ForensIQ Suite Team