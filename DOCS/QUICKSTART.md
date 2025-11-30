# ForensIQ Suite - Quick Start Guide

Get ForensIQ Suite up and running in under 10 minutes!

---

## 📋 Prerequisites Checklist

Before you begin, make sure you have:

- [ ] Python 3.8 or higher installed
- [ ] MongoDB 4.4 or higher installed and running
- [ ] Git installed
- [ ] 4GB RAM available
- [ ] 20GB disk space

**Check Python version:**
```bash
python --version
# Should show 3.8 or higher
```

**Check MongoDB:**
```bash
mongod --version
# Should show 4.4 or higher
```

---

## 🚀 5-Minute Setup

### Step 1: Clone and Navigate

```bash
git clone <repository-url>
cd ForensIQ-Suite
```

### Step 2: Run Automated Setup

```bash
python scripts/setup.py
```

This will:
- Create directory structure
- Install dependencies
- Generate encryption keys
- Create .env file
- Seed database
- Run tests

**That's it!** The application is now ready to use.

---

## 🎮 First Launch

### Start the Application

```bash
python run.py
```

Or use Make:
```bash
make run
```

You should see:
```
 * Running on http://127.0.0.1:5000
 * Running on http://localhost:5000
```

### Access the Application

Open your browser and go to:
```
http://localhost:5000
```

---

## 🔐 Default Login Credentials

### Administrator Account
```
Username: admin
Password: Admin@123
```

### Other Test Accounts

| Role | Username | Password |
|------|----------|----------|
| Case Manager | case_manager | Manager@123 |
| Investigator | investigator1 | Investigator@123 |
| OSINT Analyst | osint_analyst | Osint@123 |
| Legal Reviewer | legal_reviewer | Legal@123 |

**⚠️ Important:** Change these passwords immediately after first login!

---

## 📱 Quick Tour

### 1. Dashboard
After logging in, you'll see:
- System statistics
- Recent cases
- Recent activity
- Quick actions

### 2. Create Your First Case
1. Click **"Cases"** in navigation
2. Click **"Create New Case"**
3. Fill in:
   - Title: "Test Investigation"
   - Description: "My first case"
   - Priority: High
4. Click **"Create"**

### 3. Upload Evidence
1. Open your case
2. Click **"Upload Evidence"**
3. Select a file
4. Add description
5. Click **"Upload"**

The system will:
- Generate SHA-256, MD5, SHA1 hashes
- Encrypt the file
- Extract metadata
- Create chain-of-custody entry

### 4. Run OSINT Query
1. Click **"OSINT"** in navigation
2. Click **"New Query"**
3. Select query type: **WHOIS**
4. Enter domain: **example.com**
5. Click **"Execute"**

Results will show:
- Domain registration info
- Registrar details
- Name servers
- Creation/expiration dates

### 5. View Audit Logs
1. Click **"Logs"** (Admin/Case Manager only)
2. View all system activities
3. Click **"Verify Chain"** to check integrity

---

## 🛠️ Common Tasks

### Create a New User (Admin Only)

1. Go to **Admin** → **Users**
2. Click **"Create User"**
3. Fill in details
4. Assign role
5. Enable/disable MFA
6. Click **"Create"**

### Run Anomaly Detection (Admin Only)

1. Go to **ML** → **Anomalies**
2. Click **"Run Detection"**
3. Review detected anomalies
4. Investigate flagged users

### Backup Database

```bash
python scripts/backup_database.py
```

Or:
```bash
make backup
```

Backups are saved in `backups/` directory.

### Generate New Encryption Keys

```bash
python scripts/generate_keys.py
```

---

## 🐛 Troubleshooting

### Application Won't Start

**Check MongoDB is running:**
```bash
# Start MongoDB
mongod --dbpath /path/to/data/db
```

**Check dependencies:**
```bash
pip install -r requirements.txt
```

### Can't Login

**Reset admin password:**
```bash
python scripts/seed_database.py
```

This recreates all default users.

### Permission Errors

**Check file permissions:**
```bash
chmod -R 755 data/
```

### Port Already in Use

**Change port in run.py:**
```python
app.run(port=8000)  # Change from 5000
```

---

## 📚 Learn More

### Documentation
- `README.md` - Complete documentation
- `API_DOCUMENTATION.md` - API reference
- `DEPLOYMENT.md` - Production deployment
- `PROJECT_STATUS.md` - Implementation status

### Key Features to Explore

1. **Role-Based Access Control**
   - Login as different users
   - Notice different permissions
   - Try accessing admin features

2. **Evidence Management**
   - Upload various file types
   - Verify evidence integrity
   - Download encrypted evidence
   - View chain-of-custody

3. **OSINT Tools**
   - Try all query types
   - Run bulk queries
   - Export results

4. **Anomaly Detection**
   - Generate unusual activity
   - Check anomaly dashboard
   - Review detection details

5. **Audit Logs**
   - View system activity
   - Verify chain integrity
   - Export logs

---

## 🎯 Next Steps

### For Development

1. **Explore the Code**
   ```bash
   # Application structure
   tree app/
   
   # Models
   cat app/models.py
   
   # OSINT tools
   cat app/osint/osint_tools.py
   ```

2. **Run Tests**
   ```bash
   python tests/test_backend.py
   # or
   make test
   ```

3. **Create Frontend**
   - HTML templates in `app/templates/`
   - CSS in `app/static/css/`
   - JS in `app/static/js/`

### For Production

1. **Review Security Settings**
   - Change all default passwords
   - Update `app/config.py`
   - Configure HTTPS

2. **Set Up Monitoring**
   - Configure logging
   - Set up backups
   - Monitor anomalies

3. **Deploy**
   - Follow `DEPLOYMENT.md`
   - Use Gunicorn + Nginx
   - Enable SSL

---

## 💡 Tips & Best Practices

### Security
- Always enable MFA for admin accounts
- Use strong passwords (8+ chars, mixed case, numbers, symbols)
- Review audit logs regularly
- Back up encryption keys securely
- Change default credentials immediately

### Performance
- Keep MongoDB indexed
- Clean old audit logs periodically
- Monitor disk space for evidence
- Use pagination for large datasets

### Workflow
- Create cases before uploading evidence
- Add descriptive tags to cases and evidence
- Document investigation steps in notes
- Run OSINT queries systematically
- Review anomaly alerts daily

---

## 🆘 Getting Help

### Check Logs
```bash
# Application logs
tail -f logs/forensiq.log

# Python errors
python run.py
```

### Common Issues

**"ModuleNotFoundError"**
```bash
pip install -r requirements.txt
```

**"Connection refused to MongoDB"**
```bash
mongod --dbpath /path/to/data/db
```

**"Permission denied"**
```bash
chmod -R 755 data/
chmod +x scripts/*.py
```

### Resources
- Documentation in `/docs`
- Test suite in `/tests`
- Example scripts in `/scripts`

---

## ✅ Verification Checklist

After setup, verify:

- [ ] Application starts without errors
- [ ] Can login with admin credentials
- [ ] Dashboard loads correctly
- [ ] Can create a case
- [ ] Can upload evidence
- [ ] Evidence is encrypted
- [ ] OSINT queries work
- [ ] Audit logs are created
- [ ] Chain integrity verifies
- [ ] Can backup database

---

## 🎉 You're All Set!

ForensIQ Suite is now ready for use!

**Quick Commands:**
```bash
make run      # Start application
make test     # Run tests
make backup   # Backup database
make seed     # Re-seed database
make clean    # Clean temp files
```

**Important URLs:**
- Application: http://localhost:5000
- MongoDB: mongodb://localhost:27017
- Logs: `logs/forensiq.log`
- Backups: `backups/`

**Default Login:** admin / Admin@123

---

**Happy Investigating! 🔍**

For detailed documentation, see `README.md`.  
For API details, see `API_DOCUMENTATION.md`.  
For deployment, see `DEPLOYMENT.md`.

---

**Project:** ForensIQ Suite  
**Institution:** Kabarak University  
**Author:** Caleb Munene Kinyua  
**Version:** 1.0.0