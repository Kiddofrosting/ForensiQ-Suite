# ForensIQ Suite - API Documentation

## Overview

ForensIQ Suite provides a comprehensive REST API for digital evidence management and forensic investigations. This document covers all available endpoints, authentication, and usage examples.

**Base URL:** `http://localhost:5000` (development)

---

## Authentication

### Login
**POST** `/auth/login`

Authenticate user and create session.

**Request Body:**
```json
{
  "username": "admin",
  "password": "Admin@123"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "user": {
    "id": "user_id",
    "username": "admin",
    "role": "admin"
  }
}
```

### Verify MFA
**POST** `/auth/verify-mfa`

Verify multi-factor authentication code.

**Request Body:**
```json
{
  "code": "123456"
}
```

### Logout
**GET** `/auth/logout`

End user session.

---

## User Management

### List Users
**GET** `/admin/users`

List all users (Admin only).

**Query Parameters:**
- `status` - Filter by status (active, suspended, inactive)
- `role` - Filter by role

**Response:**
```json
{
  "users": [
    {
      "id": "user_id",
      "username": "admin",
      "email": "admin@forensiq.local",
      "role": "admin",
      "status": "active",
      "mfa_enabled": false,
      "created_at": "2025-01-01T00:00:00"
    }
  ]
}
```

### Create User
**POST** `/admin/user/create`

Create new user (Admin only).

**Request Body:**
```json
{
  "username": "newuser",
  "email": "newuser@forensiq.local",
  "password": "Strong@Pass123",
  "full_name": "New User",
  "role": "investigator",
  "mfa_enabled": false
}
```

### Edit User
**POST** `/admin/user/<user_id>/edit`

Update user details (Admin only).

### Suspend User
**POST** `/admin/user/<user_id>/suspend`

Suspend user account (Admin only).

### Activate User
**POST** `/admin/user/<user_id>/activate`

Activate suspended account (Admin only).

---

## Case Management

### List Cases
**GET** `/cases/`

List all accessible cases.

**Query Parameters:**
- `status` - Filter by status (open, in_progress, closed, archived)
- `priority` - Filter by priority

**Response:**
```json
{
  "cases": [
    {
      "id": "case_id",
      "case_number": "CASE-20250126-ABC123",
      "title": "Data Breach Investigation",
      "description": "...",
      "status": "open",
      "priority": "high",
      "created_by": "user_id",
      "assigned_to": ["user_id_1", "user_id_2"],
      "created_at": "2025-01-26T00:00:00",
      "evidence_count": 5
    }
  ]
}
```

### Create Case
**POST** `/cases/create`

Create new case.

**Request Body:**
```json
{
  "title": "New Investigation",
  "description": "Case description",
  "priority": "high",
  "case_type": "cybercrime",
  "assigned_to": ["user_id_1", "user_id_2"]
}
```

**Response:**
```json
{
  "success": true,
  "case_id": "case_id",
  "case_number": "CASE-20250126-ABC123"
}
```

### View Case
**GET** `/cases/<case_id>`

Get case details including evidence and timeline.

### Edit Case
**POST** `/cases/<case_id>/edit`

Update case details.

### Add Note
**POST** `/cases/<case_id>/add-note`

Add note to case.

**Request Body:**
```json
{
  "note": "Investigation update..."
}
```

### Add Tag
**POST** `/cases/<case_id>/add-tag`

Add tag to case.

**Request Body:**
```json
{
  "tag": "cybercrime"
}
```

### Search Cases
**GET** `/cases/search?q=<query>`

Search cases by title, description, or case number.

---

## Evidence Management

### Upload Evidence
**POST** `/evidence/upload/<case_id>`

Upload evidence file to case.

**Request:**
- Content-Type: `multipart/form-data`
- `file` - Evidence file
- `description` - Evidence description
- `tags` - Comma-separated tags
- `retention_days` - Retention period (default: 365)

**Response:**
```json
{
  "success": true,
  "evidence_id": "evidence_id",
  "hashes": {
    "sha256": "...",
    "md5": "...",
    "sha1": "..."
  }
}
```

### View Evidence
**GET** `/evidence/<evidence_id>`

Get evidence details and metadata.

**Response:**
```json
{
  "id": "evidence_id",
  "file_name": "evidence.pdf",
  "file_size": 1048576,
  "file_type": "application/pdf",
  "sha256_hash": "...",
  "md5_hash": "...",
  "sha1_hash": "...",
  "uploaded_by": "user_id",
  "uploaded_at": "2025-01-26T00:00:00",
  "metadata": {
    "file_size_human": "1.00 MB",
    "created": "...",
    "modified": "..."
  },
  "chain_of_custody": [
    {
      "action": "evidence_uploaded",
      "user_id": "user_id",
      "timestamp": "2025-01-26T00:00:00",
      "ip_address": "192.168.1.1"
    }
  ],
  "verified": true,
  "verified_by": "user_id",
  "verified_at": "2025-01-26T01:00:00"
}
```

### Download Evidence
**GET** `/evidence/<evidence_id>/download`

Download evidence file (decrypted).

### Verify Evidence
**POST** `/evidence/<evidence_id>/verify`

Verify evidence integrity by checking hash.

---

## OSINT Operations

### OSINT Dashboard
**GET** `/osint/dashboard`

View OSINT query statistics and recent queries.

### Perform Query
**POST** `/osint/query/<case_id>`

Execute OSINT query.

**Request Body:**
```json
{
  "query_type": "whois",
  "query_term": "example.com"
}
```

**Query Types:**
- `whois` - Domain WHOIS lookup
- `dns` - DNS records
- `ip` - IP address intelligence
- `email` - Email validation and intelligence
- `url` - URL analysis
- `file` - File hash lookup
- `username` - Username enumeration

**Response:**
```json
{
  "success": true,
  "query_id": "query_id",
  "status": "completed",
  "results": {
    "domain_name": "example.com",
    "registrar": "...",
    "creation_date": "...",
    "records": {
      "A": ["93.184.216.34"],
      "MX": [...],
      "NS": [...]
    }
  }
}
```

### View Query Results
**GET** `/osint/view/<query_id>`

Get OSINT query results.

### Bulk Query
**POST** `/osint/bulk-query/<case_id>`

Execute multiple OSINT queries.

**Request Body:**
```json
{
  "query_type": "whois",
  "query_terms": "example.com\ntest.com\ndomain.com"
}
```

### Quick Lookup (AJAX)
**POST** `/osint/api/quick-lookup`

Quick OSINT lookup without saving to case.

**Request Body:**
```json
{
  "type": "email",
  "term": "test@example.com"
}
```

---

## Anomaly Detection

### List Anomalies
**GET** `/ml/anomalies`

List all anomaly alerts (Admin/Case Manager only).

**Query Parameters:**
- `status` - Filter by status (open, investigating, resolved, false_positive)
- `user` - Filter by user ID

### View Anomaly
**GET** `/ml/anomaly/<anomaly_id>`

Get anomaly details.

**Response:**
```json
{
  "id": "anomaly_id",
  "user_id": "user_id",
  "username": "testuser",
  "anomaly_type": "login_pattern",
  "anomaly_score": 0.85,
  "detected_at": "2025-01-26T00:00:00",
  "status": "open",
  "details": {
    "features": {
      "login_count": 50,
      "failed_login_count": 8,
      "unique_ips": 10
    },
    "detection_method": "ML (IForest + LOF)"
  }
}
```

### Update Anomaly
**POST** `/ml/anomaly/<anomaly_id>/update`

Update anomaly status and add resolution notes.

**Request Body:**
```json
{
  "status": "resolved",
  "notes": "Investigation complete. False positive."
}
```

### Run Detection
**POST** `/ml/run-detection`

Manually trigger anomaly detection (Admin only).

### Anomaly Statistics
**GET** `/ml/api/anomaly-stats?days=7`

Get anomaly statistics for specified period.

---

## Audit Logs

### View Logs
**GET** `/logs/`

View audit logs (Admin/Case Manager only).

**Query Parameters:**
- `user` - Filter by user ID
- `action` - Filter by action type
- `days` - Days to look back (default: 7)
- `page` - Page number

**Response:**
```json
{
  "logs": [
    {
      "id": "log_id",
      "user_id": "user_id",
      "username": "admin",
      "role": "admin",
      "action": "login",
      "timestamp": "2025-01-26T00:00:00",
      "ip_address": "192.168.1.1",
      "metadata": {},
      "previous_hash": "...",
      "current_hash": "..."
    }
  ],
  "total": 100,
  "page": 1,
  "total_pages": 2
}
```

### Verify Chain
**GET** `/logs/verify-chain`

Verify audit log chain integrity (Admin only).

### Export Logs
**GET** `/logs/export?days=7`

Export audit logs to JSON.

### User Logs
**GET** `/logs/user/<user_id>?days=30`

View logs for specific user.

### Case Logs
**GET** `/logs/case/<case_id>`

View logs for specific case.

### Recent Activity (AJAX)
**GET** `/logs/api/recent-activity?limit=10`

Get recent system activity.

---

## System Administration

### System Settings
**GET/POST** `/admin/system-settings`

View or update system settings (Admin only).

**POST Request Body:**
```json
{
  "anomaly_detection": true,
  "auto_suspend": false,
  "mfa_required": false,
  "session_timeout": 120,
  "max_login_attempts": 5
}
```

### Statistics
**GET** `/admin/statistics`

Get system statistics.

**Response:**
```json
{
  "user_stats": {
    "total": 10,
    "active": 8,
    "suspended": 2,
    "by_role": {
      "admin": 1,
      "investigator": 5,
      "osint_analyst": 2,
      "legal_reviewer": 2
    }
  },
  "case_stats": {
    "total": 50,
    "open": 15,
    "in_progress": 20,
    "closed": 15
  },
  "evidence_stats": {
    "total": 200,
    "verified": 180
  },
  "activity_stats": {
    "logins": 500,
    "evidence_uploads": 50,
    "osint_queries": 300
  }
}
```

---

## Error Responses

All endpoints return consistent error responses:

```json
{
  "error": true,
  "message": "Error description",
  "code": "ERROR_CODE"
}
```

**Common HTTP Status Codes:**
- `200` - Success
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `500` - Internal Server Error

---

## Rate Limiting

API endpoints are not rate-limited in development. In production:
- General endpoints: 100 requests/minute
- OSINT queries: 20 requests/minute
- Authentication: 10 requests/minute

---

## Examples

### Python Example

```python
import requests

# Login
session = requests.Session()
login_data = {
    "username": "admin",
    "password": "Admin@123"
}
response = session.post("http://localhost:5000/auth/login", data=login_data)

# Create case
case_data = {
    "title": "New Investigation",
    "description": "Test case",
    "priority": "high",
    "case_type": "cybercrime"
}
response = session.post("http://localhost:5000/cases/create", data=case_data)
case_id = response.json()["case_id"]

# Upload evidence
files = {"file": open("evidence.pdf", "rb")}
data = {"description": "Test evidence"}
response = session.post(
    f"http://localhost:5000/evidence/upload/{case_id}",
    files=files,
    data=data
)

# OSINT query
osint_data = {
    "query_type": "whois",
    "query_term": "example.com"
}
response = session.post(
    f"http://localhost:5000/osint/query/{case_id}",
    data=osint_data
)
```

### cURL Example

```bash
# Login
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin@123"}' \
  -c cookies.txt

# List cases
curl -X GET http://localhost:5000/cases/ \
  -b cookies.txt

# Create case
curl -X POST http://localhost:5000/cases/create \
  -b cookies.txt \
  -F "title=New Investigation" \
  -F "description=Test case" \
  -F "priority=high"

# Upload evidence
curl -X POST http://localhost:5000/evidence/upload/<case_id> \
  -b cookies.txt \
  -F "file=@evidence.pdf" \
  -F "description=Test evidence"
```

---

## Webhooks (Future Enhancement)

Webhook support for external integrations (planned for v2.0):
- Evidence upload notifications
- Anomaly detection alerts
- Case status changes
- Chain-of-custody events

---

## SDK and Client Libraries (Future)

Official SDKs planned:
- Python SDK
- JavaScript SDK
- REST API client

---

**Version:** 1.0.0  
**Last Updated:** 2025-01-26  
**Contact:** forensiq-support@kabarak.ac.ke