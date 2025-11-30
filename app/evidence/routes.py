from flask import Blueprint, render_template, request, redirect, url_for, flash, session, send_file
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from bson import ObjectId
import os
import magic
from PIL import Image
import piexif
from app import get_db
from app.models import Evidence, AuditLog
from app.utils import (login_required, role_required, allowed_file,
                       compute_hashes, encrypt_file, decrypt_file,
                       get_client_ip, format_file_size, safe_filename)
from app.config import Config

evidence_bp = Blueprint('evidence', __name__)


@evidence_bp.route('/upload/<case_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'case_manager', 'investigator')
def upload_evidence(case_id):
    """Upload evidence to a case"""
    db = get_db()

    # Verify case exists and user has access
    case = db.cases.find_one({'_id': ObjectId(case_id)})
    if not case:
        flash('Case not found', 'danger')
        return redirect(url_for('cases.list_cases'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(request.url)

        file = request.files['file']
        description = request.form.get('description', '')
        tags = request.form.get('tags', '').split(',')
        retention_days = int(request.form.get('retention_days', 365))

        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            # Secure filename
            filename = secure_filename(file.filename)
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            unique_filename = f"{timestamp}_{filename}"

            # Create case directory structure
            case_dir = os.path.join(Config.UPLOAD_FOLDER, case_id, 'raw')
            os.makedirs(case_dir, exist_ok=True)

            # Save file
            file_path = os.path.join(case_dir, unique_filename)
            file.save(file_path)

            # Get file info
            file_size = os.path.getsize(file_path)
            file_type = magic.from_file(file_path, mime=True)

            # Compute hashes
            hashes = compute_hashes(file_path)

            # Check for duplicate evidence by hash
            existing_evidence = db.evidence.find_one({
                'sha256_hash': hashes['sha256'],
                'case_id': case_id
            })

            if existing_evidence:
                os.remove(file_path)
                flash('Duplicate evidence detected (same hash exists)', 'warning')
                return redirect(url_for('cases.view_case', case_id=case_id))

            # Extract metadata
            metadata = extract_metadata(file_path, file_type)

            # Encrypt file
            try:
                encrypted_path = encrypt_file(file_path)
                print(f"✓ File encrypted successfully: {encrypted_path}")
            except Exception as e:
                flash(f'Encryption failed: {str(e)}', 'danger')
                os.remove(file_path)
                return redirect(request.url)

            # Create evidence record
            evidence = Evidence(
                case_id=case_id,
                file_name=filename,
                file_path=file_path,
                file_size=file_size,
                file_type=file_type,
                uploaded_by=session['user_id'],
                description=description
            )

            evidence.sha256_hash = hashes['sha256']
            evidence.md5_hash = hashes['md5']
            evidence.sha1_hash = hashes['sha1']
            evidence.encrypted_path = encrypted_path
            evidence.metadata = metadata
            evidence.tags = [tag.strip().lower() for tag in tags if tag.strip()]
            evidence.retention_until = datetime.utcnow() + timedelta(days=retention_days)

            # Add chain of custody entry
            custody_entry = {
                'action': 'evidence_uploaded',
                'user_id': session['user_id'],
                'username': session['username'],
                'timestamp': datetime.utcnow(),
                'ip_address': get_client_ip(),
                'details': 'Evidence uploaded to system'
            }
            evidence.chain_of_custody.append(custody_entry)

            result = db.evidence.insert_one(evidence.to_dict())
            evidence_id = str(result.inserted_id)

            # Update case with evidence reference
            db.cases.update_one(
                {'_id': ObjectId(case_id)},
                {'$push': {'evidence_ids': evidence_id}}
            )

            # Log evidence upload
            log_entry = AuditLog(
                user_id=session['user_id'],
                username=session['username'],
                role=session['role'],
                action='evidence_uploaded',
                ip_address=get_client_ip(),
                metadata={
                    'case_id': case_id,
                    'evidence_id': evidence_id,
                    'file_name': filename,
                    'file_size': file_size,
                    'sha256': hashes['sha256']
                }
            )
            db.audit_logs.insert_one(log_entry.to_dict())

            flash(f'Evidence uploaded successfully! SHA256: {hashes["sha256"]}', 'success')
            return redirect(url_for('evidence.view_evidence', evidence_id=evidence_id))

        flash('File type not allowed', 'danger')
        return redirect(request.url)

    return render_template('evidence/upload.html', case=case)


@evidence_bp.route('/<evidence_id>')
@login_required
def view_evidence(evidence_id):
    """View evidence details"""
    db = get_db()

    try:
        evidence = db.evidence.find_one({'_id': ObjectId(evidence_id)})
    except:
        flash('Invalid evidence ID', 'danger')
        return redirect(url_for('cases.list_cases'))

    if not evidence:
        flash('Evidence not found', 'danger')
        return redirect(url_for('cases.list_cases'))

    # Get case details
    case = db.cases.find_one({'_id': ObjectId(evidence['case_id'])})

    # Check access permissions
    user_role = session.get('role')
    user_id = session.get('user_id')

    if user_role not in ['admin', 'case_manager']:
        if case['created_by'] != user_id and user_id not in case.get('assigned_to', []):
            if user_role == 'legal_reviewer' and evidence.get('verified_by') is None:
                flash('You do not have permission to view unverified evidence', 'danger')
                return redirect(url_for('cases.view_case', case_id=evidence['case_id']))

    # Log evidence view
    log_entry = AuditLog(
        user_id=session['user_id'],
        username=session['username'],
        role=session['role'],
        action='evidence_viewed',
        ip_address=get_client_ip(),
        metadata={
            'case_id': evidence['case_id'],
            'evidence_id': evidence_id,
            'file_name': evidence['file_name']
        }
    )
    db.audit_logs.insert_one(log_entry.to_dict())

    # Add chain of custody entry
    custody_entry = {
        'action': 'evidence_viewed',
        'user_id': session['user_id'],
        'username': session['username'],
        'timestamp': datetime.utcnow(),
        'ip_address': get_client_ip(),
        'details': f'Evidence viewed by {session["username"]}'
    }

    db.evidence.update_one(
        {'_id': ObjectId(evidence_id)},
        {'$push': {'chain_of_custody': custody_entry}}
    )

    return render_template('evidence/view.html', evidence=evidence, case=case)


@evidence_bp.route('/<evidence_id>/download')
@login_required
def download_evidence(evidence_id):
    """Download evidence file"""
    db = get_db()

    evidence = db.evidence.find_one({'_id': ObjectId(evidence_id)})

    if not evidence:
        flash('Evidence not found', 'danger')
        return redirect(url_for('cases.list_cases'))

    # Check permissions
    user_role = session.get('role')
    if user_role == 'osint_analyst':
        flash('OSINT analysts cannot download evidence files', 'danger')
        return redirect(url_for('evidence.view_evidence', evidence_id=evidence_id))

    # Decrypt file temporarily
    encrypted_path = evidence['encrypted_path']
    temp_path = encrypted_path + '.temp'

    try:
        encryption_key = Config.ENCRYPTION_KEY
        decrypt_file(encrypted_path, encryption_key, temp_path)

        # Log download
        log_entry = AuditLog(
            user_id=session['user_id'],
            username=session['username'],
            role=session['role'],
            action='evidence_downloaded',
            ip_address=get_client_ip(),
            metadata={
                'case_id': evidence['case_id'],
                'evidence_id': evidence_id,
                'file_name': evidence['file_name']
            }
        )
        db.audit_logs.insert_one(log_entry.to_dict())

        # Add chain of custody entry
        custody_entry = {
            'action': 'evidence_downloaded',
            'user_id': session['user_id'],
            'username': session['username'],
            'timestamp': datetime.utcnow(),
            'ip_address': get_client_ip(),
            'details': f'Evidence downloaded by {session["username"]}'
        }

        db.evidence.update_one(
            {'_id': ObjectId(evidence_id)},
            {'$push': {'chain_of_custody': custody_entry}}
        )

        response = send_file(
            temp_path,
            as_attachment=True,
            download_name=evidence['file_name']
        )

        # Clean up temp file after sending
        @response.call_on_close
        def cleanup():
            if os.path.exists(temp_path):
                os.remove(temp_path)

        return response

    except Exception as e:
        flash(f'Error downloading file: {str(e)}', 'danger')
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return redirect(url_for('evidence.view_evidence', evidence_id=evidence_id))


@evidence_bp.route('/<evidence_id>/verify', methods=['POST'])
@login_required
@role_required('admin', 'case_manager', 'legal_reviewer')
def verify_evidence(evidence_id):
    """Verify evidence integrity"""
    db = get_db()

    evidence = db.evidence.find_one({'_id': ObjectId(evidence_id)})

    if not evidence:
        flash('Evidence not found', 'danger')
        return redirect(url_for('cases.list_cases'))

    # Verify hash integrity
    current_hash = compute_hashes(evidence['file_path'])['sha256']

    if current_hash != evidence['sha256_hash']:
        flash('Evidence integrity check FAILED! Hash mismatch detected.', 'danger')

        # Log tampering detection
        log_entry = AuditLog(
            user_id=session['user_id'],
            username=session['username'],
            role=session['role'],
            action='evidence_tampering_detected',
            ip_address=get_client_ip(),
            metadata={
                'case_id': evidence['case_id'],
                'evidence_id': evidence_id,
                'original_hash': evidence['sha256_hash'],
                'current_hash': current_hash
            }
        )
        db.audit_logs.insert_one(log_entry.to_dict())

        return redirect(url_for('evidence.view_evidence', evidence_id=evidence_id))

    # Mark as verified
    db.evidence.update_one(
        {'_id': ObjectId(evidence_id)},
        {'$set': {
            'verified_by': session['user_id'],
            'verified_at': datetime.utcnow()
        }}
    )

    # Log verification
    log_entry = AuditLog(
        user_id=session['user_id'],
        username=session['username'],
        role=session['role'],
        action='evidence_verified',
        ip_address=get_client_ip(),
        metadata={
            'case_id': evidence['case_id'],
            'evidence_id': evidence_id,
            'sha256': evidence['sha256_hash']
        }
    )
    db.audit_logs.insert_one(log_entry.to_dict())

    # Add chain of custody entry
    custody_entry = {
        'action': 'evidence_verified',
        'user_id': session['user_id'],
        'username': session['username'],
        'timestamp': datetime.utcnow(),
        'ip_address': get_client_ip(),
        'details': f'Evidence verified by {session["username"]}'
    }

    db.evidence.update_one(
        {'_id': ObjectId(evidence_id)},
        {'$push': {'chain_of_custody': custody_entry}}
    )

    flash('Evidence integrity verified successfully!', 'success')
    return redirect(url_for('evidence.view_evidence', evidence_id=evidence_id))


def extract_metadata(file_path, file_type):
    """Extract metadata from file based on type"""
    metadata = {
        'file_type': file_type,
        'extracted_at': datetime.utcnow().isoformat()
    }

    try:
        # Image EXIF extraction
        if file_type.startswith('image/'):
            try:
                img = Image.open(file_path)
                metadata['dimensions'] = f"{img.width}x{img.height}"
                metadata['format'] = img.format
                metadata['mode'] = img.mode

                # Extract EXIF if available
                if hasattr(img, '_getexif') and img._getexif():
                    exif_dict = piexif.load(img.info.get('exif', b''))
                    metadata['exif'] = {
                        'Make': exif_dict.get('0th', {}).get(271, 'Unknown'),
                        'Model': exif_dict.get('0th', {}).get(272, 'Unknown'),
                        'DateTime': exif_dict.get('0th', {}).get(306, 'Unknown')
                    }
            except:
                pass

        # File size
        metadata['file_size_bytes'] = os.path.getsize(file_path)
        metadata['file_size_human'] = format_file_size(os.path.getsize(file_path))

        # Creation and modification times
        stat = os.stat(file_path)
        metadata['created'] = datetime.fromtimestamp(stat.st_ctime).isoformat()
        metadata['modified'] = datetime.fromtimestamp(stat.st_mtime).isoformat()

    except Exception as e:
        metadata['error'] = str(e)

    return metadata