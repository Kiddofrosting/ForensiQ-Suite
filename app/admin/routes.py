"""
Admin module for user and system management
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from datetime import datetime
from bson import ObjectId
from app import get_db
from app.models import User, AuditLog
from app.utils import login_required, role_required, get_client_ip, validate_password_strength

admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/users')
@login_required
@role_required('admin')
def list_users():
    """List all users"""
    db = get_db()

    # Get filter parameters
    status_filter = request.args.get('status', 'all')
    role_filter = request.args.get('role', 'all')

    query = {}
    if status_filter != 'all':
        query['status'] = status_filter

    if role_filter != 'all':
        query['role'] = role_filter

    users = list(db.users.find(query).sort('created_at', -1))

    # Get statistics
    stats = {
        'total': db.users.count_documents({}),
        'active': db.users.count_documents({'status': 'active'}),
        'suspended': db.users.count_documents({'status': 'suspended'}),
        'inactive': db.users.count_documents({'status': 'inactive'})
    }

    return render_template('admin/users.html',
                           users=users,
                           stats=stats,
                           status_filter=status_filter,
                           role_filter=role_filter)


@admin_bp.route('/user/create', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def create_user():
    """Create a new user"""
    db = get_db()

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        full_name = request.form.get('full_name')
        role = request.form.get('role')
        mfa_enabled = request.form.get('mfa_enabled') == 'on'

        # Validate password
        is_strong, message = validate_password_strength(password)
        if not is_strong:
            flash(message, 'danger')
            return render_template('admin/create_user.html')

        # Check if username exists
        if db.users.find_one({'username': username}):
            flash('Username already exists', 'danger')
            return render_template('admin/create_user.html')

        # Check if email exists
        if db.users.find_one({'email': email}):
            flash('Email already exists', 'danger')
            return render_template('admin/create_user.html')

        # Create user
        user = User(
            username=username,
            email=email,
            password=password,
            role=role,
            full_name=full_name,
            mfa_enabled=mfa_enabled,
            status='active',
            created_by=session['user_id']
        )

        result = db.users.insert_one(user.to_dict())

        # Log user creation
        log_entry = AuditLog(
            user_id=session['user_id'],
            username=session['username'],
            role=session['role'],
            action='user_created',
            ip_address=get_client_ip(),
            metadata={
                'new_user_id': str(result.inserted_id),
                'new_username': username,
                'new_user_role': role
            }
        )
        db.audit_logs.insert_one(log_entry.to_dict())

        flash(f'User {username} created successfully!', 'success')
        return redirect(url_for('admin.list_users'))

    return render_template('admin/create_user.html')


@admin_bp.route('/user/<user_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_user(user_id):
    """Edit user details"""
    db = get_db()

    try:
        user = db.users.find_one({'_id': ObjectId(user_id)})
    except:
        flash('Invalid user ID', 'danger')
        return redirect(url_for('admin.list_users'))

    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin.list_users'))

    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        role = request.form.get('role')
        status = request.form.get('status')
        mfa_enabled = request.form.get('mfa_enabled') == 'on'

        # Check if email exists for other users
        existing = db.users.find_one({
            'email': email,
            '_id': {'$ne': ObjectId(user_id)}
        })

        if existing:
            flash('Email already in use by another user', 'danger')
            return render_template('admin/edit_user.html', user=user)

        update_data = {
            'full_name': full_name,
            'email': email,
            'role': role,
            'status': status,
            'mfa_enabled': mfa_enabled
        }

        db.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': update_data}
        )

        # Log user update
        log_entry = AuditLog(
            user_id=session['user_id'],
            username=session['username'],
            role=session['role'],
            action='user_updated',
            ip_address=get_client_ip(),
            metadata={
                'updated_user_id': user_id,
                'updated_username': user['username'],
                'changes': update_data
            }
        )
        db.audit_logs.insert_one(log_entry.to_dict())

        flash('User updated successfully!', 'success')
        return redirect(url_for('admin.list_users'))

    return render_template('admin/edit_user.html', user=user)


@admin_bp.route('/user/<user_id>/suspend', methods=['POST'])
@login_required
@role_required('admin')
def suspend_user(user_id):
    """Suspend a user account"""
    db = get_db()

    user = db.users.find_one({'_id': ObjectId(user_id)})

    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin.list_users'))

    # Don't allow suspending self
    if str(user['_id']) == session['user_id']:
        flash('You cannot suspend your own account', 'danger')
        return redirect(url_for('admin.list_users'))

    db.users.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {'status': 'suspended'}}
    )

    # Log suspension
    log_entry = AuditLog(
        user_id=session['user_id'],
        username=session['username'],
        role=session['role'],
        action='user_suspended',
        ip_address=get_client_ip(),
        metadata={
            'suspended_user_id': user_id,
            'suspended_username': user['username']
        }
    )
    db.audit_logs.insert_one(log_entry.to_dict())

    flash(f'User {user["username"]} suspended successfully!', 'success')
    return redirect(url_for('admin.list_users'))


@admin_bp.route('/user/<user_id>/activate', methods=['POST'])
@login_required
@role_required('admin')
def activate_user(user_id):
    """Activate a suspended user account"""
    db = get_db()

    user = db.users.find_one({'_id': ObjectId(user_id)})

    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin.list_users'))

    db.users.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {'status': 'active'}}
    )

    # Log activation
    log_entry = AuditLog(
        user_id=session['user_id'],
        username=session['username'],
        role=session['role'],
        action='user_activated',
        ip_address=get_client_ip(),
        metadata={
            'activated_user_id': user_id,
            'activated_username': user['username']
        }
    )
    db.audit_logs.insert_one(log_entry.to_dict())

    flash(f'User {user["username"]} activated successfully!', 'success')
    return redirect(url_for('admin.list_users'))


@admin_bp.route('/user/<user_id>/reset-password', methods=['POST'])
@login_required
@role_required('admin')
def reset_password(user_id):
    """Reset user password"""
    db = get_db()

    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if new_password != confirm_password:
        flash('Passwords do not match', 'danger')
        return redirect(url_for('admin.edit_user', user_id=user_id))

    is_strong, message = validate_password_strength(new_password)
    if not is_strong:
        flash(message, 'danger')
        return redirect(url_for('admin.edit_user', user_id=user_id))

    user = db.users.find_one({'_id': ObjectId(user_id)})

    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin.list_users'))

    # Update password
    from werkzeug.security import generate_password_hash
    new_hash = generate_password_hash(new_password)

    db.users.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {'password_hash': new_hash}}
    )

    # Log password reset
    log_entry = AuditLog(
        user_id=session['user_id'],
        username=session['username'],
        role=session['role'],
        action='password_reset_by_admin',
        ip_address=get_client_ip(),
        metadata={
            'target_user_id': user_id,
            'target_username': user['username']
        }
    )
    db.audit_logs.insert_one(log_entry.to_dict())

    flash(f'Password reset successfully for {user["username"]}!', 'success')
    return redirect(url_for('admin.edit_user', user_id=user_id))


@admin_bp.route('/user/<user_id>/toggle-mfa', methods=['POST'])
@login_required
@role_required('admin')
def toggle_mfa(user_id):
    """Enable/disable MFA for a user"""
    db = get_db()

    user = db.users.find_one({'_id': ObjectId(user_id)})

    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin.list_users'))

    current_mfa = user.get('mfa_enabled', False)
    new_mfa = not current_mfa

    db.users.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {'mfa_enabled': new_mfa}}
    )

    # Log MFA toggle
    log_entry = AuditLog(
        user_id=session['user_id'],
        username=session['username'],
        role=session['role'],
        action='mfa_toggled',
        ip_address=get_client_ip(),
        metadata={
            'target_user_id': user_id,
            'target_username': user['username'],
            'mfa_enabled': new_mfa
        }
    )
    db.audit_logs.insert_one(log_entry.to_dict())

    status = 'enabled' if new_mfa else 'disabled'
    flash(f'MFA {status} for {user["username"]}!', 'success')
    return redirect(url_for('admin.list_users'))


@admin_bp.route('/system-settings', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def system_settings():
    """System settings page"""
    db = get_db()

    if request.method == 'POST':
        # Update system settings
        settings = {
            'anomaly_detection_enabled': request.form.get('anomaly_detection') == 'on',
            'auto_suspend_on_anomaly': request.form.get('auto_suspend') == 'on',
            'mfa_required_for_all': request.form.get('mfa_required') == 'on',
            'session_timeout_minutes': int(request.form.get('session_timeout', 120)),
            'max_login_attempts': int(request.form.get('max_login_attempts', 5)),
            'updated_at': datetime.utcnow(),
            'updated_by': session['user_id']
        }

        db.system_settings.update_one(
            {},
            {'$set': settings},
            upsert=True
        )

        # Log settings update
        log_entry = AuditLog(
            user_id=session['user_id'],
            username=session['username'],
            role=session['role'],
            action='system_settings_updated',
            ip_address=get_client_ip(),
            metadata={'settings': settings}
        )
        db.audit_logs.insert_one(log_entry.to_dict())

        flash('System settings updated successfully!', 'success')

    # Get current settings
    settings = db.system_settings.find_one() or {}

    # Get system statistics
    stats = {
        'total_users': db.users.count_documents({}),
        'total_cases': db.cases.count_documents({}),
        'total_evidence': db.evidence.count_documents({}),
        'total_logs': db.audit_logs.count_documents({}),
        'total_osint_queries': db.osint_queries.count_documents({}),
        'total_anomalies': db.anomaly_alerts.count_documents({}),
        'database_size': 'N/A'  # Would need admin privileges to query
    }

    return render_template('admin/settings.html', settings=settings, stats=stats)


@admin_bp.route('/statistics')
@login_required
@role_required('admin')
def statistics():
    """System statistics dashboard"""
    db = get_db()
    from datetime import timedelta

    # User statistics
    user_stats = {
        'total': db.users.count_documents({}),
        'active': db.users.count_documents({'status': 'active'}),
        'suspended': db.users.count_documents({'status': 'suspended'}),
        'by_role': {}
    }

    for role in ['admin', 'case_manager', 'investigator', 'osint_analyst', 'legal_reviewer']:
        user_stats['by_role'][role] = db.users.count_documents({'role': role})

    # Case statistics
    case_stats = {
        'total': db.cases.count_documents({}),
        'open': db.cases.count_documents({'status': 'open'}),
        'in_progress': db.cases.count_documents({'status': 'in_progress'}),
        'closed': db.cases.count_documents({'status': 'closed'}),
        'archived': db.cases.count_documents({'status': 'archived'})
    }

    # Evidence statistics
    evidence_stats = {
        'total': db.evidence.count_documents({}),
        'active': db.evidence.count_documents({'status': 'active'}),
        'verified': db.evidence.count_documents({'verified_by': {'$ne': None}}),
        'total_size': 0  # Would need to sum file sizes
    }

    # Activity statistics (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)

    activity_stats = {
        'logins': db.audit_logs.count_documents({
            'action': 'login',
            'timestamp': {'$gte': thirty_days_ago}
        }),
        'failed_logins': db.audit_logs.count_documents({
            'action': 'failed_login',
            'timestamp': {'$gte': thirty_days_ago}
        }),
        'evidence_uploads': db.audit_logs.count_documents({
            'action': 'evidence_uploaded',
            'timestamp': {'$gte': thirty_days_ago}
        }),
        'osint_queries': db.osint_queries.count_documents({
            'performed_at': {'$gte': thirty_days_ago}
        }),
        'anomalies_detected': db.anomaly_alerts.count_documents({
            'detected_at': {'$gte': thirty_days_ago}
        })
    }

    return render_template('admin/statistics.html',
                           user_stats=user_stats,
                           case_stats=case_stats,
                           evidence_stats=evidence_stats,
                           activity_stats=activity_stats)