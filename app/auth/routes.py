from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from datetime import datetime, timedelta
from app import get_db
from app.models import User, AuditLog, MFASession
from app.utils import generate_otp, get_client_ip, validate_password_strength, get_last_audit_log_hash
from bson import ObjectId

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        db = get_db()
        user = db.users.find_one({'username': username})

        if not user:
            # Log failed login attempt
            log_entry = AuditLog(
                user_id='unknown',
                username=username,
                role='unknown',
                action='failed_login',
                ip_address=get_client_ip(),
                metadata={'reason': 'user_not_found'},
                previous_hash=get_last_audit_log_hash()
            )
            db.audit_logs.insert_one(log_entry.to_dict())

            flash('Invalid username or password', 'danger')
            return render_template('auth/login.html')

        # Check if account is locked
        if user.get('locked_until') and user['locked_until'] > datetime.utcnow():
            flash('Account is locked. Please try again later.', 'danger')
            return render_template('auth/login.html')

        # Check if account is active
        if user.get('status') != 'active':
            flash('Account is inactive. Contact administrator.', 'danger')
            return render_template('auth/login.html')

        # Verify password
        if not User.verify_password(user['password_hash'], password):
            # Increment failed attempts
            failed_attempts = user.get('failed_login_attempts', 0) + 1
            update_data = {'failed_login_attempts': failed_attempts}

            # Lock account after 5 failed attempts
            if failed_attempts >= 5:
                update_data['locked_until'] = datetime.utcnow() + timedelta(minutes=30)
                flash('Account locked due to multiple failed login attempts.', 'danger')
            else:
                flash('Invalid username or password', 'danger')

            db.users.update_one(
                {'_id': user['_id']},
                {'$set': update_data}
            )

            # Log failed login
            log_entry = AuditLog(
                user_id=str(user['_id']),
                username=username,
                role=user['role'],
                action='failed_login',
                ip_address=get_client_ip(),
                metadata={'reason': 'invalid_password', 'attempts': failed_attempts},
                previous_hash=get_last_audit_log_hash()
            )
            db.audit_logs.insert_one(log_entry.to_dict())

            return render_template('auth/login.html')

        # Reset failed attempts on successful password verification
        db.users.update_one(
            {'_id': user['_id']},
            {'$set': {
                'failed_login_attempts': 0,
                'locked_until': None
            }}
        )

        # Check if MFA is enabled
        if user.get('mfa_enabled'):
            # Generate OTP
            otp = generate_otp()
            expires_at = datetime.utcnow() + timedelta(seconds=600)

            mfa_session = MFASession(
                user_id=str(user['_id']),
                code=otp,
                expires_at=expires_at
            )

            # Delete old MFA sessions for this user
            db.mfa_sessions.delete_many({'user_id': str(user['_id'])})

            # Insert new MFA session
            db.mfa_sessions.insert_one(mfa_session.to_dict())

            # Store user info in session temporarily
            session['pending_user_id'] = str(user['_id'])
            session['pending_username'] = user['username']
            session['pending_role'] = user['role']

            # Mock email send (in production, use Flask-Mail)
            print(f"MFA OTP for {username}: {otp}")
            flash(f'MFA code sent to your email. (Dev mode: {otp})', 'info')

            return redirect(url_for('auth.verify_mfa'))

        # No MFA - log in directly
        session['user_id'] = str(user['_id'])
        session['username'] = user['username']
        session['role'] = user['role']
        session['mfa_verified'] = True

        # Update last login
        db.users.update_one(
            {'_id': user['_id']},
            {'$set': {'last_login': datetime.utcnow()}}
        )

        # Log successful login
        log_entry = AuditLog(
            user_id=str(user['_id']),
            username=user['username'],
            role=user['role'],
            action='login',
            ip_address=get_client_ip(),
            metadata={'mfa': False},
            previous_hash=get_last_audit_log_hash()
        )
        db.audit_logs.insert_one(log_entry.to_dict())

        flash('Login successful!', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('auth/login.html')


@auth_bp.route('/verify-mfa', methods=['GET', 'POST'])
def verify_mfa():
    """Verify MFA code"""
    if 'pending_user_id' not in session:
        flash('Invalid session. Please log in again.', 'danger')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        code = request.form.get('code')
        user_id = session.get('pending_user_id')

        db = get_db()

        # Find MFA session
        mfa_session = db.mfa_sessions.find_one({
            'user_id': user_id,
            'expires_at': {'$gt': datetime.utcnow()}
        })

        if not mfa_session:
            flash('MFA code expired. Please log in again.', 'danger')
            session.pop('pending_user_id', None)
            session.pop('pending_username', None)
            session.pop('pending_role', None)
            return redirect(url_for('auth.login'))

        # Check attempts
        if mfa_session.get('attempts', 0) >= 3:
            flash('Too many failed attempts. Please log in again.', 'danger')
            db.mfa_sessions.delete_one({'_id': mfa_session['_id']})
            session.pop('pending_user_id', None)
            session.pop('pending_username', None)
            session.pop('pending_role', None)
            return redirect(url_for('auth.login'))

        # Verify code
        if mfa_session['code'] != code:
            # Increment attempts
            db.mfa_sessions.update_one(
                {'_id': mfa_session['_id']},
                {'$inc': {'attempts': 1}}
            )
            flash('Invalid MFA code. Please try again.', 'danger')
            return render_template('auth/verify_mfa.html')

        # MFA verified - complete login
        session['user_id'] = user_id
        session['username'] = session.pop('pending_username')
        session['role'] = session.pop('pending_role')
        session['mfa_verified'] = True
        session.pop('pending_user_id', None)

        # Mark MFA session as verified
        db.mfa_sessions.update_one(
            {'_id': mfa_session['_id']},
            {'$set': {'verified': True}}
        )

        # Update last login
        db.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'last_login': datetime.utcnow()}}
        )

        # Log successful login with MFA
        log_entry = AuditLog(
            user_id=user_id,
            username=session['username'],
            role=session['role'],
            action='login',
            ip_address=get_client_ip(),
            metadata={'mfa': True},
            previous_hash=get_last_audit_log_hash()
        )
        db.audit_logs.insert_one(log_entry.to_dict())

        flash('Login successful with MFA!', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('auth/verify_mfa.html')


@auth_bp.route('/logout')
def logout():
    """User logout"""
    if 'user_id' in session:
        db = get_db()

        # Log logout
        log_entry = AuditLog(
            user_id=session['user_id'],
            username=session['username'],
            role=session['role'],
            action='logout',
            ip_address=get_client_ip(),
            metadata={},
            previous_hash=get_last_audit_log_hash()
        )
        db.audit_logs.insert_one(log_entry.to_dict())

    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration (Admin only in production)"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        full_name = request.form.get('full_name')
        role = request.form.get('role', 'investigator')

        # Validate password
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('auth/register.html')

        is_strong, message = validate_password_strength(password)
        if not is_strong:
            flash(message, 'danger')
            return render_template('auth/register.html')

        db = get_db()

        # Check if username exists
        if db.users.find_one({'username': username}):
            flash('Username already exists', 'danger')
            return render_template('auth/register.html')

        # Check if email exists
        if db.users.find_one({'email': email}):
            flash('Email already exists', 'danger')
            return render_template('auth/register.html')

        # Create user
        user = User(
            username=username,
            email=email,
            password=password,
            role=role,
            full_name=full_name,
            mfa_enabled=False,
            status='active'
        )

        result = db.users.insert_one(user.to_dict())

        # Log registration
        log_entry = AuditLog(
            user_id=str(result.inserted_id),
            username=username,
            role=role,
            action='user_registered',
            ip_address=get_client_ip(),
            metadata={'email': email, 'full_name': full_name},
            previous_hash=get_last_audit_log_hash()
        )
        db.audit_logs.insert_one(log_entry.to_dict())

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html')


@auth_bp.route('/change-password', methods=['GET', 'POST'])
def change_password():
    """Change user password"""
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return render_template('auth/change_password.html')

        is_strong, message = validate_password_strength(new_password)
        if not is_strong:
            flash(message, 'danger')
            return render_template('auth/change_password.html')

        db = get_db()
        user = db.users.find_one({'_id': ObjectId(session['user_id'])})

        if not User.verify_password(user['password_hash'], current_password):
            flash('Current password is incorrect', 'danger')
            return render_template('auth/change_password.html')

        # Update password
        from werkzeug.security import generate_password_hash
        new_hash = generate_password_hash(new_password)

        db.users.update_one(
            {'_id': user['_id']},
            {'$set': {
                'password_hash': new_hash,
                'updated_at': datetime.utcnow()
            }}
        )

        # Log password change
        log_entry = AuditLog(
            user_id=session['user_id'],
            username=session['username'],
            role=session['role'],
            action='password_changed',
            ip_address=get_client_ip(),
            metadata={'changed_by': 'self'},
            previous_hash=get_last_audit_log_hash()
        )
        db.audit_logs.insert_one(log_entry.to_dict())

        flash('Password changed successfully!', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('auth/change_password.html')