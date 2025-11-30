from flask import Blueprint, render_template, session, redirect, url_for
from datetime import datetime, timedelta
from app import get_db
from app.utils import login_required

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    """Landing page"""
    if 'user_id' in session:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))


@main_bp.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard"""
    db = get_db()
    user_role = session.get('role')
    user_id = session.get('user_id')

    # Get user statistics based on role
    stats = {}

    # Common stats
    if user_role == 'admin':
        stats['total_users'] = db.users.count_documents({})
        stats['active_users'] = db.users.count_documents({'status': 'active'})
        stats['total_cases'] = db.cases.count_documents({})
        stats['total_evidence'] = db.evidence.count_documents({})
        stats['total_osint_queries'] = db.osint_queries.count_documents({})
        stats['open_anomalies'] = db.anomaly_alerts.count_documents({'status': 'open'})

    elif user_role == 'case_manager':
        stats['total_cases'] = db.cases.count_documents({})
        stats['my_cases'] = db.cases.count_documents({
            '$or': [
                {'created_by': user_id},
                {'assigned_to': user_id}
            ]
        })
        stats['open_cases'] = db.cases.count_documents({'status': 'open'})
        stats['in_progress_cases'] = db.cases.count_documents({'status': 'in_progress'})
        stats['open_anomalies'] = db.anomaly_alerts.count_documents({'status': 'open'})

    elif user_role == 'investigator':
        stats['my_cases'] = db.cases.count_documents({
            '$or': [
                {'created_by': user_id},
                {'assigned_to': user_id}
            ]
        })
        stats['evidence_uploaded'] = db.evidence.count_documents({'uploaded_by': user_id})
        stats['osint_queries'] = db.osint_queries.count_documents({'performed_by': user_id})

    elif user_role == 'osint_analyst':
        stats['my_cases'] = db.cases.count_documents({'assigned_to': user_id})
        stats['osint_queries'] = db.osint_queries.count_documents({'performed_by': user_id})
        stats['queries_today'] = db.osint_queries.count_documents({
            'performed_by': user_id,
            'performed_at': {'$gte': datetime.utcnow() - timedelta(days=1)}
        })

    elif user_role == 'legal_reviewer':
        stats['finalized_cases'] = db.cases.count_documents({'status': 'closed'})
        stats['pending_review'] = db.evidence.count_documents({
            'verified_by': None,
            'status': 'active'
        })

    # Get recent activity
    recent_logs = list(db.audit_logs.find()
                       .sort('timestamp', -1)
                       .limit(10))

    # Get recent cases
    if user_role in ['admin', 'case_manager']:
        recent_cases = list(db.cases.find()
                            .sort('created_at', -1)
                            .limit(5))
    else:
        recent_cases = list(db.cases.find({
            '$or': [
                {'created_by': user_id},
                {'assigned_to': user_id}
            ]
        }).sort('created_at', -1).limit(5))

    # Get recent anomalies (admin/case_manager only)
    recent_anomalies = []
    if user_role in ['admin', 'case_manager']:
        recent_anomalies = list(db.anomaly_alerts.find()
                                .sort('detected_at', -1)
                                .limit(5))

    # Get system health metrics (admin only)
    system_health = {}
    if user_role == 'admin':
        # Check audit log chain integrity
        logs_count = db.audit_logs.count_documents({})

        # Recent logins (last 24 hours)
        recent_logins = db.audit_logs.count_documents({
            'action': 'login',
            'timestamp': {'$gte': datetime.utcnow() - timedelta(days=1)}
        })

        # Failed logins (last 24 hours)
        failed_logins = db.audit_logs.count_documents({
            'action': 'failed_login',
            'timestamp': {'$gte': datetime.utcnow() - timedelta(days=1)}
        })

        system_health = {
            'audit_logs_count': logs_count,
            'recent_logins': recent_logins,
            'failed_logins': failed_logins,
            'database_status': 'Connected'
        }

    return render_template('dashboard.html',
                           stats=stats,
                           recent_logs=recent_logs,
                           recent_cases=recent_cases,
                           recent_anomalies=recent_anomalies,
                           system_health=system_health,
                           user_role=user_role)


@main_bp.route('/profile')
@login_required
def profile():
    """User profile page"""
    db = get_db()
    from bson import ObjectId

    user = db.users.find_one({'_id': ObjectId(session['user_id'])})

    if not user:
        return redirect(url_for('auth.logout'))

    # Get user statistics
    stats = {
        'cases_created': db.cases.count_documents({'created_by': session['user_id']}),
        'evidence_uploaded': db.evidence.count_documents({'uploaded_by': session['user_id']}),
        'osint_queries': db.osint_queries.count_documents({'performed_by': session['user_id']}),
        'login_count': db.audit_logs.count_documents({
            'user_id': session['user_id'],
            'action': 'login'
        })
    }

    # Get recent activity
    recent_activity = list(db.audit_logs.find({
        'user_id': session['user_id']
    }).sort('timestamp', -1).limit(20))

    return render_template('profile.html',
                           user=user,
                           stats=stats,
                           recent_activity=recent_activity)


@main_bp.route('/settings')
@login_required
def settings():
    """User settings page"""
    db = get_db()
    from bson import ObjectId

    user = db.users.find_one({'_id': ObjectId(session['user_id'])})

    return render_template('settings.html', user=user)


@main_bp.route('/help')
@login_required
def help_page():
    """Help and documentation page"""
    from app.config import Config

    role_permissions = Config.ROLE_PERMISSIONS

    return render_template('help.html', role_permissions=role_permissions)