from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from datetime import datetime, timedelta
from bson import ObjectId
from app import get_db
from app.models import AnomalyAlert, AuditLog
from app.utils import login_required, role_required, get_client_ip
try:
    from app.ml.anomaly_detector import anomaly_detector
except ImportError:
    # Fallback if module structure is different
    from anomaly_detector import anomaly_detector
ml_bp = Blueprint('ml', __name__)


@ml_bp.route('/anomalies')
@login_required
@role_required('admin', 'case_manager')
def list_anomalies():
    """List all anomaly alerts"""
    db = get_db()

    # Get filter parameters
    status_filter = request.args.get('status', 'open')
    user_filter = request.args.get('user')

    query = {}
    if status_filter != 'all':
        query['status'] = status_filter

    if user_filter:
        query['user_id'] = user_filter

    # Get anomalies
    anomalies = list(db.anomaly_alerts.find(query).sort('detected_at', -1))

    # Get statistics
    stats = {
        'total': db.anomaly_alerts.count_documents({}),
        'open': db.anomaly_alerts.count_documents({'status': 'open'}),
        'investigating': db.anomaly_alerts.count_documents({'status': 'investigating'}),
        'resolved': db.anomaly_alerts.count_documents({'status': 'resolved'}),
        'false_positive': db.anomaly_alerts.count_documents({'status': 'false_positive'})
    }

    # Get all users for filter
    users = list(db.users.find({}, {'username': 1, 'full_name': 1}))

    return render_template('ml/anomalies.html',
                           anomalies=anomalies,
                           stats=stats,
                           users=users,
                           current_status=status_filter)


@ml_bp.route('/anomaly/<anomaly_id>')
@login_required
@role_required('admin', 'case_manager')
def view_anomaly(anomaly_id):
    """View anomaly details"""
    db = get_db()

    try:
        anomaly = db.anomaly_alerts.find_one({'_id': ObjectId(anomaly_id)})
    except:
        flash('Invalid anomaly ID', 'danger')
        return redirect(url_for('ml.list_anomalies'))

    if not anomaly:
        flash('Anomaly not found', 'danger')
        return redirect(url_for('ml.list_anomalies'))

    # Get user details
    user = db.users.find_one({'_id': ObjectId(anomaly['user_id'])})

    # Get related audit logs
    audit_logs = []
    if anomaly.get('audit_log_ids'):
        audit_logs = list(db.audit_logs.find({
            '_id': {'$in': [ObjectId(log_id) for log_id in anomaly['audit_log_ids']]}
        }).sort('timestamp', -1))

    # Get recent user activity
    recent_activity = list(db.audit_logs.find({
        'user_id': anomaly['user_id']
    }).sort('timestamp', -1).limit(50))

    return render_template('ml/view_anomaly.html',
                           anomaly=anomaly,
                           user=user,
                           audit_logs=audit_logs,
                           recent_activity=recent_activity)


@ml_bp.route('/anomaly/<anomaly_id>/update', methods=['POST'])
@login_required
@role_required('admin', 'case_manager')
def update_anomaly(anomaly_id):
    """Update anomaly status"""
    db = get_db()

    status = request.form.get('status')
    notes = request.form.get('notes', '')

    update_data = {
        'status': status,
        'investigated_by': session['user_id'],
        'investigated_at': datetime.utcnow(),
        'resolution_notes': notes
    }

    db.anomaly_alerts.update_one(
        {'_id': ObjectId(anomaly_id)},
        {'$set': update_data}
    )

    # Log anomaly investigation
    anomaly = db.anomaly_alerts.find_one({'_id': ObjectId(anomaly_id)})

    log_entry = AuditLog(
        user_id=session['user_id'],
        username=session['username'],
        role=session['role'],
        action='anomaly_investigated',
        ip_address=get_client_ip(),
        metadata={
            'anomaly_id': anomaly_id,
            'anomaly_type': anomaly['anomaly_type'],
            'affected_user': anomaly['username'],
            'status': status
        }
    )
    db.audit_logs.insert_one(log_entry.to_dict())

    flash('Anomaly updated successfully!', 'success')
    return redirect(url_for('ml.view_anomaly', anomaly_id=anomaly_id))


@ml_bp.route('/run-detection', methods=['POST'])
@login_required
@role_required('admin')
def run_detection():
    """Manually trigger anomaly detection"""
    try:
        # Run anomaly detection
        results = anomaly_detector.detect_anomalies()

        flash(f"Anomaly detection completed: {results['anomalies_detected']} new anomalies detected",
              'info')

    except Exception as e:
        flash(f'Error running anomaly detection: {str(e)}', 'danger')

    return redirect(url_for('ml.list_anomalies'))


@ml_bp.route('/dashboard')
@login_required
@role_required('admin', 'case_manager')
def dashboard():
    """ML/Anomaly detection dashboard"""
    db = get_db()

    # Get recent anomalies
    recent_anomalies = list(db.anomaly_alerts.find().sort('detected_at', -1).limit(10))

    # Get statistics by type
    anomaly_types = {}
    for anomaly_type in ['login_pattern', 'access_pattern', 'osint_abuse', 'evidence_access']:
        count = db.anomaly_alerts.count_documents({'anomaly_type': anomaly_type})
        anomaly_types[anomaly_type] = count

    # Get anomalies over time (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    anomalies_by_day = []

    for i in range(30):
        day = thirty_days_ago + timedelta(days=i)
        next_day = day + timedelta(days=1)

        count = db.anomaly_alerts.count_documents({
            'detected_at': {
                '$gte': day,
                '$lt': next_day
            }
        })

        anomalies_by_day.append({
            'date': day.strftime('%Y-%m-%d'),
            'count': count
        })

    # Get users with most anomalies
    pipeline = [
        {'$group': {
            '_id': '$user_id',
            'count': {'$sum': 1},
            'username': {'$first': '$username'}
        }},
        {'$sort': {'count': -1}},
        {'$limit': 10}
    ]

    top_users = list(db.anomaly_alerts.aggregate(pipeline))

    stats = {
        'total_anomalies': db.anomaly_alerts.count_documents({}),
        'open_anomalies': db.anomaly_alerts.count_documents({'status': 'open'}),
        'anomaly_types': anomaly_types,
        'anomalies_by_day': anomalies_by_day,
        'top_users': top_users
    }

    return render_template('ml/dashboard.html',
                           recent_anomalies=recent_anomalies,
                           stats=stats)


@ml_bp.route('/api/anomaly-stats')
@login_required
@role_required('admin', 'case_manager')
def anomaly_stats():
    """Get anomaly statistics (AJAX endpoint)"""
    db = get_db()

    days = int(request.args.get('days', 7))
    start_date = datetime.utcnow() - timedelta(days=days)

    stats = {
        'total': db.anomaly_alerts.count_documents({'detected_at': {'$gte': start_date}}),
        'by_type': {},
        'by_status': {}
    }

    # Count by type
    for anomaly_type in ['login_pattern', 'access_pattern', 'osint_abuse', 'evidence_access']:
        count = db.anomaly_alerts.count_documents({
            'anomaly_type': anomaly_type,
            'detected_at': {'$gte': start_date}
        })
        stats['by_type'][anomaly_type] = count

    # Count by status
    for status in ['open', 'investigating', 'resolved', 'false_positive']:
        count = db.anomaly_alerts.count_documents({
            'status': status,
            'detected_at': {'$gte': start_date}
        })
        stats['by_status'][status] = count

    return jsonify(stats)

print("🔍 Debugging ML Module Import")
try:
    from app.ml.anomaly_detector import anomaly_detector
    print(f"✅ Successfully imported: {type(anomaly_detector)}")
    print(f"✅ Has detect_anomalies: {hasattr(anomaly_detector, 'detect_anomalies')}")
    print(f"✅ Available methods: {[m for m in dir(anomaly_detector) if not m.startswith('_')]}")
except Exception as e:
    print(f"❌ Import failed: {e}")
    import traceback
    traceback.print_exc()