from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from datetime import datetime
from bson import ObjectId
from app import get_db
from app.models import Case, AuditLog
from app.utils import (login_required, role_required, has_permission,
                       generate_case_number, get_client_ip, sanitize_input)

cases_bp = Blueprint('cases', __name__)


@cases_bp.route('/')
@login_required
def list_cases():
    """List all cases based on user role"""
    db = get_db()
    user_role = session.get('role')
    user_id = session.get('user_id')

    # Build query based on role
    query = {}

    if user_role == 'admin':
        # Admin can see all cases
        pass
    elif user_role == 'case_manager':
        # Case managers can see all cases
        pass
    elif user_role in ['investigator', 'osint_analyst']:
        # Investigators and analysts see assigned cases or created by them
        query = {
            '$or': [
                {'created_by': user_id},
                {'assigned_to': user_id}
            ]
        }
    elif user_role == 'legal_reviewer':
        # Legal reviewers see closed/finalized cases
        query = {'status': {'$in': ['closed', 'archived']}}

    cases = list(db.cases.find(query).sort('created_at', -1))

    # Get case statistics
    total_cases = db.cases.count_documents({})
    open_cases = db.cases.count_documents({'status': 'open'})
    in_progress_cases = db.cases.count_documents({'status': 'in_progress'})
    closed_cases = db.cases.count_documents({'status': 'closed'})

    stats = {
        'total': total_cases,
        'open': open_cases,
        'in_progress': in_progress_cases,
        'closed': closed_cases
    }

    return render_template('cases/list.html', cases=cases, stats=stats)


@cases_bp.route('/create', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'case_manager', 'investigator')
def create_case():
    """Create a new case"""
    db = get_db()

    if request.method == 'POST':
        title = sanitize_input(request.form.get('title'))
        description = sanitize_input(request.form.get('description'))
        priority = request.form.get('priority', 'medium')
        case_type = request.form.get('case_type', 'cybercrime')
        assigned_to = request.form.getlist('assigned_to')

        # Generate unique case number
        case_number = generate_case_number()

        # Create case
        case = Case(
            case_number=case_number,
            title=title,
            description=description,
            created_by=session['user_id'],
            assigned_to=assigned_to,
            priority=priority,
            case_type=case_type
        )

        result = db.cases.insert_one(case.to_dict())
        case_id = str(result.inserted_id)

        # Create directory structure for case evidence
        from app.utils import create_directory_structure
        create_directory_structure(case_id)

        # Log case creation
        log_entry = AuditLog(
            user_id=session['user_id'],
            username=session['username'],
            role=session['role'],
            action='case_created',
            ip_address=get_client_ip(),
            metadata={
                'case_id': case_id,
                'case_number': case_number,
                'title': title
            }
        )
        db.audit_logs.insert_one(log_entry.to_dict())

        flash(f'Case {case_number} created successfully!', 'success')
        return redirect(url_for('cases.view_case', case_id=case_id))

    # Get all users for assignment
    users = list(db.users.find({'status': 'active'}))

    return render_template('cases/create.html', users=users)


@cases_bp.route('/<case_id>')
@login_required
def view_case(case_id):
    """View case details"""
    db = get_db()

    try:
        case = db.cases.find_one({'_id': ObjectId(case_id)})
    except:
        flash('Invalid case ID', 'danger')
        return redirect(url_for('cases.list_cases'))

    if not case:
        flash('Case not found', 'danger')
        return redirect(url_for('cases.list_cases'))

    # Check access permissions
    user_role = session.get('role')
    user_id = session.get('user_id')

    if user_role not in ['admin', 'case_manager']:
        if case['created_by'] != user_id and user_id not in case.get('assigned_to', []):
            if user_role == 'legal_reviewer' and case['status'] not in ['closed', 'archived']:
                flash('You do not have permission to view this case', 'danger')
                return redirect(url_for('cases.list_cases'))

    # Get evidence for this case
    evidence_list = list(db.evidence.find({'case_id': case_id}))

    # Get OSINT queries for this case
    osint_queries = list(db.osint_queries.find({'case_id': case_id}).sort('performed_at', -1))

    # Get case timeline (audit logs)
    timeline = list(db.audit_logs.find({
        'metadata.case_id': case_id
    }).sort('timestamp', -1).limit(50))

    # Get assigned users
    assigned_users = []
    if case.get('assigned_to'):
        assigned_users = list(db.users.find({
            '_id': {'$in': [ObjectId(uid) for uid in case['assigned_to']]}
        }))

    # Get creator
    creator = db.users.find_one({'_id': ObjectId(case['created_by'])})

    return render_template('cases/view.html',
                           case=case,
                           evidence_list=evidence_list,
                           osint_queries=osint_queries,
                           timeline=timeline,
                           assigned_users=assigned_users,
                           creator=creator)


@cases_bp.route('/<case_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'case_manager')
def edit_case(case_id):
    """Edit case details"""
    db = get_db()

    try:
        case = db.cases.find_one({'_id': ObjectId(case_id)})
    except:
        flash('Invalid case ID', 'danger')
        return redirect(url_for('cases.list_cases'))

    if not case:
        flash('Case not found', 'danger')
        return redirect(url_for('cases.list_cases'))

    if request.method == 'POST':
        title = sanitize_input(request.form.get('title'))
        description = sanitize_input(request.form.get('description'))
        priority = request.form.get('priority')
        status = request.form.get('status')
        assigned_to = request.form.getlist('assigned_to')

        update_data = {
            'title': title,
            'description': description,
            'priority': priority,
            'status': status,
            'assigned_to': assigned_to,
            'updated_at': datetime.utcnow()
        }

        if status == 'closed':
            update_data['closed_at'] = datetime.utcnow()

        db.cases.update_one(
            {'_id': ObjectId(case_id)},
            {'$set': update_data}
        )

        # Log case update
        log_entry = AuditLog(
            user_id=session['user_id'],
            username=session['username'],
            role=session['role'],
            action='case_updated',
            ip_address=get_client_ip(),
            metadata={
                'case_id': case_id,
                'case_number': case['case_number'],
                'changes': {
                    'status': status,
                    'priority': priority
                }
            }
        )
        db.audit_logs.insert_one(log_entry.to_dict())

        flash('Case updated successfully!', 'success')
        return redirect(url_for('cases.view_case', case_id=case_id))

    # Get all users for assignment
    users = list(db.users.find({'status': 'active'}))

    return render_template('cases/edit.html', case=case, users=users)


@cases_bp.route('/<case_id>/add-note', methods=['POST'])
@login_required
def add_note(case_id):
    """Add a note to the case"""
    db = get_db()

    note_text = sanitize_input(request.form.get('note'))

    if not note_text:
        flash('Note cannot be empty', 'danger')
        return redirect(url_for('cases.view_case', case_id=case_id))

    note = {
        'text': note_text,
        'added_by': session['user_id'],
        'username': session['username'],
        'added_at': datetime.utcnow()
    }

    db.cases.update_one(
        {'_id': ObjectId(case_id)},
        {'$push': {'notes': note}}
    )

    # Log note addition
    log_entry = AuditLog(
        user_id=session['user_id'],
        username=session['username'],
        role=session['role'],
        action='case_note_added',
        ip_address=get_client_ip(),
        metadata={
            'case_id': case_id,
            'note_preview': note_text[:100]
        }
    )
    db.audit_logs.insert_one(log_entry.to_dict())

    flash('Note added successfully!', 'success')
    return redirect(url_for('cases.view_case', case_id=case_id))


@cases_bp.route('/<case_id>/add-tag', methods=['POST'])
@login_required
def add_tag(case_id):
    """Add a tag to the case"""
    db = get_db()

    tag = sanitize_input(request.form.get('tag'))

    if not tag:
        flash('Tag cannot be empty', 'danger')
        return redirect(url_for('cases.view_case', case_id=case_id))

    db.cases.update_one(
        {'_id': ObjectId(case_id)},
        {'$addToSet': {'tags': tag.lower()}}
    )

    flash('Tag added successfully!', 'success')
    return redirect(url_for('cases.view_case', case_id=case_id))


@cases_bp.route('/<case_id>/delete', methods=['POST'])
@login_required
@role_required('admin')
def delete_case(case_id):
    """Delete a case (admin only)"""
    db = get_db()

    case = db.cases.find_one({'_id': ObjectId(case_id)})

    if not case:
        flash('Case not found', 'danger')
        return redirect(url_for('cases.list_cases'))

    # Archive instead of delete
    db.cases.update_one(
        {'_id': ObjectId(case_id)},
        {'$set': {
            'status': 'archived',
            'updated_at': datetime.utcnow()
        }}
    )

    # Log case archival
    log_entry = AuditLog(
        user_id=session['user_id'],
        username=session['username'],
        role=session['role'],
        action='case_archived',
        ip_address=get_client_ip(),
        metadata={
            'case_id': case_id,
            'case_number': case['case_number']
        }
    )
    db.audit_logs.insert_one(log_entry.to_dict())

    flash('Case archived successfully!', 'success')
    return redirect(url_for('cases.list_cases'))


@cases_bp.route('/search')
@login_required
def search_cases():
    """Search cases"""
    db = get_db()

    query_text = request.args.get('q', '')

    if not query_text:
        return redirect(url_for('cases.list_cases'))

    # Search in title, description, case number, and tags
    search_query = {
        '$or': [
            {'title': {'$regex': query_text, '$options': 'i'}},
            {'description': {'$regex': query_text, '$options': 'i'}},
            {'case_number': {'$regex': query_text, '$options': 'i'}},
            {'tags': {'$regex': query_text, '$options': 'i'}}
        ]
    }

    cases = list(db.cases.find(search_query).sort('created_at', -1))

    return render_template('cases/search_results.html',
                           cases=cases,
                           query=query_text)