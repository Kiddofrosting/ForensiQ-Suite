from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from datetime import datetime
from bson import ObjectId
from app import get_db
from app.models import OSINTQuery, AuditLog
from app.utils import login_required, role_required, get_client_ip, sanitize_input
from app.osint.osint_tools import osint_tools

osint_bp = Blueprint('osint', __name__)


@osint_bp.route('/dashboard')
@login_required
@role_required('admin', 'case_manager', 'investigator', 'osint_analyst')
def dashboard():
    """OSINT dashboard"""
    db = get_db()

    # Get recent OSINT queries
    recent_queries = list(db.osint_queries.find().sort('performed_at', -1).limit(20))

    # Get statistics
    total_queries = db.osint_queries.count_documents({})
    user_queries = db.osint_queries.count_documents({'performed_by': session['user_id']})

    stats = {
        'total': total_queries,
        'user': user_queries,
        'by_type': {}
    }

    # Count by type
    for query_type in ['whois', 'dns', 'ip', 'email', 'url', 'file', 'username']:
        count = db.osint_queries.count_documents({'query_type': query_type})
        stats['by_type'][query_type] = count

    return render_template('osint/dashboard.html',
                           recent_queries=recent_queries,
                           stats=stats)


@osint_bp.route('/query/<case_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'case_manager', 'investigator', 'osint_analyst')
def perform_query(case_id):
    """Perform OSINT query"""
    db = get_db()

    # Verify case exists
    case = db.cases.find_one({'_id': ObjectId(case_id)})
    if not case:
        flash('Case not found', 'danger')
        return redirect(url_for('cases.list_cases'))

    if request.method == 'POST':
        query_type = request.form.get('query_type')
        query_term = sanitize_input(request.form.get('query_term'))

        if not query_term:
            flash('Query term cannot be empty', 'danger')
            return render_template('osint/query.html', case=case)

        # Create OSINT query record
        osint_query = OSINTQuery(
            case_id=case_id,
            query_type=query_type,
            query_term=query_term,
            performed_by=session['user_id']
        )

        try:
            # Perform the appropriate OSINT lookup
            if query_type == 'whois':
                results = osint_tools.whois_lookup(query_term)
            elif query_type == 'dns':
                results = osint_tools.dns_lookup(query_term)
            elif query_type == 'ip':
                results = osint_tools.ip_lookup(query_term)
            elif query_type == 'email':
                results = osint_tools.email_lookup(query_term)
            elif query_type == 'url':
                results = osint_tools.url_analysis(query_term)
            elif query_type == 'file':
                # For file hash lookup
                results = osint_tools.file_hash_lookup(query_term)
            elif query_type == 'username':
                results = osint_tools.username_lookup(query_term)
            else:
                results = {'error': 'Invalid query type'}

            osint_query.results = results
            osint_query.status = 'completed' if 'error' not in results else 'failed'
            osint_query.error_message = results.get('error')

        except Exception as e:
            osint_query.status = 'failed'
            osint_query.error_message = str(e)
            osint_query.results = {'error': str(e)}

        # Save query
        result = db.osint_queries.insert_one(osint_query.to_dict())
        query_id = str(result.inserted_id)

        # Update case with OSINT query reference
        db.cases.update_one(
            {'_id': ObjectId(case_id)},
            {'$push': {'osint_query_ids': query_id}}
        )

        # Log OSINT query
        log_entry = AuditLog(
            user_id=session['user_id'],
            username=session['username'],
            role=session['role'],
            action='osint_query_performed',
            ip_address=get_client_ip(),
            metadata={
                'case_id': case_id,
                'query_id': query_id,
                'query_type': query_type,
                'query_term': query_term,
                'status': osint_query.status
            }
        )
        db.audit_logs.insert_one(log_entry.to_dict())

        if osint_query.status == 'completed':
            flash(f'OSINT query completed successfully!', 'success')
        else:
            flash(f'OSINT query failed: {osint_query.error_message}', 'danger')

        return redirect(url_for('osint.view_query', query_id=query_id))

    return render_template('osint/query.html', case=case)


@osint_bp.route('/view/<query_id>')
@login_required
def view_query(query_id):
    """View OSINT query results"""
    db = get_db()

    try:
        query = db.osint_queries.find_one({'_id': ObjectId(query_id)})
    except:
        flash('Invalid query ID', 'danger')
        return redirect(url_for('osint.dashboard'))

    if not query:
        flash('Query not found', 'danger')
        return redirect(url_for('osint.dashboard'))

    # Get case details
    case = db.cases.find_one({'_id': ObjectId(query['case_id'])})

    # Log query view
    log_entry = AuditLog(
        user_id=session['user_id'],
        username=session['username'],
        role=session['role'],
        action='osint_results_viewed',
        ip_address=get_client_ip(),
        metadata={
            'case_id': query['case_id'],
            'query_id': query_id,
            'query_type': query['query_type']
        }
    )
    db.audit_logs.insert_one(log_entry.to_dict())

    return render_template('osint/view_results.html', query=query, case=case)


@osint_bp.route('/bulk-query/<case_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'osint_analyst')
def bulk_query(case_id):
    """Perform bulk OSINT queries"""
    db = get_db()

    case = db.cases.find_one({'_id': ObjectId(case_id)})
    if not case:
        flash('Case not found', 'danger')
        return redirect(url_for('cases.list_cases'))

    if request.method == 'POST':
        query_type = request.form.get('query_type')
        query_terms = request.form.get('query_terms').strip().split('\n')

        results_summary = {
            'total': len(query_terms),
            'successful': 0,
            'failed': 0,
            'query_ids': []
        }

        for term in query_terms:
            term = term.strip()
            if not term:
                continue

            osint_query = OSINTQuery(
                case_id=case_id,
                query_type=query_type,
                query_term=term,
                performed_by=session['user_id']
            )

            try:
                if query_type == 'whois':
                    results = osint_tools.whois_lookup(term)
                elif query_type == 'dns':
                    results = osint_tools.dns_lookup(term)
                elif query_type == 'ip':
                    results = osint_tools.ip_lookup(term)
                elif query_type == 'email':
                    results = osint_tools.email_lookup(term)
                else:
                    results = {'error': 'Unsupported bulk query type'}

                osint_query.results = results
                osint_query.status = 'completed' if 'error' not in results else 'failed'

                if osint_query.status == 'completed':
                    results_summary['successful'] += 1
                else:
                    results_summary['failed'] += 1

            except Exception as e:
                osint_query.status = 'failed'
                osint_query.error_message = str(e)
                results_summary['failed'] += 1

            result = db.osint_queries.insert_one(osint_query.to_dict())
            results_summary['query_ids'].append(str(result.inserted_id))

        # Log bulk query
        log_entry = AuditLog(
            user_id=session['user_id'],
            username=session['username'],
            role=session['role'],
            action='osint_bulk_query',
            ip_address=get_client_ip(),
            metadata={
                'case_id': case_id,
                'query_type': query_type,
                'total_queries': results_summary['total'],
                'successful': results_summary['successful'],
                'failed': results_summary['failed']
            }
        )
        db.audit_logs.insert_one(log_entry.to_dict())

        flash(f"Bulk query completed: {results_summary['successful']} successful, "
              f"{results_summary['failed']} failed", 'info')

        return redirect(url_for('cases.view_case', case_id=case_id))

    return render_template('osint/bulk_query.html', case=case)


@osint_bp.route('/api/quick-lookup', methods=['POST'])
@login_required
def quick_lookup():
    """Quick OSINT lookup (AJAX endpoint)"""
    data = request.get_json()
    query_type = data.get('type')
    query_term = data.get('term')

    if not query_type or not query_term:
        return jsonify({'error': 'Missing parameters'}), 400

    try:
        if query_type == 'whois':
            results = osint_tools.whois_lookup(query_term)
        elif query_type == 'dns':
            results = osint_tools.dns_lookup(query_term)
        elif query_type == 'ip':
            results = osint_tools.ip_lookup(query_term)
        elif query_type == 'email':
            results = osint_tools.email_lookup(query_term)
        else:
            return jsonify({'error': 'Invalid query type'}), 400

        # Log quick lookup
        db = get_db()
        log_entry = AuditLog(
            user_id=session['user_id'],
            username=session['username'],
            role=session['role'],
            action='osint_quick_lookup',
            ip_address=get_client_ip(),
            metadata={
                'query_type': query_type,
                'query_term': query_term
            }
        )
        db.audit_logs.insert_one(log_entry.to_dict())

        return jsonify(results)

    except Exception as e:
        return jsonify({'error': str(e)}), 500