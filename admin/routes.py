import io
import datetime
import pytz
from flask import Blueprint, render_template, jsonify, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from database import get_db, log_audit

# Sri Lanka timezone (UTC+5:30)
SL_TZ = pytz.timezone('Asia/Colombo')

admin_bp = Blueprint('admin', __name__)

def admin_required():
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return False
    return True

@admin_bp.route('/dashboard')
@jwt_required()
def dashboard():
    if not admin_required():
        return jsonify({"msg": "Admin access required"}), 403
        
    db = get_db()
    # Metrics
    total_scans = db.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
    safe_scans = db.execute("SELECT COUNT(*) FROM scan_history WHERE risk_level = 'Safe'").fetchone()[0]
    suspicious_scans = db.execute("SELECT COUNT(*) FROM scan_history WHERE risk_level = 'Suspicious'").fetchone()[0]
    malicious_scans = db.execute("SELECT COUNT(*) FROM scan_history WHERE risk_level = 'Malicious'").fetchone()[0]
    
    # Recent suspicious activity with user names
    logs = db.execute('''
        SELECT s.*, u.first_name, u.last_name 
        FROM scan_history s
        LEFT JOIN users u ON s.user_id = u.id
        WHERE s.risk_level != 'Safe' 
        ORDER BY s.timestamp DESC LIMIT 5
    ''').fetchall()
    
    # Check for pending admins waiting in the approval queue
    pending_admins = db.execute("SELECT COUNT(*) FROM users WHERE status = 'pending' AND role = 'admin'").fetchone()[0]
    
    return render_template('dashboard_admin.html', 
                           total=total_scans, 
                           safe=safe_scans, 
                           suspicious=suspicious_scans, 
                           malicious=malicious_scans,
                           logs=logs,
                           pending_admins=pending_admins)

@admin_bp.route('/users')
@jwt_required()
def users():
    if not admin_required():
        return jsonify({"msg": "Admin access required"}), 403
        
    db = get_db()
    all_users = db.execute("SELECT id, first_name, last_name, email, role, status, created_at FROM users").fetchall()
    
    total_users = len(all_users)
    regular_users = sum(1 for u in all_users if u['role'] == 'user')
    admins = sum(1 for u in all_users if u['role'] == 'admin')
    
    return render_template('admin_users.html', users=all_users, total=total_users, regular=regular_users, admins=admins)

@admin_bp.route('/approve_user/<int:user_id>', methods=['POST'])
@jwt_required()
def approve_user(user_id):
    if not admin_required():
        return jsonify({"success": False, "msg": "Admin access required"}), 403
        
    db = get_db()
    current_admin_id = get_jwt_identity()
    target = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    
    if not target:
        return jsonify({"success": False, "msg": "User not found"}), 404
    if target['status'] != 'pending':
        return jsonify({"success": False, "msg": "User is already active"}), 400
        
    # Promote to active status
    db.execute("UPDATE users SET status = 'active' WHERE id = ?", (user_id,))
    
    # Retain a formal audit log of which administrator approved this account
    log_audit(current_admin_id, "ADMIN_APPROVED", f"Administrator (ID: {current_admin_id}) officially approved new admin account {target['email']} (ID: {user_id})")
    db.commit()
    
    return jsonify({"success": True, "msg": f"Administrator {target['first_name']} successfully approved."})

@admin_bp.route('/delete_user/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    if not admin_required():
        return jsonify({"success": False, "msg": "Admin access required"}), 403
        
    db = get_db()
    current_admin_id = get_jwt_identity()
    
    # Prevent self-deletion
    if user_id == current_admin_id:
        return jsonify({"success": False, "msg": "Cannot delete your own administrator account"}), 400
        
    target = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not target:
        return jsonify({"success": False, "msg": "User not found"}), 404
        
    # Delete dependent child foreign key records first
    db.execute("DELETE FROM scan_history WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM audit_logs WHERE user_id = ?", (user_id,))
    
    # Delete actual user
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    
    log_audit(current_admin_id, "ADMIN_DELETED_USER", f"Deleted account {target['email']} (ID: {user_id})")
    db.commit()
    
    return jsonify({"success": True, "msg": f"Account {target['first_name']} deleted successfully."})

@admin_bp.route('/history')
@jwt_required()
def history():
    if not admin_required():
        return jsonify({"msg": "Admin access required"}), 403
        
    db = get_db()
    all_scans = db.execute("SELECT * FROM scan_history ORDER BY timestamp DESC").fetchall()
    
    # We pass role='admin' to reuse the history.html template
    return render_template('history.html', scans=all_scans, role='admin', user=None)

@admin_bp.route('/download_all_report')
@jwt_required()
def download_all_report():
    """Admin can download a full report of all scans across all users."""
    if not admin_required():
        return jsonify({"msg": "Admin access required"}), 403

    db = get_db()

    # Get all scans joined with user info
    all_scans = db.execute('''
        SELECT s.url, s.risk_level, s.risk_score, s.timestamp,
               u.first_name, u.last_name, u.email
        FROM scan_history s
        LEFT JOIN users u ON s.user_id = u.id
        ORDER BY s.timestamp DESC
    ''').fetchall()

    # Build the report text using Sri Lanka time
    now_sl = datetime.datetime.now(SL_TZ)
    report = "SecureQR — Full System Scan Report (Admin)\n"
    report += "=" * 50 + "\n"
    report += f"Generated: {now_sl.strftime('%Y-%m-%d %H:%M:%S')} (Sri Lanka Time)\n"
    report += f"Total Records: {len(all_scans)}\n"
    report += "=" * 50 + "\n\n"

    if not all_scans:
        report += "No scan records found.\n"
    else:
        for scan in all_scans:
            name = f"{scan['first_name']} {scan['last_name']}" if scan['first_name'] else "Unknown"
            report += f"User     : {name} ({scan['email']})\n"
            report += f"Date     : {scan['timestamp']}\n"
            report += f"URL      : {scan['url']}\n"
            report += f"Risk     : {scan['risk_level']} (Score: {scan['risk_score']}/100)\n"
            report += "-" * 50 + "\n"

    # Send as downloadable file
    mem = io.BytesIO()
    mem.write(report.encode('utf-8'))
    mem.seek(0)

    filename = f"all_scans_report_{now_sl.strftime('%Y%m%d')}.txt"
    return send_file(mem, mimetype='text/plain', as_attachment=True, download_name=filename)
