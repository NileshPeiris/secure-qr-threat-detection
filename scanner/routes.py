import urllib.parse
from flask import Blueprint, request, jsonify, render_template, send_file, redirect, url_for
from flask_jwt_extended import get_jwt_identity, jwt_required, verify_jwt_in_request
from scanner.processor import process_qr_image
from threat_engine.aggregator import evaluate_url
from database import get_db, log_audit
import json
import io
import datetime
scanner_bp = Blueprint('scanner', __name__)

@scanner_bp.route('/', methods=['GET', 'POST'])
@jwt_required() # Force auth for scan page
def scan_page():
    if request.method == 'GET':
        return render_template('scan.html')
        
    if 'qr_image' not in request.files:
        return jsonify({"msg": "No file parameter 'qr_image' found"}), 400
        
    file = request.files['qr_image']
    if file.filename == '':
        return jsonify({"msg": "No selected file"}), 400
        
    # Read the image content
    img_bytes = file.read()
    
    # Process QR
    url, message = process_qr_image(img_bytes)
    
    if not url:
        return jsonify({"msg": message}), 400
        
    # Evaluate URL through Threat Engine
    eval_result = evaluate_url(url)
    
    # Optional context for logging
    user_id = None
    try:
        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity()
    except Exception:
        pass

    # Save History if User is Logged In
    if user_id:
        db = get_db()
        details_json = json.dumps(eval_result['details'])
        db.execute(
            "INSERT INTO scan_history (user_id, url, risk_score, risk_level, scan_details) VALUES (?, ?, ?, ?, ?)",
            (user_id, url, eval_result['risk_score'], eval_result['risk_level'], details_json)
        )
        db.commit()
    
    # Return context to the result page/JSON
    if request.headers.get('Accept') == 'application/json':
        return jsonify({
            "url": url,
            "risk_score": eval_result['risk_score'],
            "risk_level": eval_result['risk_level'],
            "details": eval_result['details']
        }), 200
        
    # Otherwise render template
    return render_template(
        'result.html', 
        url=url, 
        encoded_url=urllib.parse.quote(url, safe=''),
        risk_score=eval_result['risk_score'],
        risk_level=eval_result['risk_level'],
        details=eval_result['details']
    )

@scanner_bp.route('/process_url', methods=['POST'])
def process_url():
    """Endpoint for handling URLs directly scanned from the frontend camera"""
    # The frontend form uses 'scanned_url'
    url = request.form.get('scanned_url', '').strip()
    
    if not url:
        return jsonify({"msg": "No scanned_url provided"}), 400

    # Backend URL validation
    parsed = urllib.parse.urlparse(url)
    if not all([parsed.scheme, parsed.netloc]) or parsed.scheme not in ['http', 'https']:
        from flask import flash
        flash("Invalid URL format. Please include http:// or https://", "error")
        return redirect(url_for('scanner.scan_page'))
        
    # Standard evaluation logic
    eval_result = evaluate_url(url)
    
    user_id = None
    try:
        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity()
    except Exception:
        pass

    if user_id:
        db = get_db()
        details_json = json.dumps(eval_result['details'])
        db.execute(
            "INSERT INTO scan_history (user_id, url, risk_score, risk_level, scan_details) VALUES (?, ?, ?, ?, ?)",
            (user_id, url, eval_result['risk_score'], eval_result['risk_level'], details_json)
        )
        db.commit()
    
    return render_template(
        'result.html', 
        url=url, 
        encoded_url=urllib.parse.quote(url, safe=''),
        risk_score=eval_result['risk_score'],
        risk_level=eval_result['risk_level'],
        details=eval_result['details']
    )

import base64

@scanner_bp.route('/process_frame', methods=['POST'])
def process_frame():
    """Endpoint for processing base64 image frames from webcam using OpenCV"""
    data = request.json
    if not data or 'image' not in data:
        return jsonify({"msg": "No image provided"}), 400
        
    image_data = data['image']
    try:
        # Extract base64 part
        if ',' in image_data:
            image_data = image_data.split(',')[1]
        
        img_bytes = base64.b64decode(image_data)
        
        # Process QR using OpenCV
        url, message = process_qr_image(img_bytes)
        
        if url:
            return jsonify({"success": True, "url": url}), 200
        else:
            return jsonify({"success": False, "msg": message}), 200
            
    except Exception as e:
        return jsonify({"success": False, "msg": str(e)}), 400

@scanner_bp.route('/download_report', methods=['POST'])
def download_report():
    url = request.form.get('url', 'Unknown URL')
    risk_level = request.form.get('risk_level', 'Unknown')
    risk_score = request.form.get('risk_score', '0')
    
    report_text = f"SecureQR Threat Detection Report\n================================\n"
    report_text += f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    report_text += f"[URL Details]\n"
    report_text += f"Scanned URL: {url}\n"
    report_text += f"Overall Risk Level: {risk_level}\n"
    report_text += f"Risk Score: {risk_score}/100\n\n"
    report_text += f"[Security Checks Summary]\n"
    report_text += f"- Machine Learning (Phishing/Malware) Evaluation processed.\n"
    report_text += f"- Google Safe Browsing and VirusTotal reputation factors integrated.\n\n"
    report_text += f"* Note: This is an automatically generated report out of SecureQR *\n"

    # Create an in-memory file
    mem = io.BytesIO()
    mem.write(report_text.encode('utf-8'))
    mem.seek(0)
    
    return send_file(
        mem,
        mimetype='text/plain',
        as_attachment=True,
        download_name=f"threat_report_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.txt"
    )

@scanner_bp.route('/report_url', methods=['POST'])
def report_url():
    url = request.form.get('url')
    if not url:
        return jsonify({"success": False, "msg": "No URL provided"}), 400
        
    user_id = None
    try:
        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity()
    except Exception:
        pass
        
    db = get_db()
    # Log the action in audit_logs so admins see it
    details = f"User explicitly reported URL as malicious/blocked: {url}"
    db.execute(
        "INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)",
        (user_id, "REPORT_MALICIOUS_URL", details)
    )
    db.commit()
    
    return jsonify({"success": True, "msg": "URL has been successfully reported to administrators."})
