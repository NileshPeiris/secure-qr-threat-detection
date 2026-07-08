from flask import Blueprint, request, jsonify, render_template, current_app, redirect, url_for
import bcrypt
import pyotp
import qrcode
from io import BytesIO
import base64
from database import get_db, log_audit
from flask_jwt_extended import create_access_token, set_access_cookies, unset_jwt_cookies

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
        
    data = request.form if request.form else request.json
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'user') # Defaults to user
    
    if not email or not password or not first_name or not last_name:
        return jsonify({"msg": "All fields are required"}), 400
        
    import re
    if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$', password):
        return jsonify({"msg": "Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one number, and one special character."}), 400
        
    db = get_db()
    
    # Check if user exists
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if user:
        return jsonify({"msg": "User already exists"}), 400
        
    # Hash password
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # Generate TOTP Secret
    totp_secret = pyotp.random_base32()
    
    # Zero Trust: Admins are locked pending verification
    status = 'pending' if role == 'admin' else 'active'
    
    # Insert User
    cursor = db.execute(
        "INSERT INTO users (first_name, last_name, email, password_hash, totp_secret, role, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (first_name, last_name, email, hashed_pw, totp_secret, role, status)
    )
    db.commit()
    user_id = cursor.lastrowid
    
    log_audit(user_id, "User registration", f"User {email} successfully registered.")
    
    # Generate QR Code for Google Authenticator
    totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
        name=email,
        issuer_name=current_app.config['OTP_ISSUER_NAME']
    )
    
    img = qrcode.make(totp_uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode('utf-8')
    
    return jsonify({
        "msg": "User registered successfully.",
        "qr_code": img_str,
        "totp_secret": totp_secret
    }), 201

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
        
    data = request.form if request.form else request.json
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({"msg": "Missing credentials"}), 400
        
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        return jsonify({"msg": "Invalid credentials"}), 401
        
    if user['status'] == 'pending' and user['role'] == 'admin':
        return jsonify({"msg": "Your Administrator account is pending approval from current admins."}), 403
        
    # Create JWT Token
    access_token = create_access_token(
        identity=str(user['id']),
        additional_claims={"role": user['role']}
    )
    
    log_audit(user['id'], "Login", "Successful login.")
    
    resp = jsonify({
        "msg": "Login successful",
        "access_token": access_token,
        "role": user['role']
    })
    set_access_cookies(resp, access_token)
    return resp, 200

@auth_bp.route('/logout', methods=['POST'])
def logout():
    resp = jsonify({"msg": "Logout successful"})
    unset_jwt_cookies(resp)
    return resp, 200

from flask_jwt_extended import jwt_required, get_jwt_identity

@auth_bp.route('/verify-2fa', methods=['POST'])
@jwt_required()
def verify_2fa():
    """Verify a 2FA code before sensitive actions using the JWT token identity"""
    data = request.json
    otp = data.get('otp')
    
    if not otp:
        return jsonify({"msg": "OTP required"}), 400
        
    user_id = get_jwt_identity()
    db = get_db()
    
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    
    if not user:
        return jsonify({"msg": "User not found"}), 404
        
    totp = pyotp.TOTP(user['totp_secret'])
    if totp.verify(otp):
        return jsonify({"msg": "2FA Verification successful", "verified": True}), 200
    else:
        return jsonify({"msg": "Invalid 2FA code", "verified": False}), 401

import itsdangerous
from itsdangerous import URLSafeTimedSerializer

def get_reset_serializer():
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'])

@auth_bp.route('/verify-identity', methods=['POST'])
def verify_identity():
    """Step 1 of forgot-password: verify email exists + TOTP code is correct.
    Returns a short-lived signed reset token on success."""
    data = request.json
    email = data.get('email', '').strip()
    otp   = data.get('otp', '').strip()

    if not email or not otp:
        return jsonify({"msg": "Email and authenticator code are required."}), 400

    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if not user:
        # Intentionally vague to prevent user enumeration
        return jsonify({"msg": "No account found with that email."}), 404

    totp = pyotp.TOTP(user['totp_secret'])
    if not totp.verify(otp):
        return jsonify({"msg": "Invalid authenticator code. Please try again."}), 401

    # Issue a short-lived signed token (valid 10 minutes)
    s = get_reset_serializer()
    reset_token = s.dumps(email, salt='password-reset')

    log_audit(user['id'], "Password Reset Request", f"Identity verified for {email}.")
    return jsonify({"msg": "Identity verified.", "reset_token": reset_token}), 200


@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    """Step 2 of forgot-password: consume the reset token and update the password."""
    data        = request.json
    reset_token = data.get('reset_token', '')
    new_password = data.get('new_password', '')

    if not reset_token or not new_password:
        return jsonify({"msg": "Reset token and new password are required."}), 400

    if len(new_password) < 6:
        return jsonify({"msg": "Password must be at least 6 characters."}), 400

    s = get_reset_serializer()
    try:
        email = s.loads(reset_token, salt='password-reset', max_age=600)  # 10 min
    except itsdangerous.SignatureExpired:
        return jsonify({"msg": "Reset link expired. Please restart the process."}), 400
    except itsdangerous.BadSignature:
        return jsonify({"msg": "Invalid reset token."}), 400

    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not user:
        return jsonify({"msg": "User not found."}), 404

    hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    db.execute("UPDATE users SET password_hash = ? WHERE email = ?", (hashed_pw, email))
    db.commit()

    log_audit(user['id'], "Password Reset", f"Password successfully reset for {email}.")
    return jsonify({"msg": "Password reset successfully! You can now log in."}), 200
