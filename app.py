import os
import io
import datetime
import pytz
from flask import Flask, render_template, redirect, url_for, g, send_file
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, get_jwt
from config import Config
from database import init_db, close_connection, get_db
from flask_talisman import Talisman

# Sri Lanka timezone (UTC+5:30)
SL_TZ = pytz.timezone('Asia/Colombo')

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Security Headers Check (Simplified for dev)
    # Talisman(app, content_security_policy=None)
    
    # Initialize JWT
    app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies']
    app.config['JWT_COOKIE_CSRF_PROTECT'] = False # For dev prototype
    jwt = JWTManager(app)

    @jwt.unauthorized_loader
    def unauthorized_callback(callback):
        return redirect('/auth/login', 302)
        
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return redirect('/auth/login', 302)

    # Register teardown
    app.teardown_appcontext(close_connection)

    # Initialize DB if it doesn't exist
    if not os.path.exists(app.config['DATABASE']):
        init_db(app)

    # Register Blueprints
    from auth.routes import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    from scanner.routes import scanner_bp
    app.register_blueprint(scanner_bp, url_prefix='/scanner')

    from admin.routes import admin_bp
    app.register_blueprint(admin_bp, url_prefix='/admin')

    @app.route('/')
    def index():
        return render_template('index.html')
        
    @app.route('/dashboard')
    @jwt_required()
    def dashboard():
        user_id = get_jwt_identity()
        claims = get_jwt()
        role = claims.get('role', 'user')
        db = get_db()
        
        # User's metrics
        total_scans = db.execute("SELECT COUNT(*) FROM scan_history WHERE user_id = ?", (user_id,)).fetchone()[0]
        safe_scans = db.execute("SELECT COUNT(*) FROM scan_history WHERE risk_level = 'Safe' AND user_id = ?", (user_id,)).fetchone()[0]
        malicious_scans = db.execute("SELECT COUNT(*) FROM scan_history WHERE risk_level = 'Malicious' AND user_id = ?", (user_id,)).fetchone()[0]

        # Scan frequency — using Sri Lanka time
        now_sl = datetime.datetime.now(SL_TZ)
        week_ago = (now_sl - datetime.timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
        month_start = now_sl.replace(day=1, hour=0, minute=0, second=0).strftime('%Y-%m-%d %H:%M:%S')

        scans_this_week = db.execute(
            "SELECT COUNT(*) FROM scan_history WHERE user_id = ? AND timestamp >= ?",
            (user_id, week_ago)
        ).fetchone()[0]

        scans_this_month = db.execute(
            "SELECT COUNT(*) FROM scan_history WHERE user_id = ? AND timestamp >= ?",
            (user_id, month_start)
        ).fetchone()[0]

        # Recent scans for user
        recent_scans = db.execute("SELECT * FROM scan_history WHERE user_id = ? ORDER BY timestamp DESC LIMIT 5", (user_id,)).fetchall()
        
        user = db.execute("SELECT first_name, email FROM users WHERE id = ?", (user_id,)).fetchone()
        
        return render_template('dashboard_user.html', 
                               user=user,
                               role=role,
                               total=total_scans, 
                               safe=safe_scans, 
                               malicious=malicious_scans,
                               scans=recent_scans,
                               scans_this_week=scans_this_week,
                               scans_this_month=scans_this_month)

    @app.route('/history')
    @jwt_required()
    def history():
        user_id = get_jwt_identity()
        claims = get_jwt()
        role = claims.get('role', 'user')
        db = get_db()
        
        all_scans = db.execute("SELECT * FROM scan_history WHERE user_id = ? ORDER BY timestamp DESC", (user_id,)).fetchall()
        user = db.execute("SELECT first_name, email FROM users WHERE id = ?", (user_id,)).fetchone()
        
        return render_template('history.html', scans=all_scans, role=role, user=user)

    @app.route('/download_my_report')
    @jwt_required()
    def download_my_report():
        """Lets a logged-in user download their full scan history as a text file."""
        user_id = get_jwt_identity()
        db = get_db()

        user = db.execute("SELECT first_name, last_name, email FROM users WHERE id = ?", (user_id,)).fetchone()
        all_scans = db.execute(
            "SELECT url, risk_level, risk_score, timestamp FROM scan_history WHERE user_id = ? ORDER BY timestamp DESC",
            (user_id,)
        ).fetchall()

        # Build the report text
        now_sl = datetime.datetime.now(SL_TZ)
        report = "SecureQR — My Scan Report\n"
        report += "=" * 40 + "\n"
        report += f"Generated: {now_sl.strftime('%Y-%m-%d %H:%M:%S')} (Sri Lanka Time)\n"
        report += f"User: {user['first_name']} {user['last_name']} ({user['email']})\n"
        report += "=" * 40 + "\n\n"

        if not all_scans:
            report += "No scan records found.\n"
        else:
            for scan in all_scans:
                report += f"Date     : {scan['timestamp']}\n"
                report += f"URL      : {scan['url']}\n"
                report += f"Risk     : {scan['risk_level']} (Score: {scan['risk_score']}/100)\n"
                report += "-" * 40 + "\n"

        # Send as downloadable file
        mem = io.BytesIO()
        mem.write(report.encode('utf-8'))
        mem.seek(0)

        filename = f"my_scan_report_{now_sl.strftime('%Y%m%d')}.txt"
        return send_file(mem, mimetype='text/plain', as_attachment=True, download_name=filename)

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5001)
