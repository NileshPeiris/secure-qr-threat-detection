import os
import secrets
from dotenv import load_dotenv

# Load nearest .env file automatically
load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'secureqr-fallback-flask-key'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'secureqr-fallback-jwt-key'
    DATABASE = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'qr_scanner.db')
    
    # Live APIs loaded directly from .env file
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
    GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_API_KEY')
    
    # 2FA Settings
    OTP_ISSUER_NAME = 'SecureQR Threat System'
