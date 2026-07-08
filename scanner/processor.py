import cv2
import numpy as np
from werkzeug.utils import secure_filename
import urllib.parse
import re

def process_qr_image(image_bytes):
    """
    Decodes a QR code from image bytes using OpenCV.
    Returns the extracted URL or None if not found.
    """
    # Convert bytes to numpy array
    nparr = np.frombuffer(image_bytes, np.uint8)
    
    # Decode image
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    
    if img is None:
        return None, "Invalid image format"
        
    # Initialize OpenCV QR detector
    detector = cv2.QRCodeDetector()
    
    # Detect and decode
    data, bbox, _ = detector.detectAndDecode(img)
    
    if not data:
        return None, "No QR Code detected"
        
    # Basic URL validation
    if not is_valid_url(data):
        return None, f"Extracted data is not a valid URL: {data[:50]}..."
        
    return data, "Success"

def is_valid_url(url):
    """Basic sanity check for a URL"""
    regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None
