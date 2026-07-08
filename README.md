# secure-qr-threat-detection

Secure QR-Based Intelligent Threat Detection Framework using Python, Flask, OpenCV and Machine Learning.

## Overview

This project detects malicious QR codes in real time using a machine learning classifier combined with a Flask-based web interface. Users can upload a QR code image or scan one via camera, and the system analyzes the embedded content to flag it as safe or malicious before the user interacts with it.

## Tech Stack

- **Backend:** Python, Flask
- **Computer Vision:** OpenCV (QR code detection and decoding)
- **Machine Learning:** Scikit-learn (feature-based classification)
- **Frontend:** HTML, Flask templates

## How It Works

1. User uploads a QR code image or scans one using the camera
2. OpenCV decodes the embedded URL/content
3. Extracted features (URL structure, domain reputation signals, etc.) are passed to the trained ML model
4. The model classifies the QR code as **Safe** or **Malicious**
5. Result is displayed on the dashboard with a clear visual indicator

## screenshots 

### Login Page

![Login Page](screenshots/login-page.png)

### Dashboard

![Dashboard](screenshots/dashboard.png)

### QR Scanner

![QR Scanner](screenshots/qr-scanner.png)

### Detection Result Safe

![Detection Result Safe](screenshots/detection-result.png)

### Detection Result Malicious
![Detection Result malicious](screenshots/detection-result_malicious.png)

### My Role
Machine Learning and Threat Detection Developer









