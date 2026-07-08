import json
from threat_engine.models import predict_url_ml, get_ml_risk_score
from threat_engine.apis import check_virustotal, check_google_safe_browsing
from database import get_db

def calculate_virus_total_boost(vt_detections):
    if vt_detections == 0:
        return 0
    elif vt_detections == 1:
        return 8
    elif vt_detections == 2:
        return 15
    elif 3 <= vt_detections <= 5:
        return 25
    else:
        return 35

def calculate_risk_score(phishing_prob, malware_prob, keyword_count, vt_detections, vt_total, gsb_safe):
    # Base variables
    max_ml = max(phishing_prob, malware_prob)
    final_score = 0
    
    # ML contribution
    if max_ml >= 0.80:
        final_score += 45
    elif max_ml >= 0.60:
        final_score += 30
    elif max_ml >= 0.40:
        final_score += 15
    else:
        final_score += 5
        
    # Malware bonus
    if malware_prob >= 0.60:
        final_score += 10
        
    # Keyword contribution
    final_score += min(12, keyword_count * 3)
    
    # VirusTotal contribution
    if vt_total > 0:
        if vt_detections >= 5:
            final_score += 35
        elif vt_detections >= 3:
            final_score += 25
        elif vt_detections >= 1:
            final_score += 15
            
    # Google Safe Browsing
    if not gsb_safe:
        final_score += 20
        if final_score < 75:
            final_score = 75
            
    return min(100, final_score)

def determine_final_label(score, phishing_prob, malware_prob, vt_detections, gsb_safe):
    # Google Safe Browsing strong escalation
    if not gsb_safe:
        return "Malicious"

    # ML classification if confidence is high
    if malware_prob >= phishing_prob and malware_prob >= 0.60:
        return "Malware"
    elif phishing_prob > malware_prob and phishing_prob >= 0.60:
        return "Phishing"

    # Fallback to VirusTotal if ML confidence is low
    if phishing_prob < 0.60 and malware_prob < 0.60:
        if vt_detections >= 3:
            return "Malware"
        elif vt_detections >= 1:
            return "Suspicious"
        elif vt_detections == 0:
            if score >= 60:
                return "Malicious"
            elif score >= 25:
                return "Suspicious"
            else:
                return "Safe"

    if score < 25:
        return "Safe"
    elif score < 60:
        return "Suspicious"
    else:
        return "Malicious"

def classify_risk(score):
    if score < 25:
        return "Safe"
    elif score < 60:
        return "Suspicious"
    else:
        return "Malicious"

def generate_explainability(phishing_score, malware_score, vt_detections, gsb_safe, keyword_count, risk_level):
    reasons = []
    
    if malware_score >= 85:
        reasons.append(f"High malware detection confidence ({int(malware_score)}%)")
    elif malware_score > 50:
        reasons.append(f"Suspicious malware signs detected ({int(malware_score)}%)")
        
    if phishing_score >= 85:
        reasons.append(f"High phishing detection confidence ({int(phishing_score)}%)")
    elif phishing_score > 50:
        reasons.append(f"Suspicious phishing signs detected ({int(phishing_score)}%)")
        
    if vt_detections > 0:
        reasons.append(f"VirusTotal reported {vt_detections} detection{'s' if vt_detections > 1 else ''}")
        
    if not gsb_safe:
        reasons.append("Flagged as malicious by Google Safe Browsing")
        
    if keyword_count > 0:
        reasons.append(f"Found {keyword_count} suspicious keyword{'s' if keyword_count > 1 else ''} in URL")
        
    # Catch-all external intelligence inference for explainability
    if (vt_detections > 0 or not gsb_safe) and risk_level in ["Suspicious", "Malicious"]:
        reasons.append("External threat intelligence increased the risk level")
        
    if risk_level == "Safe" and not reasons:
        reasons.append("All security checks passed successfully")
             
    return reasons

def evaluate_url(url):
    db = get_db()

    # Check cache
    cached = db.execute(
        "SELECT risk_score, risk_level, scan_details FROM cached_urls WHERE url = ?",
        (url,)
    ).fetchone()

    if cached:
        details = json.loads(cached["scan_details"])
        if "keyword_score" not in details:
            details["keyword_score"] = 0
        if "phishing_prob" not in details:
            details["phishing_prob"] = 0
        if "malware_prob" not in details:
            details["malware_prob"] = 0
        if "vt_detections" not in details:
            details["vt_detections"] = 0
        if "google_safe_browsing_safe" not in details:
            details["google_safe_browsing_safe"] = True
        if "reasons" not in details:
            details["reasons"] = []

        return {
            "risk_score": cached["risk_score"],
            "risk_level": cached["risk_level"],
            "details": details
        }

    # Evaluate using ML
    ml_result = predict_url_ml(url)
    keyword_count = ml_result.get("keyword_score", 0)
    phishing_prob = ml_result.get("phishing_prob", 0.0)
    malware_prob = ml_result.get("malware_prob", 0.0)

    # Check APIs
    vt_detections, vt_total = check_virustotal(url)
    gsb_safe = check_google_safe_browsing(url)

    # API Debug Output
    print("---- API DEBUG ----")
    print("URL:", url)
    print("VT detections:", vt_detections, "/", vt_total)
    print("GSB safe:", gsb_safe)
    print("-------------------")

    # Unified Advanced Risk Calculation
    phishing_score = phishing_prob * 100
    malware_score = malware_prob * 100
    
    base_score = calculate_risk_score(
        phishing_prob,
        malware_prob,
        keyword_count,
        vt_detections,
        vt_total,
        gsb_safe
    )
    
    level = classify_risk(base_score)
    final_label = determine_final_label(base_score, phishing_prob, malware_prob, vt_detections, gsb_safe)
    
    reasons = generate_explainability(phishing_score, malware_score, vt_detections, gsb_safe, keyword_count, level)

    # Compile details for UI
    vt_percentage = int((vt_detections / vt_total * 100)) if vt_total > 0 else 0
    max_ml = max(phishing_prob, malware_prob)

    details = {
        "ml_label": ml_result.get("label", "Safe"),
        "final_decision_label": final_label,
        "ml_probability": int(max_ml * 100),
        "phishing_prob": int(phishing_score),
        "malware_prob": int(malware_score),
        "keyword_score": keyword_count,
        "virustotal_score": vt_percentage,
        "vt_detections": vt_detections,
        "google_safe_browsing_safe": gsb_safe,
        "reasons": reasons
    }

    # Save to cache
    db.execute(
        "INSERT OR REPLACE INTO cached_urls (url, risk_score, risk_level, scan_details) VALUES (?, ?, ?, ?)",
        (url, base_score, level, json.dumps(details))
    )
    db.commit()

    return {
        "risk_score": base_score,
        "risk_level": level,
        "details": details
    }
    