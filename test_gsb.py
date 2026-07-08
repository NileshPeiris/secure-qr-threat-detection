from app import create_app
from threat_engine.apis import check_google_safe_browsing

app = create_app()
with app.app_context():
    print("Testing GSB with malware test URL...")
    # Official Google Safe Browsing testing URLs
    malware_url = "http://malware.testing.google.test/testing/malware/"
    res = check_google_safe_browsing(malware_url)
    print("GSB Result for malware_url (Expected False/Unsafe):", res)

    print("\nTesting GSB with real world eicar...")
    eicar = "http://eicar.org"
    res2 = check_google_safe_browsing(eicar)
    print("GSB Result for eicar (Expected True/Safe usually):", res2)
