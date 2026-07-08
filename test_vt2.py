import base64
import requests
import os
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("VIRUSTOTAL_API_KEY")
url = "http://this-is-a-completely-random-url-that-never-existed-123.com/random"
url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
headers = {"x-apikey": api_key}
print(f"Requesting VT for {url_id}...")
response = requests.get(endpoint, headers=headers)
print(response.status_code)
print(response.json())
