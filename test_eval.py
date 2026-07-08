from app import create_app
from threat_engine.aggregator import evaluate_url

app = create_app()
with app.app_context():
    print("Testing http://eicar.org")
    res = evaluate_url("http://eicar.org")
    print("Test Result:", res)

print("done")
