from flask import Flask
from owasp_vulns import vulnerabilities_bp
from owasp_api_vulns import api_vulnerabilities_bp

app = Flask(__name__)

# Register the vulnerabilities Blueprint
app.register_blueprint(vulnerabilities_bp)
app.register_blueprint(api_vulnerabilities_bp)

@app.route('/')
def home():
    return "<h1>Welcome to the OWASP Vulnerabilities Demo!</h1>"

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
