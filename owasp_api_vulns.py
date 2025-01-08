from flask import request, jsonify, render_template_string, Blueprint
import sqlite3
import logging
import pickle
import xml.etree.ElementTree as ET

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Create a Blueprint
api_vulnerabilities_bp = Blueprint('api_vulnerabilities', __name__, url_prefix='/owasp_api')

# --- Vulnerability 1: Broken Object Level Authorization (BOLA) ---
@api_vulnerabilities_bp.route('/bola', methods=['GET'])
def bola():
    user_id = request.args.get('user_id')  # This could be a parameter
    # Insecure: The API does not check if the authenticated user is authorized to access this data
    data = {"user_id": user_id, "data": "Sensitive data"}
    return jsonify(data)

# --- Vulnerability 2: Broken Authentication ---
@api_vulnerabilities_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Insecure: Hardcoded credentials
        if username == 'admin' and password == 'password':
            return "Login successful!"
        else:
            return "Invalid credentials!"
    return render_template_string('<form method="POST">Username: <input name="username" type="text" /><Password: <input name="password" type="password" /><input type="submit" /></form>')

# --- Vulnerability 3: Excessive Data Exposure ---
@api_vulnerabilities_bp.route('/expose_sensitive_data')
def expose_sensitive_data():
    # Sensitive data should not be exposed in API responses
    sensitive_data = {
        "credit_card": "1234-5678-9012-3456",
        "password": "plaintextpassword"
    }
    return jsonify(sensitive_data)

# --- Vulnerability 4: Lack of Resources & Rate Limiting ---
@api_vulnerabilities_bp.route('/api_request', methods=['GET'])
def api_request():
    # Simulating an API endpoint without rate limiting
    return "API request successful, but no rate limiting implemented."

# --- Vulnerability 5: Broken Function Level Authorization ---
@api_vulnerabilities_bp.route('/admin', methods=['GET'])
def admin():
    # Insecure: No authorization check before granting access to sensitive functionality
    return "Welcome to the admin panel!"

# --- Vulnerability 6: Mass Assignment ---
@api_vulnerabilities_bp.route('/update_user', methods=['POST'])
def update_user():
    user_data = request.form.to_dict()
    # Insecure: API allows mass assignment, potentially exposing sensitive data
    # This should not update arbitrary fields like "is_admin"
    return jsonify(user_data)

# --- Vulnerability 7: Security Misconfiguration ---
@api_vulnerabilities_bp.route('/debug')
def debug():
    # Debug mode enabled (do not use in production)
    return "Debug mode is active."

# --- Vulnerability 8: Injection ---
@api_vulnerabilities_bp.route('/vulnerable_sql', methods=['GET', 'POST'])
def vulnerable_sql():
    if request.method == 'POST':
        user_input = request.form.get('username')
        conn = None
        try:
            # Vulnerable Query: Directly embedding user input
            conn = sqlite3.connect('example.db')
            query = f"SELECT * FROM users WHERE username = '{user_input}'"
            cursor = conn.cursor()
            cursor.execute(query)
            results = cursor.fetchall()
            return jsonify(results)
        except sqlite3.Error as e:
            return str(e)
        finally:
            if conn:
                conn.close()
    return render_template_string('<form method="POST">Username: <input name="username" type="text" /><input type="submit" /></form>')

# --- Vulnerability 9: Improper Assets Management ---
@api_vulnerabilities_bp.route('/old_version', methods=['GET'])
def old_version():
    # Insecure: An old API version that should not be publicly accessible
    return "This is an old version of the API. It should not be accessible."

# --- Vulnerability 10: Insufficient Logging & Monitoring ---
@api_vulnerabilities_bp.route('/no_logging', methods=['POST'])
def no_logging():
    # Simulating no logging of critical events
    username = request.form.get('username')
    return f"Hello {username}, this access was not logged!"
