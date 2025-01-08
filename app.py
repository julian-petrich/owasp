from flask import Flask, request, jsonify, render_template, render_template_string
import sqlite3
import logging
import os

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Vulnerability 1: Injection ---
@app.route('/vulnerable_sql', methods=['GET', 'POST'])
def vulnerable_sql():
    if request.method == 'POST':
        user_input = request.form.get('username')
        conn = None
        try:
            # Connect to the database
            conn = sqlite3.connect('example.db')
            logging.info("Database connection successful.")

            cursor = conn.cursor()

            # Vulnerable Query: Directly embedding user input
            query = f"SELECT * FROM users WHERE username = '{user_input}'"
            logging.debug(f"Executing query: {query}")

            cursor.execute(query)
            results = cursor.fetchall()

            if results:
                logging.info(f"Query returned {len(results)} results.")
            else:
                logging.warning("Query returned no results.")

            return jsonify(results)
        except sqlite3.Error as e:
            logging.error(f"Database error: {e}")
            return str(e)
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            return str(e)
        finally:
            if conn:
                conn.close()
                logging.info("Database connection closed.")
    return render_template('login.html', page_title="SQL Injection Test", page_heading="SQL Injection Demo", form_action="/vulnerable_sql", show_password_field=False)

# --- Vulnerability 2: Broken Authentication ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Insecure: Hardcoded credentials
        if username == 'admin' and password == 'password':
            return "Login successful!"
        else:
            return "Invalid credentials!"
    return render_template('login.html', page_title="Login", page_heading="User Login", form_action="/login", show_password_field=True)

# --- Vulnerability 3: Sensitive Data Exposure ---
@app.route('/expose_sensitive_data')
def expose_sensitive_data():
    sensitive_data = {
        "credit_card": "1234-5678-9012-3456",
        "password": "plaintextpassword"
    }
    return jsonify(sensitive_data)

# --- Vulnerability 4: XML External Entities (XXE) ---
@app.route('/vulnerable_xml', methods=['POST'])
def vulnerable_xml():
    xml_data = request.data.decode()
    try:
        # Process XML without disabling external entities
        import xml.etree.ElementTree as ET
        tree = ET.fromstring(xml_data)
        return tree.tag
    except Exception as e:
        return str(e)

# --- Vulnerability 5: Broken Access Control ---
@app.route('/admin', methods=['GET'])
def admin():
    # Insecure: No authentication check for admin page
    return "Welcome to the admin panel!"

# --- Vulnerability 6: Security Misconfiguration ---
@app.route('/debug')
def debug():
    # Debug mode enabled (do not use in production)
    return "Debug mode is active."

# --- Vulnerability 7: Cross-Site Scripting (XSS) ---
@app.route('/xss', methods=['GET', 'POST'])
def xss():
    user_input = request.args.get('input')
    # Render input directly into the response
    return render_template_string(f"<p>{user_input}</p>")

# --- Vulnerability 8: Insecure Deserialization ---
@app.route('/deserialize', methods=['POST'])
def deserialize():
    import pickle
    data = request.data
    try:
        # Directly deserialize user-provided data
        obj = pickle.loads(data)
        return str(obj)
    except Exception as e:
        return str(e)

# --- Vulnerability 9: Using Components with Known Vulnerabilities ---
@app.route('/outdated_library')
def outdated_library():
    # Simulating outdated libraries
    return "This route uses an outdated library (simulate)."

# --- Vulnerability 10: Insufficient Logging and Monitoring ---
@app.route('/no_logging', methods=['POST'])
def no_logging():
    # Simulating no logging of critical events
    username = request.form.get('username')
    return f"Hello {username}, this access was not logged!"

# --- Add Website Functionality ---
@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    # Simulate security misconfiguration by enabling debug mode
    app.run(debug=True, host='0.0.0.0', port=5000)
