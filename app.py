#DESCRIPTION: This program runs the DataDash interactive data visualization dashboard. 
#             It handles secure user authentication, sanitizes and verifies uploaded CSV files 
#             via VirusTotal, uploads safe files to Backblaze B2 cloud storage, and routes 
#             data to the OOP math engine for statistical analysis.

#LIBRARIES
#import os module to securely pull environment variables like passwords and API keys.
import os

#import hashlib module to generate SHA-256 hashes of files for malware scanning.
import hashlib

#import requests module to make external HTTP calls to the VirusTotal API.
import requests

#import boto3 module to handle S3-compatible cloud storage connections (Backblaze B2).
import boto3

#from botocore.exceptions import ClientError to handle specific cloud upload failures.
from botocore.exceptions import ClientError

#from werkzeug.utils import secure_filename to strip dangerous characters from uploaded filenames.
from werkzeug.utils import secure_filename

#from werkzeug.security import password hashing functions to securely encrypt user passwords.
from werkzeug.security import generate_password_hash, check_password_hash

#from flask import modules to run the web server, render HTML templates, handle web requests, and flash messages.
from flask import Flask, render_template, request, flash

#from flask_sqlalchemy import SQLAlchemy to handle all our database operations using Python objects.
from flask_sqlalchemy import SQLAlchemy

#from dotenv import load_dotenv to force Python to read the hidden .env file on startup.
from dotenv import load_dotenv

# ---------------------------------------------------------
#SETUP & CONFIGURATION
# ---------------------------------------------------------
#Load environment variables from the .env file (passwords, database URLs)
load_dotenv()

app = Flask(__name__)

#SECRET_KEY is used by Flask to securely sign session cookies
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-dev-key')

#DATABASE_URL tells SQLAlchemy where to save our user accounts
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///local_dashboard.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ---------------------------------------------------------
#DEVELOPER 3: DATABASE MODELS (User Accounts & Auth)
# ---------------------------------------------------------
class User(db.Model):
    """
    Maps to the 'user' table in the database.
    Dev 3 will eventually add more columns here and handle password hashing.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

#Creates the local SQLite database automatically on startup if it doesn't exist
with app.app_context():
    db.create_all()

# ---------------------------------------------------------
#DEVELOPER 2: FLASK ROUTES (Traffic Controllers)
# ---------------------------------------------------------
@app.route('/')
def home():
    """
    Serves the front door login page.
    Dev 3 will eventually add login validation/security logic here.
    """
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    """
    Handles both viewing the dashboard and processing CSV file uploads.
    """
    if request.method == 'POST':
        #DEVELOPER 2: Grab the uploaded .csv file from the HTML form
        #DEVELOPER 1: Pass that file into your Python OOP Engine to calculate stats
        pass
        
    #DEVELOPER 4: Pass the calculated stats from Dev 1 into this render_template function to build charts
    return render_template('dashboard.html')

if __name__ == "__main__":
    #Runs the local development server on port 8000
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=False)    
