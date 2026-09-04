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

#CONSTANTS & CONFIGURATION
#Call load_dotenv function to pull all hidden variables into the application's environment.
load_dotenv()

#Initialize the Flask application and save it to the app variable.
app = Flask(__name__)

#Set the SECRET_KEY from the environment to securely sign session cookies for logged-in users.
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-dev-key')

#Set the SQLALCHEMY_DATABASE_URI to tell the database where to save our user accounts.
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///local_dashboard.db')

#Turn off SQLALCHEMY_TRACK_MODIFICATIONS to save memory and prevent unnecessary overhead.
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#Restrict maximum upload size to 16MB to prevent Denial of Service (DoS) attacks from massive files.
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

#Initialize the SQLAlchemy database object and link it to our Flask app.
db = SQLAlchemy(app)


#DATABASE MODELS
#User class that inherits from db.Model to map directly to the 'user' table in the database.
class User(db.Model):
    #Declare id column as an Integer and set it as the Primary Key.
    id = db.Column(db.Integer, primary_key=True)
    
    #Declare username column as a String, enforce unique names, and do not allow empty values.
    username = db.Column(db.String(150), unique=True, nullable=False)
    
    #Declare password_hash column as a String to hold the encrypted password data.
    password_hash = db.Column(db.String(256), nullable=False)

    #set_password function that takes a plaintext password and converts it to a secure hash.
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    #check_password function that compares a user's login attempt against the saved database hash.
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


#Create the local SQLite database automatically on startup if it doesn't already exist.
with app.app_context():
    db.create_all()


#FUNCTIONS
#allowed_file function that will take the filename and verify it has an extension and that the extension is exactly 'csv'.
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'csv'

#check_virustotal function that will take the file stream, calculate its hash, and ask VirusTotal if it is malicious.
def check_virustotal(file_stream):
    
    #Initialize the SHA-256 hashing algorithm.
    sha256_hash = hashlib.sha256()
    
    #Use a for loop to read the file in 4096-byte chunks to prevent memory crashes on large files.
    for byte_block in iter(lambda: file_stream.read(4096), b""):
        sha256_hash.update(byte_block)
    
    #Save the final calculated hash to the file_hash variable.
    file_hash = sha256_hash.hexdigest()
    
    #Reset the file stream pointer back to the beginning so Backblaze can read it later.
    file_stream.seek(0) 

    #Declare the VirusTotal API URL and append our calculated file_hash.
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    
    #Declare the headers dictionary and inject our private API key from the environment.
    headers = {"x-apikey": os.getenv("VIRUSTOTAL_API_KEY")}
    
    #try/catch block to attempt the external API request.
    try:
        #Send GET request to VirusTotal and wait up to 5 seconds for a response.
        response = requests.get(url, headers=headers, timeout=5)
        
        #Check if the HTTP response code is 200 OK.
        if response.status_code == 200:
            
            #Parse the JSON response to pull the specific security vendor statistics.
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            
            #Safety check to see if any vendor flagged the file as malicious. If yes, return False.
            if stats.get("malicious", 0) > 0:
                return False 
                
    #Exception handling in the event the API is down or the network request fails.
    except requests.exceptions.RequestException as e:
        print(f"VirusTotal Check Failed: {e}")
        #Fail open for local development so the app doesn't crash if we don't have internet.
        pass 
        
    #Return True if the file is clean or unknown.
    return True

#upload_to_b2 function that will take the file_stream and filename and push it to Backblaze cloud storage.
def upload_to_b2(file_stream, filename):
    
    #Initialize S3 client using the boto3 library and inject our custom Backblaze credentials.
    s3 = boto3.client(
        's3',
        endpoint_url=os.getenv('B2_ENDPOINT_URL'),
        aws_access_key_id=os.getenv('B2_KEY_ID'),
        aws_secret_access_key=os.getenv('B2_APPLICATION_KEY')
    )
    
    #try/catch block to attempt to upload the file object to the cloud bucket.
    try:
        #Call upload_fileobj sending in the file stream, the target bucket name, and the final filename.
        s3.upload_fileobj(file_stream, os.getenv('B2_BUCKET_NAME'), filename)
        
        #Construct and return the public URL for the database to reference later.
        return f"{os.getenv('B2_ENDPOINT_URL')}/{os.getenv('B2_BUCKET_NAME')}/{filename}"
        
    #Exception handling in the event the upload fails (e.g., bad keys, bucket doesn't exist).
    except ClientError as e:
        print(f"B2 Upload Failed: {e}")
        return None


#RACHEL'S OOP MATH ENGINE
#Dataset class that will hold the parsed CSV data and calculate statistics.
class Dataset:
    
    #Initialize the dataset object taking the raw file stream as an argument.
    def __init__(self, raw_file_stream):
        #RACHEL: This is where you will parse the CSV and determine the headers and column types.
        pass

    #generate_report function that will execute the math logic across all columns.
    def generate_report(self):
        #RACHEL: This function should loop through your columns, calculate Mean, Min, Max, Std, 
        #and Count, and return a dictionary of those stats to pass to the frontend dashboard.
        return {"status": "Engine not yet implemented"}


#FLASK ROUTES
#Route for the root URL ('/') that serves the front door login page.
@app.route('/')
def home():
    #Render and return the login.html template.
    return render_template('login.html')


#Route for the '/dashboard' URL that handles both viewing the dashboard and processing POST CSV file uploads.
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    
    #Initialize report_data as None.
    report_data = None

    #Safety check to process the form submission only if the user made a POST request.
    if request.method == 'POST':
        
        #Safety check to ensure the HTTP request actually contains a file part.
        if 'file' not in request.files:
            return "No file part in request", 400
            
        #Extract the file from the request and save to variable.
        file = request.files['file']
        
        #Safety check in case the user clicked submit without selecting a file.
        if file.filename == '':
            return "No selected file", 400
            
        #Call allowed_file function to verify the uploaded file is strictly a CSV.
        if file and allowed_file(file.filename):
            
            #Sanitize the filename to prevent directory traversal attacks (e.g., changing '../../../etc/passwd').
            filename = secure_filename(file.filename)
            
            #Call check_virustotal function to run malware scanning. If it returns False, block upload.
            if not check_virustotal(file):
                return "Upload rejected: Malicious file detected.", 403
                
            #Call upload_to_b2 function to import the sanitized file to Backblaze B2.
            b2_url = upload_to_b2(file, filename)
            
            #Safety check to ensure the cloud upload actually worked before proceeding.
            if not b2_url:
                return "Storage error: Could not connect to cloud bucket", 500
                
            #TEMPORARY TEST OUTPUT: Return the live B2 URL to the screen to prove the cloud upload worked!
            return f"Success! File safely stored in Backblaze at: {b2_url}"
            
        #Else clause if user attempts to upload a non-CSV file.
        else:
            return "Invalid file type. Only CSV allowed.", 400
            
    #TEMPORARY FRONTEND FOR TESTING:
    #Return a raw HTML form so we can test the backend before Developer 4 builds the real dashboard.html.
    return '''
    <!doctype html>
    <title>Test CSV Upload</title>
    <h2>DataDash Test Upload</h2>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    '''


#END OF MAIN
if __name__ == "__main__":
    #Pull the assigned port from the environment, defaulting to 8000 if not found.
    port = int(os.environ.get("PORT", 8000))
    
    #Run the Flask development server on all network interfaces (0.0.0.0) with debug mode turned off.
    app.run(host="0.0.0.0", port=port, debug=False)