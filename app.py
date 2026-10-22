#DESCRIPTION: This program runs the DataDash interactive data visualization dashboard. 
#             It handles secure user authentication, guest sessions, user account registration 
#             with email recovery, file size restrictions, VirusTotal malware verification, 
#             Backblaze B2 cloud storage, and persistent file tracking for logged-in users.

#LIBRARIES
#import os module to securely pull environment variables like passwords and API keys.
import os

#import hashlib module to generate SHA-256 hashes of files for malware scanning.
import hashlib

#import requests module to make external HTTP calls to the VirusTotal API.
import requests

#import boto3 module to handle S3-compatible cloud storage connections (Backblaze B2).
import boto3

#Math engine packages
import csv
import io
import statistics

#import time to track lockout durations for the rate limiter.
import time

#import uuid to generate random strings for unique cloud storage filenames.
import uuid

#import Counter to count categorical text occurrences for the pie charts.
from collections import Counter

#Graph engine packages
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import base64

#from botocore.exceptions import ClientError to handle specific cloud upload failures.
from botocore.exceptions import ClientError

#from werkzeug.utils import secure_filename to strip dangerous characters from uploaded filenames.
from werkzeug.utils import secure_filename

#from werkzeug.security import password hashing functions to securely encrypt user passwords.
from werkzeug.security import generate_password_hash, check_password_hash

#from flask modules to run the web server, render templates, manage web requests, sessions, and flash messages.
from flask import Flask, render_template, request, redirect, url_for, session, flash

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

#Set the SQLALCHEMY_DATABASE_URI to tell the database where to save our user accounts and file records.
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///local_dashboard.db')

#Turn off SQLALCHEMY_TRACK_MODIFICATIONS to save memory and prevent unnecessary overhead.
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#Restrict maximum upload size to 5MB to strictly protect the Backblaze B2 free tier limit from massive files.
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024 

#Initialize the SQLAlchemy database object and link it to our Flask app.
db = SQLAlchemy(app)

#SECURITY CONFIGURATION
#Initialize an in-memory dictionary to track failed login attempts by IP address.
FAILED_LOGINS = {}

#Define the hard lockout duration in seconds (300 seconds = 5 minutes).
LOCKOUT_DURATION = 300 

#DATABASE MODELS
#User class that inherits from db.Model to map directly to the 'user' table in the database.
class User(db.Model):
    #Declare id column as an Integer and set it as the Primary Key.
    id = db.Column(db.Integer, primary_key=True)
    
    #Declare username column as a String, enforce unique names, and do not allow empty values.
    username = db.Column(db.String(150), unique=True, nullable=False)
    
    #Declare email column as a String to store user email addresses for account recovery.
    email = db.Column(db.String(150), unique=True, nullable=False)
    
    #Declare password_hash column as a String to hold the encrypted password data.
    password_hash = db.Column(db.String(256), nullable=False)
    
    #Establish a relationship mapping so we can easily query all files uploaded by this specific user.
    files = db.relationship('StoredFile', backref='owner', lazy=True)

    #set_password function that takes a plaintext password and converts it to a secure hash.
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    #check_password function that compares a user's login attempt against the saved database hash.
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


#StoredFile class that maps directly to persistent records of user datasets in the database.
class StoredFile(db.Model):
    #Declare id column as an Integer and set it as the Primary Key.
    id = db.Column(db.Integer, primary_key=True)
    
    #Declare filename column as a String to save the sanitized file name.
    filename = db.Column(db.String(255), nullable=False)
    
    #Declare b2_url column as a String to hold the direct public cloud storage link.
    b2_url = db.Column(db.String(500), nullable=False)
    
    #Declare user_id as a Foreign Key linked to the primary key of the User table.
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


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
        
        #Check if the HTTP response code is 200 OK (meaning the file exists in their database).
        if response.status_code == 200:
            
            #Parse the JSON response to pull the specific security vendor statistics.
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            
            #Safety check to see if any vendor flagged the file as malicious. If yes, return False.
            if stats.get("malicious", 0) > 0:
                return False 
            
            #Return True because the file was found and is completely clean.
            return True
            
        #Check if the file is completely unknown to VirusTotal (404 Not Found).
        elif response.status_code == 404:
            #Allow the upload to proceed since it is a brand new, unrecognized user dataset.
            print("VirusTotal: Hash not found. Allowing unknown CSV.")
            return True
                
    #Exception handling in the event the API is down or the network request fails.
    except requests.exceptions.RequestException as e:
        print(f"VirusTotal Check Failed: {e}")
        
    #SECURITY FIX: Strict fail-closed. If the network dies or the API key is bad, block the upload entirely.
    return False


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

#delete_from_b2 function that will take the filename and permanently remove it from Backblaze cloud storage.
def delete_from_b2(filename):
    
    #Initialize S3 client using the boto3 library and inject our custom Backblaze credentials.
    s3 = boto3.client(
        's3',
        endpoint_url=os.getenv('B2_ENDPOINT_URL'),
        aws_access_key_id=os.getenv('B2_KEY_ID'),
        aws_secret_access_key=os.getenv('B2_APPLICATION_KEY')
    )
    
    #try/catch block to attempt the deletion command on the cloud bucket.
    try:
        #Call delete_object sending in the target bucket name and the specific filename (Key) to delete.
        s3.delete_object(Bucket=os.getenv('B2_BUCKET_NAME'), Key=filename)
        
        #Return True if the deletion was successful.
        return True
        
    #Exception handling in the event the deletion fails (e.g., file not found, bad keys).
    except ClientError as e:
        print(f"B2 Deletion Failed: {e}")
        return False


#download_from_b2 function that will fetch a saved file from cloud storage to pass to the math engine.
def download_from_b2(filename):
    
    #Initialize S3 client using the boto3 library and inject our custom Backblaze credentials.
    s3 = boto3.client(
        's3',
        endpoint_url=os.getenv('B2_ENDPOINT_URL'),
        aws_access_key_id=os.getenv('B2_KEY_ID'),
        aws_secret_access_key=os.getenv('B2_APPLICATION_KEY')
    )
    
    #try/catch block to attempt to retrieve the file object from the cloud bucket.
    try:
        #Call get_object sending in the target bucket name and the specific filename (Key) to retrieve.
        response = s3.get_object(Bucket=os.getenv('B2_BUCKET_NAME'), Key=filename)
        
        #Return the raw file stream (Body) so Rachel's OOP Dataset class can read it.
        return response['Body'] 
        
    #Exception handling in the event the download fails.
    except ClientError as e:
        print(f"B2 Download Failed: {e}")
        return None

#RACHEL'S OOP MATH ENGINE
#Dataset class that will dynamically hold parsed CSV data and calculate statistics.
class Dataset:
    #Constructor method that takes the raw binary file stream downloaded from cloud storage.
    def __init__(self, raw_file_stream):
        
        #Decode the binary file stream into a UTF-8 string buffer while replacing non-decodable characters safely.
        decoded = raw_file_stream.read().decode("utf-8", errors="replace")
        
        #Wrap the decoded raw string inside an in-memory StringIO buffer so the csv module can parse it.
        buffer = io.StringIO(decoded)

        #Initialize the DictReader object to parse rows as associative dictionaries using header names.
        reader = csv.DictReader(buffer)
        
        #Extract the list of column header strings from the CSV file.
        self.headers = reader.fieldnames
        
        #Initialize an empty list container for every parsed column key found in the header row.
        self.columns = {h: [] for h in self.headers}

        #Iterate row-by-row across the entire CSV dataset to categorize and store column cell values.
        for row in reader:
            #Iterate across each defined column header in the current data row.
            for h in self.headers:
                #Extract the cell value and strip leading and trailing whitespace characters.
                value = row.get(h, "").strip()

                #Verify if the cell contains empty data; if empty, append None to avoid false zeroes.
                if not value:
                    self.columns[h].append(None)
                    continue

                #Use a try/except block to attempt numeric parsing while preserving textual values.
                try:
                    #Convert cell string to a float for mathematical calculations.
                    num = float(value)
                    #Append the converted floating-point number into the corresponding column list.
                    self.columns[h].append(num)
                #Catch ValueError exceptions when encountering text strings, dates, or non-numeric tokens.
                except ValueError:
                    #Append the original string value directly into the column list for categorical analysis.
                    self.columns[h].append(value)

    #generate_report function that will compute numeric metrics or categorical counts per column.
    def generate_report(self):
        
        #Initialize an empty dictionary container to store summary statistics for every dataset column.
        report = {}

        #Iterate across each header to compute metric data based on the extracted contents.
        for col in self.headers:
            
            #Filter out None values to ensure calculations only process populated cells.
            valid_values = [v for v in self.columns[col] if v is not None]

            #Safety check to identify completely empty columns and prevent zero-division calculation crashes.
            if not valid_values:
                #Record empty column metrics and assign a count of zero.
                report[col] = {
                    "type": "empty",
                    "count": 0
                }
                continue

            #Filter the list of valid cells to extract only floating-point numbers.
            numeric_values = [v for v in valid_values if isinstance(v, float)]

            #Evaluate whether numeric entries represent the strict majority of populated rows in this column.
            if len(numeric_values) > len(valid_values) / 2:
                #Calculate the total number of numeric entries available.
                count = len(numeric_values)
                #Compute the mathematical average across all numeric entries.
                mean = statistics.mean(numeric_values)
                #Identify the minimum numerical value in the column dataset.
                min_val = min(numeric_values)
                #Identify the maximum numerical value in the column dataset.
                max_val = max(numeric_values)
                #Calculate sample standard deviation if sample size exceeds 1, otherwise default to 0.0.
                std = statistics.stdev(numeric_values) if count > 1 else 0.0

                #Populate the report dictionary with the computed statistical metrics.
                report[col] = {
                    "type": "numeric",
                    "count": count,
                    "mean": mean,
                    "min": min_val,
                    "max": max_val,
                    "std": std
                }
            #Else branch to handle categorical string columns such as categories, names, or drug classifications.
            else:
                #Cast all valid values explicitly to strings to maintain data homogeneity.
                string_values = [str(v) for v in valid_values]
                #Generate a set collection of the string values to isolate distinct items.
                unique_vals = set(string_values)

                #Use a try/except block to safely calculate the mathematical mode.
                try:
                    #Compute the most frequently occurring categorical value using the statistics module.
                    mode_val = statistics.mode(string_values)
                #Handle multimodal distribution exceptions when several items share equal frequency.
                except statistics.StatisticsError:
                    #Set fallback string label when no singular modal value exists.
                    mode_val = "Multiple"

                #Populate the report dictionary with the computed categorical summary.
                report[col] = {
                    "type": "categorical",
                    "count": len(string_values),
                    "unique": len(unique_vals),
                    "mode": mode_val
                }

        #Return the completed reporting dictionary ready for template rendering.
        return report

#GRAPHICAL IMPLEMENTATION CLASS
#Liam's upgraded graph engine that generates dynamic histograms and pie charts.
class DataVisualizer:
    
    # Class Definition taking both the raw dataset and the computed report.
    def __init__(self, dataset, report_data):
        self.dataset = dataset
        self.report_data = report_data

    # Generates a dynamic list of up to 4 charts based on column data types.
    def generate_charts(self, max_charts=4):
        # Initialize an empty list to hold the base64 encoded image strings.
        charts = []
        
        # Filter out completely empty columns so we don't try to graph nothing.
        valid_cols = [col for col in self.dataset.headers if self.report_data[col]['type'] != 'empty']
        
        # Loop through the valid columns, stopping once we hit the max_charts limit.
        for col in valid_cols[:max_charts]:
            # Extract the data type (numeric or categorical) from the report.
            col_type = self.report_data[col]['type']
            
            # Filter out None values from the raw column data.
            valid_values = [v for v in self.dataset.columns[col] if v is not None]
            
            # Generate figure size for the individual chart. Increased size to 6x5 for better readability.
            fig, ax = plt.subplots(figsize=(6, 5))
            
            # If the column is numeric, build a Histogram to show data distribution.
            if col_type == 'numeric':
                # Ensure all values passed to the histogram are actually floats.
                numeric_vals = [v for v in valid_values if isinstance(v, float)]
                
                # Plot the histogram with 10 bins.
                ax.hist(numeric_vals, bins=10, color='#4e73df', edgecolor='black')
                
                # Set axis titles and formatting. Increased font sizes for readability.
                ax.set_title(f"Distribution of {col}", fontsize=14, fontweight='bold', pad=10)
                ax.set_xlabel(col, fontsize=12)
                ax.set_ylabel("Frequency", fontsize=12)
                
            # If the column is text/categorical, build a Pie Chart to show breakdown.
            else:
                # Cast all values to strings.
                string_vals = [str(v) for v in valid_values]
                
                # Count the occurrences of each unique string.
                counts = Counter(string_vals)
                
                # Grab the top 5 most common items to keep the pie chart readable.
                top_items = counts.most_common(5)
                labels = [item[0] for item in top_items]
                sizes = [item[1] for item in top_items]
                
                # If there are more than 5 unique items, lump the rest into an 'Other' slice.
                if len(counts) > 5:
                    labels.append("Other")
                    sizes.append(sum(counts.values()) - sum(sizes))
                    
                # Plot the pie chart with slightly larger text.
                ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140, colors=plt.cm.Paired.colors, textprops={'fontsize': 11})
                
                # Set title.
                ax.set_title(f"Breakdown of {col}", fontsize=14, fontweight='bold', pad=10)

            # Adjust sizing so graph isn't cut off.
            plt.tight_layout()

            # Set file buffer.
            buffer = io.BytesIO()

            # Save figure to the buffer using bbox_inches to prevent text clipping.
            plt.savefig(buffer, format='png', bbox_inches='tight')

            # Get buffer iterator to front of buffer space.
            buffer.seek(0)

            # Encode figure to Base64.
            plot_url = base64.b64encode(buffer.getvalue()).decode('utf-8')

            # Close the figure to free up memory.
            plt.close(fig)

            # Append the encoded chart to our list.
            charts.append(plot_url)

        # Return the list of encoded figures.
        return charts

#FLASK ROUTES
#Route for the root URL ('/') that serves the front door login page.
@app.route('/')
def home():
    #Render and return the login.html template.
    return render_template('login.html')


#Route for the '/login' URL that processes login form submissions and starts a persistent session.
@app.route('/login', methods=['POST'])
def login():
    
    #SECURITY FIX: Isolate the user's remote IP address to track failed authentication attempts.
    ip = request.remote_addr
    #Capture the current system time in seconds since the epoch.
    current_time = time.time()
    
    #Check if the user's IP is already recorded in the failed logins dictionary.
    if ip in FAILED_LOGINS:
        #Unpack the tuple to retrieve the attempt count and the timestamp of the first failure.
        attempts, lockout_start = FAILED_LOGINS[ip]
        #If the user has failed 5 or more times...
        if attempts >= 5:
            #Check if the elapsed time is still within the 5-minute lockout window.
            if current_time - lockout_start < LOCKOUT_DURATION:
                #Reject the login attempt and flash a warning to the user.
                flash('Too many failed attempts. Device locked for 5 minutes.', 'danger')
                return redirect(url_for('home'))
            else:
                #If the 5 minutes have passed, remove the IP from the dictionary to reset the tracker.
                FAILED_LOGINS.pop(ip, None)

    #Pull username and password values from the submitted form data.
    username = request.form.get('username')
    password = request.form.get('password')
    
    #Query the database to find the user by their unique username.
    user = User.query.filter_by(username=username).first()
    
    #Check if the user exists and if their password matches the database hash.
    if user and user.check_password(password):
        #Clear any failed login history for this IP upon successful authentication.
        FAILED_LOGINS.pop(ip, None) 
        #Start the secure user session.
        session['user_id'] = user.id
        session['username'] = user.username
        session.pop('is_guest', None) # Clear guest status on successful login
        return redirect(url_for('dashboard'))
    
    #Track the failed attempt if credentials did not match.
    attempts, _ = FAILED_LOGINS.get(ip, (0, current_time))
    #Increment the attempt counter and update the dictionary for this IP.
    FAILED_LOGINS[ip] = (attempts + 1, current_time)
    
    #Flash error message if login credentials fail.
    flash('Invalid username or password.', 'danger')
    return redirect(url_for('home'))


#Route for the '/register' URL that handles creating new user accounts with username, email, and password.
@app.route('/register', methods=['GET', 'POST'])
def register():
    #Process account creation if the user submitted the registration form via POST.
    if request.method == 'POST':
        #Pull the submitted credentials from the HTTP form.
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        #SECURITY FIX: Verify that the user typed their password correctly twice to prevent accidental lockouts.
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))
            
        #Check if the username is already taken in the database.
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
            
        #SECURITY FIX: Query database to proactively catch duplicate emails and prevent a fatal IntegrityError crash.
        if User.query.filter_by(email=email).first():
            flash('Email is already registered.', 'danger')
            return redirect(url_for('register'))
            
        #Create a new User object and securely hash their password.
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        #Save the new user to the database.
        db.session.add(new_user)
        db.session.commit()
        
        #Flash success and route the user back to the login screen.
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('home'))
        
    #Render the register template if accessed via GET.
    return render_template('register.html')

#Route for the '/forgot-password' URL to assist users with password recovery via email.
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    #Process the submitted form if the user made a POST request.
    if request.method == 'POST':
        # NOTE: Actual email sending logic (like SendGrid or SMTP) would go here.
        # For now, we simulate success to prevent enumerating user emails.
        flash('If an account exists with that email, a recovery link has been sent.', 'info')
        return redirect(url_for('home'))
        
    #Render the forgot password recovery page template if accessed via GET.
    return render_template('forgot_password.html')

#Route for the '/logout' URL that clears user sessions and returns them to the home screen.
@app.route('/logout')
def logout():
    #Clear all session data.
    session.clear()
    return redirect(url_for('home'))

#Route for the '/dashboard' URL that handles guest sessions, persistent files, security scans, and uploads.
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    
    #Check if the user entered via the guest mode query parameter.
    if request.args.get('mode') == 'guest':
        #Clear the session and activate the volatile guest mode toggle.
        session.clear()
        session['is_guest'] = True
        
    #Security redirection if neither a logged-in user nor an active guest session exists.
    if not session.get('user_id') and not session.get('is_guest'):
        return redirect(url_for('home'))

    #Initialize report_data, user_files, chart_list, and active_filename as empty containers.
    report_data = None
    user_files = []
    chart_list = []
    active_filename = None
    
    #Check if the user clicked 'Analyze' on a saved dataset (passed via URL query parameter).
    active_file_id = request.args.get('load_file',type=int)

    #If logged in as a registered user, query the database for their saved files.
    if session.get('user_id'):
        user_files = StoredFile.query.filter_by(user_id=session['user_id']).all()
        
        #If an active file was selected, fetch it for the inspector view.
        if active_file_id:
            #Query the specific file ID making sure it actually belongs to the current user.
            target_file = StoredFile.query.filter_by(id=active_file_id, user_id=session['user_id']).first()
            if target_file:
                #Strip the 8-character UUID off the front so the frontend displays a clean filename to the user.
                active_filename = target_file.filename.split('_', 1)[-1] if '_' in target_file.filename else target_file.filename
                
                #Fetch the raw stream from B2.
                file_stream = download_from_b2(target_file.filename)
                
                #If the cloud download succeeds, pass the data to the math engine.
                if file_stream:
                    #RACHEL'S ENGINE
                    raw_bytes = file_stream.read()
                    buffer = io.BytesIO(raw_bytes)
                    buffer.seek(0)
                    
                    #Instantiate the Dataset class and generate the mathematical report dictionary.
                    active_dataset = Dataset(buffer)
                    report_data = active_dataset.generate_report()

                    #Pass the dataset and report into Liam's DataVisualizer to generate the Base64 image strings.
                    visualizer = DataVisualizer(active_dataset, report_data)
                    chart_list = visualizer.generate_charts(max_charts=4)

    #Safety check to process file upload submissions only if the user made a POST request.
    if request.method == 'POST':
        
        #Safety check to ensure the HTTP request actually contains a file part under the 'dataset' field.
        if 'dataset' not in request.files:
            return "No file part in request", 400
            
        #Extract the file from the request and save to variable.
        file = request.files['dataset']
        
        #Safety check in case the user clicked submit without selecting a file.
        if file.filename == '':
            return "No selected file", 400
            
        #Call allowed_file function to verify the uploaded file is strictly a CSV.
        if file and allowed_file(file.filename):
            
            #Sanitize the filename to prevent directory traversal attacks.
            base_filename = secure_filename(file.filename)
            
            #STORAGE FIX: Append a random 8-character UUID to the front to guarantee the file never overwrites an existing B2 object.
            filename = f"{uuid.uuid4().hex[:8]}_{base_filename}"
            
            #Set the active filename so the HTML template can cleanly display what was just processed.
            active_filename = base_filename 
            
            #Call check_virustotal function to run malware scanning. If it returns False, block upload entirely.
            if not check_virustotal(file):
                flash("Upload rejected: Malicious file or unavailable report from VirusTotal.", "danger")
                return redirect(url_for('dashboard'))
                
            #Call upload_to_b2 function to import the sanitized, unique file to Backblaze B2.
            b2_url = upload_to_b2(file, filename)
            
            #Safety check to ensure the cloud upload actually worked before proceeding.
            if not b2_url:
                flash("Storage error: Could not connect to cloud bucket", "danger")
                return redirect(url_for('dashboard'))
                
            #Save file reference to database ONLY if user is logged in (Guest files are temporary and discarded).
            if session.get('user_id'):
                new_file = StoredFile(filename=filename, b2_url=b2_url, user_id=session['user_id'])
                db.session.add(new_file)
                db.session.commit()
                user_files = StoredFile.query.filter_by(user_id=session['user_id']).all()

            #Set report_data string output confirming success and VirusTotal scan validation.
            flash(f"Success! File safely scanned and stored in the cloud.", "success")
            
            #GUEST ANALYSIS FIX: Immediately process the newly uploaded file through the math engines so guests actually see their results.
            file.seek(0)
            active_dataset = Dataset(file)
            report_data = active_dataset.generate_report()
            visualizer = DataVisualizer(active_dataset, report_data)
            chart_list = visualizer.generate_charts(max_charts=4)
            
        #Else clause if user attempts to upload a non-CSV file.
        else:
            flash("Invalid file type. Only CSV allowed.", "danger")
            return redirect(url_for('dashboard'))
            
    #Render the dashboard template, passing through stats reports, user file lists, chart visuals, and the active filename.
    return render_template('dashboard.html', stats=report_data, user_files=user_files, charts=chart_list, active_file=active_filename)

#Route for deleting a user's saved dataset
@app.route('/delete/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    #Verify the user is logged in
    if not session.get('user_id'):
        return redirect(url_for('home'))

    #Query the database to find the specific file, ensuring the current user owns it
    file_record = StoredFile.query.filter_by(id=file_id, user_id=session['user_id']).first()
    
    if file_record:
        #STORAGE FIX: Attempt to delete the file from the cloud bucket first.
        if delete_from_b2(file_record.filename):
            #If cloud deletion succeeds, remove the record from the Neon PostgreSQL database.
            db.session.delete(file_record)
            db.session.commit()
            
            #Strip the UUID to output a clean success message to the user.
            clean_name = file_record.filename.split('_', 1)[-1]
            flash(f"Dataset {clean_name} successfully deleted.", "success")
        else:
            #If cloud deletion fails, leave the database record intact to prevent orphaned files in B2.
            flash("Failed to delete file from cloud storage.", "danger")
    else:
        #Error if the file ID doesn't exist or belongs to another user.
        flash("File not found or unauthorized.", "danger")
        
    return redirect(url_for('dashboard'))

#END OF MAIN
if __name__ == "__main__":
    #Pull the assigned port from the environment, defaulting to 8000 if not found.
    port = int(os.environ.get("PORT", 8000))
    
    #Run the Flask development server on all network interfaces (0.0.0.0) with debug mode turned off.
    app.run(host="0.0.0.0", port=port, debug=False)