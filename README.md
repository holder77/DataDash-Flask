# 📊 DataDash

[![Live Demo](https://img.shields.io/badge/Live_Demo-datadash--flask.onrender.com-success?style=for-the-badge)](https://datadash-flask.onrender.com)

**DataDash** is an interactive data visualization and statistical analysis web application. Designed to securely accept, process, and analyze `.csv` dataset uploads, the platform isolates file uploads in a secure pipeline, verifies them against global threat intelligence databases, and safely stores them in an isolated cloud bucket before executing mathematical data analysis. 

Wrapped in a custom retro 8-bit "Dark Arcade" aesthetic, DataDash offers a gamified yet professional environment for statistical processing.

## ✨ Core Features
* **Automated Malware Scanning:** Payloads are scanned via the VirusTotal API using SHA-256 hashing. Network drops or missing API keys strictly "fail closed" to ensure zero malicious files bypass the filter.
* **Math & Visualization Engine:** Dynamically calculates descriptive statistics (mean, median, min, max, standard deviation) and generates Matplotlib histograms and pie charts instantly using an isolated in-memory buffer (`io.BytesIO`).
* **Secure Cloud Storage:** Integrates with Backblaze B2 to permanently store datasets for authenticated users, utilizing UUID-prefixing to guarantee zero file overwrite collisions.
* **Robust Access Control:** Features permanent user accounts with encrypted passwords, volatile guest sessions, and server-side IP rate-limiting (5-minute lockouts) to prevent brute-force authentication attacks.

## 🛠️ Tech Stack
* **Backend:** Python 3.11, Flask, SQLAlchemy
* **Database:** Neon Serverless PostgreSQL (`psycopg2`)
* **Cloud Infrastructure:** Backblaze B2 (via `boto3`), Render (Hosting)
* **Security:** VirusTotal API, Werkzeug Security
* **Data Processing:** Python `csv`, `statistics`, Matplotlib (Base64 inline HTML rendering)
* **Frontend:** HTML5, Bootstrap 5, Custom CSS, Jinja2

## 🚀 Local Development Setup

DataDash utilizes Docker for containerized local development.

1. **Clone the repository:**
   ```bash
   git clone https://github.com/holder77/DataDash-Flask.git
   cd DataDash-Flask
   ```

2. **Configure Environment Variables:**
   Review the `.env.example` file and create a `.env` file in the project root with your own provisioned API credentials:
   ```ini
   SECRET_KEY=your_secure_flask_key
   DATABASE_URL=sqlite:///local_dashboard.db # Or your Neon PostgreSQL connection string
   VIRUSTOTAL_API_KEY=your_virustotal_key
   B2_KEY_ID=your_backblaze_key_id
   B2_APPLICATION_KEY=your_backblaze_app_key
   B2_BUCKET_NAME=your_bucket_name
   B2_ENDPOINT_URL=https://s3.us-west-XXX.backblazeb2.com
   ```

3. **Build and Launch via Docker:**
   ```bash
   docker compose up --build
   ```

4. **Access the Application:**
   Open a modern web browser and navigate to `http://localhost:8000`. You can use the included `SAMPLE.csv` to immediately test the upload pipeline and math engine.

## 👥 The Team (Data Dashers)
Built for UCCS CS 3300 (Intro to Software Engineering) by:
* **Josh Holder:** Infrastructure and Security Architect 
* **Rachel Promersberger:** Algorithmic Engineer 
* **Liam Rasmussen:** Quantitative Systems Engineer
* **Wendy-Germaine Tamajong:** UI/UX Experience Direction

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.