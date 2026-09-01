FROM python:3.11-slim

WORKDIR /app

#Prevent Python from writing .pyc files and keep console output unbuffered
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

#Install required packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

#Copy the rest of the application
COPY . .

#Expose Flask's default port
EXPOSE 5000

#Start the Flask development server
CMD ["flask", "run", "--host=0.0.0.0"]

#Bind to 0.0.0.0 and dynamically read Koyeb's assigned PORT (defaults to 8000)
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "app:app"]