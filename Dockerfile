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

#SECURITY & ROUTING FIX: Expose port 8000 to correctly match the Gunicorn bind
EXPOSE 8000

#COMPILATION FIX: Removed the conflicting 'flask run' command.
#Bind to 0.0.0.0 and dynamically read the assigned cloud PORT (defaults to 8000).
#Using shell form (no brackets) so the $PORT environment variable evaluates correctly.
CMD gunicorn --bind 0.0.0.0:${PORT:-8000} --workers 2 app:app