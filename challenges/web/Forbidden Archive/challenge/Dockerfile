# Use Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies for lxml
RUN apt-get update && apt-get install -y \
    libxml2-dev \
    libxslt-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY flag.txt .
COPY templates/ templates/

# Create a non-root user
RUN useradd -m -u 1000 ctf
RUN chown -R ctf:ctf /app
USER ctf

# Expose port
EXPOSE 5003

# Run the application
CMD ["python", "app.py"]
