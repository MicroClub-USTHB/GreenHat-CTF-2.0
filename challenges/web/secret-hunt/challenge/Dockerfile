FROM python:3.9-slim

# Install dependencies
RUN pip install flask requests

# Create app directory
WORKDIR /app

# Copy application
COPY app.py /app/

# Create some sample files
RUN mkdir -p /app/docs && \
    echo "Welcome to FileShare Pro!" > /app/docs/readme.txt && \
    echo "Admin contact: admin@fileshare.local" > /app/docs/contacts.txt && \
    echo "# Internal Documentation" > /app/docs/internal.md

# Create non-root user
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

# Don't change to non-root user yet - we want the service account token accessible
# USER appuser

EXPOSE 5000

CMD ["python", "app.py"]