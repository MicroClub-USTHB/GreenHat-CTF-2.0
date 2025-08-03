# Dockerfile for a simple Flask application 
FROM python:3.11-alpine


LABEL author="conan"
LABEL description="A simple Flask application for the Dig Deeper challenge"
LABEL version="1.0"



WORKDIR /app


# Delete all unnecessary files to reduce image size
RUN rm -rf /var/cache/apk/* /root/.cache


RUN pip install --no-cache-dir flask pyjwt Unidecode gunicorn



COPY src /app


RUN mkdir -p /app/data 



EXPOSE 8000



CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "app:app"]