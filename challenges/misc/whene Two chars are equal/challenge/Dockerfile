# Dockerfile
FROM python:3-alpine

RUN apk add --no-cache socat

WORKDIR /app

COPY main.py .

# Listen on port 1337 and redirect input/output to main.py
ENTRYPOINT ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:'python main.py'"]
