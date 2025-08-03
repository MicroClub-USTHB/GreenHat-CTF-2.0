FROM python:3.11-slim

RUN apt-get update && apt-get install -y socat sudo zsh && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -m ctfuser && echo 'ctfuser ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

WORKDIR /challenge

COPY app.py . 
COPY flag.txt .
COPY entry.sh .

# Set flag permissions: readable only by root
RUN chown root:root flag.txt && chmod 600 flag.txt

RUN chmod +x entry.sh

EXPOSE 1337

# Switch to non-root user
USER ctfuser

CMD ["./entry.sh"]
