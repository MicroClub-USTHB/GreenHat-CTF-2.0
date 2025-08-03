FROM alpine:latest

# Install dependencies
RUN apk add --no-cache \
    tor \
    torsocks \
    nodejs \
    npm \
    bash


# Create necessary tor directories and set permissions
RUN mkdir -p /var/lib/tor /etc/tor && \
    chown -R tor:tor /var/lib/tor /etc/tor && \
    mkdir -p /app && chown -R tor:tor /app

COPY tor/torrc /etc/tor/torrc
COPY tor/var/hidden_service /var/lib/tor/hidden_service



# Create app directory and set permissions
WORKDIR /app

# Copy package files first to leverage Docker cache
COPY src/package*.json ./

# Install Node.js dependencies
RUN npm install




# Copy the rest of the application code
COPY src/ .



# Create the entrypoint script inside the image


# give /var/lib/tor ownership to tor user
RUN chown -R tor:tor /var/lib/tor

RUN chmod 700 /var/lib/tor/hidden_service

# Switch to tor user
USER tor

# Expose app port
EXPOSE 8080

# Use the inline entrypoint script
CMD ["sh", "-c","tor & \
    sleep 5 && \
    node index.js"]