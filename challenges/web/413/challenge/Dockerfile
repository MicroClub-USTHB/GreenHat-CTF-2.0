# Dockerfile for a simple Flask application 
FROM node:22-alpine3.20

WORKDIR /app



COPY src /app


RUN npm install --no-cache


EXPOSE 8000



CMD ["npm", "start"]