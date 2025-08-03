FROM node:18-alpine

RUN apk add --no-cache nginx

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

RUN mkdir -p /etc/nginx/conf.d

COPY nginx.conf /etc/nginx/nginx.conf

RUN mkdir -p /var/www/public
RUN mkdir -p /var/www/admin
RUN mkdir -p /var/www/files

RUN echo "ghctf{n61nx_3xpr3ss_p4th_tr4v3rs4l_m4st3r}" > /var/www/admin/flag.txt

RUN echo "public file" > /var/www/public/readme.txt
RUN echo "not the flag" > /var/www/files/backup.sql

RUN chown -R nginx:nginx /var/www

EXPOSE 80

CMD nginx && node server.js

