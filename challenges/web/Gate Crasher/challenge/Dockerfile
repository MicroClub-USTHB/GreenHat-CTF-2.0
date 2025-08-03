FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app.py .
COPY templates/ templates/
COPY database/init_db.py database/

RUN python database/init_db.py

ENV FLAG="ghctf{SQL_1nj3ct10ns_m4st3r}"
EXPOSE 5000

CMD ["python", "app.py"]