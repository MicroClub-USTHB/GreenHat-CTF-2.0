FROM python:3.8.5-slim-buster

RUN pip install flask gunicorn requests

COPY . /app

WORKDIR /app/src

EXPOSE 5000

CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app", "-t", "120", "-w", "8"]