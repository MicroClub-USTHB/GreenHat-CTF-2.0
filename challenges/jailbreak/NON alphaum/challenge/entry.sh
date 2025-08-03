#!/bin/sh
while true; do
    socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"python3 /challenge/app.py",stderr
done
