FROM ubuntu:22.04

RUN apt-get update -y \
 && apt-get install -y --no-install-recommends socat patchelf\
 && rm -rf /var/lib/apt/lists/*

RUN mkdir /challenge 
WORKDIR /challenge

COPY src/unusual .
COPY src/flag.txt .
COPY src/libc.so.6 .
COPY src/ld-linux-x86-64.so.2 .

RUN patchelf --set-interpreter "/challenge/ld-linux-x86-64.so.2" \
             --set-rpath "/challenge" \
             /challenge/unusual

EXPOSE 9000

ENTRYPOINT [ "socat", "tcp-l:9000,reuseaddr,fork", "EXEC:./unusual,stderr" ]