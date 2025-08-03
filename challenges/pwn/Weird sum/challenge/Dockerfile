FROM ubuntu:22.04

RUN apt-get update -y \
 && apt-get install -y --no-install-recommends socat\
 && rm -rf /var/lib/apt/lists/*

RUN mkdir /challenge 
WORKDIR /challenge

COPY  src/chall .
COPY  src/flag.txt .


EXPOSE 9000

ENTRYPOINT [ "socat", "tcp-l:9000,reuseaddr,fork", "EXEC:./chall,stderr" ]
