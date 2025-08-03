FROM ubuntu:22.04

RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y libc6:i386 libncurses5:i386 libstdc++6:i386 socat \
    && apt-get clean

RUN mkdir /challenge
WORKDIR /challenge

COPY src/chall /challenge
COPY src/flag.txt /challenge

EXPOSE 9000


ENTRYPOINT [ "socat", "tcp-l:9000,reuseaddr,fork", "EXEC:./chall,stderr" ]
