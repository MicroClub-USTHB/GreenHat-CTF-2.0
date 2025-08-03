FROM alpine:3.16

RUN apk add --no-cache \
      build-base \
      socat \
      tini

WORKDIR /challenge
COPY src/chall.c .
RUN gcc chall.c -o chall -fno-stack-protector

COPY src/flag.txt .

EXPOSE 9000
ENTRYPOINT ["/sbin/tini", "--","socat", "tcp-l:9000,reuseaddr,fork", "EXEC:./chall,stderr"]
