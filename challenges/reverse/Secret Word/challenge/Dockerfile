FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /challenge

COPY src/secret.c .
COPY src/flag .
COPY src/secret .

EXPOSE 13800

ENTRYPOINT ["./secret"]
