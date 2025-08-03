FROM ubuntu:18.04

RUN apt-get update && apt-get install -y \
    build-essential wget curl \
    libpam0g-dev zlib1g-dev \
    libselinux1 libedit-dev \
    libbsd-dev libkrb5-dev bzip2

RUN useradd -r -s /usr/sbin/nologin sshd

#  OpenSSL 1.0.2u
WORKDIR /usr/local/src
RUN wget https://www.openssl.org/source/old/1.0.2/openssl-1.0.2u.tar.gz && \
    tar xzf openssl-1.0.2u.tar.gz && \
    cd openssl-1.0.2u && \
    ./config --prefix=/usr/local/ssl && make && make install

ENV LD_LIBRARY_PATH=/usr/local/ssl/lib
ENV PATH="/usr/local/ssl/bin:$PATH"

#  OpenSSH 7.7p1
RUN wget https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-7.7p1.tar.gz && \
    tar xzf openssh-7.7p1.tar.gz && \
    cd openssh-7.7p1 && \
    ./configure --with-ssl-dir=/usr/local/ssl && \
    make && make install

RUN useradd -m kristin && echo 'kristin:thalia' | chpasswd

# Ajouter un flag dans /root
RUN echo "ghctf{T1m3_cAn_MaK3_D1ff3r3nce!}" > /root/flag.txt && chmod 444 /root/flag.txt && chmod 755 /root

# Config SSH
RUN mkdir /var/run/sshd && \
    echo "PermitRootLogin no" >> /usr/local/etc/sshd_config && \
    echo "PasswordAuthentication yes" >> /usr/local/etc/sshd_config && \
    echo "ChallengeResponseAuthentication no" >> /usr/local/etc/sshd_config

RUN echo 'for cmd in touch sudo echo vi nano vim tee cp mv python perl awk gcc g++ tar unzip zip curl wget head tail scp sftp bash sh; do alias $cmd="echo Command not allowed"; done' >> /home/kristin/.bashrc

EXPOSE 22
CMD ["/usr/local/sbin/sshd", "-D"]
