FROM kathara/base

RUN apt-get update && apt-get install -y \
    telnetd \
    openbsd-inetd \
    vsftpd \
    && rm -rf /var/lib/apt/lists/*