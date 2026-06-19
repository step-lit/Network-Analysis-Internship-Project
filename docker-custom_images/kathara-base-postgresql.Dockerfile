FROM kathara/base

RUN apt-get update && apt-get install -y \
    postgresql \
    procps \
    tcpdump \
    htop \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*