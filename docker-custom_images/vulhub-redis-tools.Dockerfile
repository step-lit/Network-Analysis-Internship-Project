FROM vulhub/redis:5.0.7

# I tuoi strumenti di rete e diagnostica
RUN apt-get update && apt-get install -y \
    iproute2 \
    procps \
    tcpdump \
    htop \
    && rm -rf /var/lib/apt/lists/*