FROM kathara/base

RUN apt-get update && apt-get install -y \
    nmap \
    python3-pip \
    && pip3 install python3-nmap --break-system-packages \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
