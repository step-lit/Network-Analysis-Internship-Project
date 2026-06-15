FROM kathara/base

RUN apt-get update && apt-get install -y \
    nmap \
    python3-pip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
   
RUN pip3 install python3-nmap requests --break-system-packages
