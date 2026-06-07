FROM vulhub/apache-cxf:3.2.14

RUN apt-get update && \
    apt-get install -y iproute2 && \
    rm -rf /var/lib/apt/lists/*
