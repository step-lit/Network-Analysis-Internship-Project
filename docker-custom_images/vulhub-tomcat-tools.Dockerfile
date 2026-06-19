FROM vulhub/tomcat:9.0.116

# Installa le utility necessarie per i tuoi test e monitoraggi
RUN apt-get update && apt-get install -y \
    iproute2 \
    procps \
    tcpdump \
    htop \
    && rm -rf /var/lib/apt/lists/*