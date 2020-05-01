FROM        docker.io/centos:latest
MAINTAINER  Michaela.Lang@ctbto.org
EXPOSE      53/tcp
EXPOSE      53/udp
RUN         yum install -y python3 ; rm -fR /var/cache/yum ; \ 
            pip3 install dnslib dnspython docker docker-py
ENTRYPOINT ["/app.py"] 
COPY        app.py /app.py
