FROM debian:12-slim

RUN apt update -y 
RUN apt install -y iproute2 mtr-tiny arping iputils-ping tcpdump
