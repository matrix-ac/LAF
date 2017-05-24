FROM ubuntu
MAINTAINER Matrix-ac

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y build-essential clang libnfnetlink-dev libnetfilter-queue-dev
