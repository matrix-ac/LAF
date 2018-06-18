FROM ubuntu
MAINTAINER Matrix-ac

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y build-essential cmeson ninja-build clang clang-tools libnfnetlink-dev libnetfilter-queue-dev
