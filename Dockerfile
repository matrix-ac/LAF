FROM alpine:edge
ENV LANG C.UTF-8
 
MAINTAINER Matrix-ac

RUN set -x \
	&& apk update && apk upgrade \
	&& apk add --no-cache bash \
	&& apk add --no-cache meson \
	&& apk add --no-cache clang \
	&& apk add --no-cache libnfnetlink-dev \
	&& apk add --no-cache libnetfilter_queue-dev

#RUN apt-get install -y build-essential meson ninja-build clang clang-tools libnfnetlink-dev libnetfilter-queue-dev
