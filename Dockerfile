FROM alpine

RUN apk add python2

ADD ping.py /