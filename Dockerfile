FROM golang:latest
LABEL authors="gsantomaggio"

COPY ./ /fuffa/

RUN    apt-get update
RUN    apt-get install -y clang llvm
RUN    cd /fuffa && make test
