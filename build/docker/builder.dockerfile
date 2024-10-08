# Dockerfile for building kmesh-build docker image.
#
# Usage:
# docker build -f builder.dockerfile -t kmesh-build:latest .
#

# base image
FROM openeuler/openeuler:23.09

# Setup Go
COPY --from=golang:1.23.2 /usr/local/go/ /usr/local/go/
RUN mkdir -p /go
ENV GOROOT /usr/local/go
ENV GOPATH /go
ENV PATH "${GOROOT}/bin:${GOPATH}/bin:${PATH}"

WORKDIR /prepare
COPY go.mod ./

# install pkg dependencies 
# RUN yum install -y kmod util-linux
# install package in online-compile image
RUN yum install -y kmod \
    && yum install -y util-linux iptables

RUN go env -w GO111MODULE=on \
    && go mod download \
    && go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.32.0

RUN yum install -y git make clang llvm libboundscheck protobuf protobuf-c protobuf-c-devel bpftool libbpf libbpf-devel cmake pkg-config

# container work directory
WORKDIR /kmesh