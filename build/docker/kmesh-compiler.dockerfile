#
# Dockerfile for building openEuler kmesh docker image.
# 
# Usage:
# docker build -f kmesh.dockerfile -t kmesh:latest .
# docker run -itd --privileged=true -v /usr/src:/usr/src -v /usr/include/linux/bpf.h:/kmesh/config/linux-bpf.h -v /etc/cni/net.d:/etc/cni/net.d -v /opt/cni/bin:/opt/cni/bin -v /mnt:/mnt -v /sys/fs/bpf:/sys/fs/bpf -v /lib/modules:/lib/modules --name kmesh kmesh:latest
#

# base image
FROM openeuler/openeuler:23.09

# Setup Go
COPY --from=golang:1.21.6 /usr/local/go/ /usr/local/go/
RUN mkdir -p /go
ENV GOROOT /usr/local/go
ENV GOPATH /go
ENV PATH "${GOROOT}/bin:${GOPATH}/bin:${PATH}"

WORKDIR /prepare
COPY kmesh_compile_env_pre.sh ./
COPY go.mod ./

# install pkg dependencies 
# RUN yum install -y kmod util-linux
# install package in online-compile image
RUN yum install -y kmod \
    && yum install -y util-linux

RUN go mod download \
    && go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.32.0

RUN bash kmesh_compile_env_pre.sh

# container work directory
WORKDIR /kmesh

