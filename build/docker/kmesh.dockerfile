# Usage:
# docker run -itd --privileged=true -v /etc/cni/net.d:/etc/cni/net.d -v /opt/cni/bin:/opt/cni/bin -v /mnt:/mnt -v /sys/fs/bpf:/sys/fs/bpf -v /lib/modules:/lib/modules --name kmesh kmesh:latest
#
FROM openeuler/openeuler:23.09

WORKDIR /kmesh

ARG aarch

ADD out/$aarch/*so* /usr/lib64/
ADD out/$aarch/kmesh-daemon /usr/bin/
ADD out/$aarch/kmesh-cni /usr/bin/
ADD out/$aarch/kmesh-cmd /usr/bin/
ADD out/$aarch/mdacore /usr/bin/
ADD build/docker/start_kmesh.sh /kmesh

RUN mkdir /etc/kmesh
ADD config/kmesh.json /etc/kmesh

RUN yum install -y kmod util-linux