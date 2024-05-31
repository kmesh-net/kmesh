# Usage:
# docker run -itd --privileged=true -v /etc/cni/net.d:/etc/cni/net.d -v /opt/cni/bin:/opt/cni/bin -v /mnt:/mnt -v /sys/fs/bpf:/sys/fs/bpf -v /lib/modules:/lib/modules --name kmesh kmesh:latest
#
FROM openeuler/openeuler:23.09

WORKDIR /kmesh

ARG arch

RUN \
    --mount=type=cache,target=/var/cache/dnf \
    yum install -y kmod util-linux iptables

COPY out/$arch/*so* /usr/lib64/
COPY out/$arch/kmesh-daemon /usr/bin/
COPY out/$arch/kmesh-cni /usr/bin/
COPY out/$arch/mdacore /usr/bin/
COPY build/docker/start_kmesh.sh /kmesh
COPY out/$arch/ko /kmesh
