# Usage:
# docker run -itd --privileged=true -v /etc/cni/net.d:/etc/cni/net.d -v /opt/cni/bin:/opt/cni/bin -v /mnt:/mnt -v /sys/fs/bpf:/sys/fs/bpf -v /lib/modules:/lib/modules --name kmesh kmesh:latest
#
FROM openeuler/openeuler:23.09

WORKDIR /kmesh

ARG dir

ADD out/$dir/*so* /usr/lib64/
ADD out/$dir/kmesh-daemon /usr/bin/
ADD out/$dir/kmesh-cni /usr/bin/
ADD out/$dir/kmesh-cmd /usr/bin/
ADD out/$dir/mdacore /usr/bin/
ADD build/docker/start_kmesh.sh /kmesh

RUN mkdir /etc/kmesh
ADD config/kmesh.json /etc/kmesh

RUN yum install -y kmod util-linux