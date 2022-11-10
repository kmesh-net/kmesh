#
# Dockerfile for building openEuler kmesh docker image.
# 
# Usage:
# docker build -f kmesh.dockerfile -t kmesh:1.0.1 .
# docker run -itd --privileged=true -v /mnt/cgroup2:/mnt/cgroup2 -v /sys/fs/bpf:/sys/fs/bpf -v /lib/modules:/lib/modules --name kmesh kmesh:1.0.1
#

# base image
FROM openeuler/openeuler:22.03-lts

# container work directory
WORKDIR /kmesh

# copy current directory files to container work directory
# start_kmesh.sh and may also need kmesh rpm package
ADD . /kmesh

# install pkg dependencies 
# RUN yum install -y kmod util-linux kmesh
RUN yum update -y \
    && yum install -y kmod \
    && yum install -y util-linux \
    && yum install -y kmesh-*.rpm

RUN cp /lib/modules/kmesh/kmesh.ko .

# expose port
EXPOSE 6789

# start kmesh service
ENTRYPOINT ["/bin/sh", "./start_kmesh.sh"]
