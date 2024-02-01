FROM openeuler/openeuler:23.09

WORKDIR /kmesh

ARG dir

ADD out/$dir/*so* /usr/lib64/
ADD out/$dir/kmesh-daemon /usr/bin/
ADD out/$dir/kmesh-cni /usr/bin/
ADD out/$dir/kmesh-cmd /usr/bin/
ADD out/$dir/mdacore /usr/bin/


RUN mkdir -p /usr/share/oncn-mda/

ADD out/$dir/sock_ops.c.o /usr/share/oncn-mda/
ADD out/$dir/sock_redirect.c.o /usr/share/oncn-mda/

RUN yum install -y kmod util-linux

EXPOSE 6789