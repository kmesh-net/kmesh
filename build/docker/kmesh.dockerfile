FROM ghcr.io/kmesh-net/kmesh-build:latest AS builder
Copy . /kmesh
WORKDIR /kmesh
RUN ./build.sh && ./build.sh -i
# Copy the kmesh.ko to /kmesh
RUN if [ -f /lib/modules/kmesh/kmesh.ko ]; then cp /lib/modules/kmesh/kmesh.ko /kmesh; fi

FROM openeuler/openeuler:23.09
WORKDIR /kmesh
RUN \
    --mount=type=cache,target=/var/cache/dnf \
    yum install -y kmod util-linux iptables && \
    mkdir -p /usr/share/oncn-mda && \
    mkdir -p /etc/oncn-mda
COPY --from=builder /usr/lib64/libbpf.so* /usr/lib64/
COPY --from=builder /usr/lib64/libprotobuf-c.so* /usr/lib64/
COPY --from=builder /usr/lib64/libkmesh_api_v2_c.so /usr/lib64/
COPY --from=builder /usr/lib64/libkmesh_deserial.so /usr/lib64/
COPY --from=builder /usr/lib64/libboundscheck.so /usr/lib64/
COPY --from=builder /kmesh/*.ko /kmesh
COPY --from=builder /kmesh/oncn-mda/build/ebpf_src/CMakeFiles/sock_redirect.dir/sock_redirect.c.o /usr/share/oncn-mda/
COPY --from=builder /kmesh/oncn-mda/build/ebpf_src/CMakeFiles/sock_ops.dir/sock_ops.c.o /usr/share/oncn-mda/
COPY --from=builder /etc/oncn-mda/oncn-mda.conf /etc/oncn-mda/
COPY --from=builder /usr/bin/kmesh-daemon /usr/bin/
COPY --from=builder /usr/bin/kmesh-cni /usr/bin/
COPY --from=builder /usr/bin/mdacore /usr/bin/
COPY build/docker/start_kmesh.sh /kmesh
