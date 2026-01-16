FROM debian:trixie

RUN apt-get update && \
    apt-get install -y socat && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 1001 ctfuser && \
    useradd --uid 1001 --gid 1001 --system --comment "" -s /usr/bin/nologin ctfuser && \
    echo 'ctfuser ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

RUN mkdir -m 555 /app

COPY --chown=root:ctfuser --chmod=555 ./chall_patched /app/chall_patched
COPY --chown=root:ctfuser --chmod=555 ./libc.so.6 /app/libc.so.6
COPY --chown=root:ctfuser --chmod=555 ./ld-2.35.so /app/ld-2.35.so
COPY --chown=root:ctfuser --chmod=444 ./flag.txt /app/flag.txt

WORKDIR /app
USER ctfuser
EXPOSE 8000

CMD ["socat", "TCP-LISTEN:8000,reuseaddr,fork", "EXEC:/app/chall_patched,stderr"]
