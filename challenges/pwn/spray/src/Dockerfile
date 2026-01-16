FROM debian:trixie

ENV DEBIAN_FRONTEND=noninteractive

# Install minimal dependencies
RUN apt-get update && \
    apt-get install -y socat curl qemu-system-x86 qemu-utils && \
    rm -rf /var/lib/apt/lists/*

# Create locked-down CTF user
RUN groupadd --gid 1001 ctfuser && \
    useradd --uid 1001 --gid 1001 --system --comment "" -s /usr/bin/nologin ctfuser && \
    echo 'ctfuser ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

# Application directory
RUN mkdir -m 555 /app

# Copy files into /app with correct perms and ownership
COPY --chown=root:ctfuser --chmod=555 ./bzImage      /app/bzImage
COPY --chown=root:ctfuser --chmod=555 ./deploy.sh    /app/deploy.sh
COPY --chown=root:ctfuser --chmod=444 ./flag.txt     /app/flag.txt
COPY --chown=root:ctfuser --chmod=555 ./rootfs.ext2  /app/rootfs.ext2

# Set working directory
WORKDIR /app

# Drop privileges
USER ctfuser

EXPOSE 5000

# Use socat + EXEC just like your model
CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:/app/deploy.sh,pty,stderr"]
