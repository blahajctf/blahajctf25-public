FROM debian:trixie

RUN apt-get update && \
  apt-get install -y socat python3 && \
  rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 1001 ctfuser && \
  useradd --uid 1001 --gid 1001 --system --comment "" -s /usr/bin/nologin ctfuser && \
  echo 'ctfuser ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

RUN mkdir -m 555 /app

COPY --chown=root:ctfuser --chmod=444 ./flag.txt /flag.txt
COPY --chown=root:ctfuser --chmod=444 ./waiting_room.py /app/waiting_room.py

WORKDIR /app
USER ctfuser
EXPOSE 1337

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:\"/bin/python3 /app/waiting_room.py\",stderr"]
