FROM debian:12@sha256:9d11a2b1e25f5c84ae3d454ed51ef64f0cf07cbbc1ec25d689b9b0de7071ea66

RUN apt-get update && apt-get install -y socat

RUN addgroup --gid 1001 nonroot && \
    adduser --uid 1001 --gid 1001 --disabled-password --gecos "" nonroot && \
    echo 'nonroot ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

COPY ./chal /srv/app/run
COPY ./entry.sh /srv/app/entry.sh
RUN chmod 555 /srv/app/run
RUN chmod 555 /srv/app/entry.sh

EXPOSE 1337
USER 1001
WORKDIR /srv/app
CMD [ "/srv/app/entry.sh" ]
