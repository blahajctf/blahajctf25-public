FROM sagemath/sagemath:latest AS chroot

USER root

RUN apt-get update && apt-get install -y python3 python3-pip socat && rm -rf /var/lib/apt/lists/*
RUN mkdir -m 777 /app

USER sage

COPY . /app/

WORKDIR /app

EXPOSE 20001

CMD ["socat", "TCP-LISTEN:20001,nodelay,reuseaddr,fork", "EXEC:\"./run.sh\""]

# docker build . -t bls
# docker run -p 20001:20001 -d -t bls:latest