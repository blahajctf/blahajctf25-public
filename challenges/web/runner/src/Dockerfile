FROM php:8.2-apache@sha256:d2ba3ab5dcb2d1dd4a945fc379825afa0de38242e0f38f43140941f3ea0f4323
ADD app /app/src
COPY entry.sh /app/entry.sh
COPY flag.txt /flag.txt
WORKDIR /app/src

RUN chmod 555 /app/entry.sh
RUN chmod -R 555 /app/src
RUN chmod 444 /flag.txt

RUN adduser --system --uid 1001 nonroot
EXPOSE 1337
USER 1001

# configure the container to run in an executed manner
CMD ["/app/entry.sh" ]
