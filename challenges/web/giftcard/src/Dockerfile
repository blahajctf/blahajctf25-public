# start by pulling the python image
FROM python:3.8-alpine@sha256:3d93b1f77efce339aa77db726656872517b0d67837989aa7c4b35bd5ae7e81ba

# copy the requirements file into the image
COPY ./requirements.txt /app/requirements.txt

# switch working directory
WORKDIR /app

RUN apk update
RUN apk add haproxy
RUN apk add sslh

# install the dependencies and packages in the requirements file
RUN pip install -r requirements.txt

# copy every content from the local file to the image
COPY . /app
RUN chmod 555 /app/entry.sh
RUN chmod 444 /app/cert.pem
RUN chmod 444 /app/key.pem
RUN chmod 444 /app/haproxy.pem

RUN adduser --uid 1001 -D nonroot
EXPOSE 1337
USER 1001

# configure the container to run in an executed manner
CMD ["/app/entry.sh" ]
