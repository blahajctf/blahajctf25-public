FROM lipanski/docker-static-website:latest

# Copy your static files
COPY ./background.jpg .
COPY ./index.html .
COPY ./logo.png .

EXPOSE 1337

CMD ["/busybox-httpd", "-f", "-v", "-p", "1337"]