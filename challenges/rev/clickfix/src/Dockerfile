FROM lipanski/docker-static-website:latest

# Copy your static files
COPY . .

EXPOSE 1337

CMD ["/busybox-httpd", "-f", "-v", "-p", "1337"]