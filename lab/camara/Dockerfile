FROM alpine:3.20
# busybox-extras trae telnetd; busybox trae httpd
RUN apk add --no-cache busybox-extras
COPY www/ /www/
COPY httpd.conf /etc/httpd.conf
EXPOSE 23 80
# telnetd en segundo plano; httpd en primer plano mantiene vivo el contenedor
CMD ["sh", "-c", "telnetd -l /bin/login; exec httpd -f -h /www -c /etc/httpd.conf"]
