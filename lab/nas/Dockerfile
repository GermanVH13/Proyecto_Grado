FROM alpine:3.20
RUN apk add --no-cache vsftpd && mkdir -p /var/ftp/pub && chmod 555 /var/ftp
COPY vsftpd.conf /etc/vsftpd/vsftpd.conf
EXPOSE 21
CMD ["vsftpd", "/etc/vsftpd/vsftpd.conf"]
