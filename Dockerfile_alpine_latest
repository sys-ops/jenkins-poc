FROM alpine:latest  
MAINTAINER Daniel Andrzejewski daniel@danand.xyz
RUN apk update && apk add --no-cache tzdata curl
RUN ln -s /usr/share/zoneinfo/Europe/Warsaw /etc/localtime
WORKDIR /root/
COPY run.sh .
CMD ["/root/run.sh"]
