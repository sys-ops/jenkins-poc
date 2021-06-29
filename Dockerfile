FROM debian:9.5  
MAINTAINER Daniel Andrzejewski daniel@danand.xyz
RUN apt-get update && apt-get -y upgrade
#RUN ln -s /usr/share/zoneinfo/Europe/Warsaw /etc/localtime
WORKDIR /root/
COPY run.sh .
CMD ["/root/run.sh"]
