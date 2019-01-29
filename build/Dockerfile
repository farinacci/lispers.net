# 
# Build LISP docker image based on ubuntu. Use one of the following commands:
#
#   docker build -t lispers.net/ubuntu .
#   docker build -t lispers.net/debian .
#   docker build -t lispers.net/centos .
#
FROM ubuntu:latest
#FROM debian:latest
#FROM centos:latest

#
# Install tools we need for a networking geek.
#
RUN apt-get update && apt-get install -y \
    gcc libc-dev python python-dev golang libffi-dev openssl libpcap-dev \
    curl iptables iproute2 tcpdump tcsh sudo traceroute iputils-ping \
    net-tools procps emacs vim jq

#
# Install LISP release in /lispers.net directory. Two options exist to get
# a lispers.net release. Get tarball from Dropbox or from git repo in
# build/latest/lispers.net.tgz. Default is Dropbox. One of the two needs
# to be commented out or you get the git repo option.    
#
RUN mkdir /lispers.net
        
#
# Dropbox option.
#        
ENV LISP_URL https://www.dropbox.com/s/0t36qe03lh1t9c1/lispers.net.tgz
RUN cd /lispers.net; curl --insecure -L $LISP_URL | gzip -dc | tar -xf - 

#
# Git repo option.
#        
#ENV LISP_TGZ ./latest/lispers.net.tgz
#COPY $LISP_TGZ /lispers.net/.
#RUN cd /lispers.net; cat `basename $LISP_TGZ` | gzip -dc | tar -xf - 

#
# Install python modules the lispers.net directory depends on.
#
RUN python /lispers.net/get-pip.py
RUN pip install -r /lispers.net/pip-requirements.txt

#
# Make prompt hostname/container name, allow web interface to work, and put us
# in the /lispers.net directory when you attach to container.
#
#RUN echo 'PS1="`hostname | cut -d . -f 0` > "' >> /root/.profile
EXPOSE 8080
WORKDIR /lispers.net

#
# Start up LISP when container is created.
#
COPY ./RL.docker /lispers.net/RL
CMD /lispers.net/RL; sleep 1; /lispers.net/pslisp; tcsh

#------------------------------------------------------------------------------
