# 
# Build LISP docker image based on the latest Ubuntu LTS or Rocky Linux. Both
# come off this one file, only the base image changes:
#
#   docker build -t lispers.net/ubuntu-latest .
#
#   docker build --build-arg BASE=rockylinux/rockylinux:10 \
#       -t lispers.net/rocky-latest .
#
# Then to run one of the above docker images in a container, type:
#
# docker run -p 8080 --privileged --name <name> -h <name> \
#            -v <host-dir>:/hostOS -ti lispers.net/ubuntu-latest
#
# where:
#   <name> is a container name you select                                
#   <host-dir> is directory on your host OS that maps to directory called
#              /hostOS inside your container for easy file movement
#
# This builds a python3-only image. Neither Ubuntu 24.04 nor Rocky 10 ships
# python2 packages at all, so the py2 install steps this file used to carry
# are gone and the py3 release tarball is used. Both distros ship python 3.12.
# The last py2-capable version of this file is in git history.
#
ARG BASE=ubuntu:24.04
FROM ${BASE}

#
# Install tools we need for a networking geek. Need the symlink so installing
# tzdata does not prompt for timezone input.
#
# The two distros name these packages differently:
#
#   libc-dev      -> glibc-devel      python3-dev -> python3-devel
#   libssl-dev    -> openssl-devel    libffi-dev  -> libffi-devel
#   libpcap-dev   -> libpcap-devel    iproute2    -> iproute
#   iputils-ping  -> iputils          procps      -> procps-ng
#   iptables      -> iptables-nft     vim         -> vim-enhanced
#   iperf         -> iperf3
#
# On Rocky, libpcap-devel only lives in the CRB repo, which is disabled by
# default, so it needs --enablerepo=crb. Without those headers pcapy-ng will
# not build.
#
# If "apt-get update" gets signature verification issues, run:
#
#    docker system prune --force
#
# And then rebuild.        
#
RUN if command -v apt-get > /dev/null; then \
        apt-get update -y && apt-get install -y curl wget; \
    else \
        dnf install -y --allowerasing curl wget tzdata; \
    fi
RUN ln -snf /usr/share/zoneinfo/US/Pacific /etc/localtime
RUN if command -v apt-get > /dev/null; then \
        apt-get install -y \
            gcc libc-dev python3 python3-dev python3-pip golang libffi-dev \
            openssl libssl-dev libpcap-dev \
            iptables iproute2 tcpdump tcsh sudo traceroute iputils-ping iperf \
            net-tools procps emacs vim jq file git; \
    else \
        dnf install -y --enablerepo=crb \
            gcc glibc-devel python3 python3-devel python3-pip golang \
            libffi-devel openssl openssl-devel libpcap-devel \
            iptables-nft iproute tcpdump tcsh sudo traceroute iputils iperf3 \
            net-tools procps-ng emacs vim-enhanced jq file git; \
    fi
RUN ln -s /usr/bin/python3 /usr/bin/python    

#
# Rocky ships the upstream GNU egrep and fgrep wrappers, which print
# "egrep: warning: egrep is obsolescent; using grep -E" on stderr. The lisp
# code shells out to egrep and reads it back with getoutput(), which merges
# stderr into stdout, so the warning gets parsed as data. is-lisp-running.py
# does an int() on one of those words and dies, and ./RL reports garbage file
# descriptors instead of socket names.
#
# Debian and Ubuntu patch their egrep to stay quiet. Replace Rocky's in place
# with the identical script rather than shadowing it from /usr/local/bin,
# because RHEL sudoers sets "secure_path = /sbin:/bin:/usr/sbin:/usr/bin" and
# RESTART-LISP runs under sudo, so a /usr/local/bin copy would be skipped.
#
RUN if ! command -v apt-get > /dev/null; then \
        printf '#!/bin/sh\ncmd=${0##*/}\nexec grep -E "$@"\n' \
            > /usr/bin/egrep && \
        printf '#!/bin/sh\ncmd=${0##*/}\nexec grep -F "$@"\n' \
            > /usr/bin/fgrep && \
        chmod 755 /usr/bin/egrep /usr/bin/fgrep; \
    fi

#
# Install LISP release in /lispers.net directory. Two options exist to get
# a lispers.net release. Get tarball from Dropbox or from git repo in
# build/latest-py3/lispers.net.tgz. Default is the git repo.
#
RUN mkdir /lispers.net

#
# Get lispers.net release. Dropbox option.
#        
#ENV LISP_URL https://www.dropbox.com/s/0t36qe03lh1t9c1/lispers.net.tgz
#RUN cd /lispers.net; curl --insecure -L $LISP_URL | gzip -dc | tar -xf - 

#
# Get lispers.net release. Git repo option.
#        
ENV LISP_TGZ ./latest-py3/lispers.net.tgz
COPY $LISP_TGZ /lispers.net/.
RUN cd /lispers.net; cat `basename $LISP_TGZ` | gzip -dc | tar -xf - 

#
# Install python3 modules the lispers.net directory depends on. Ubuntu 24.04
# marks the system python as externally managed (PEP 668), so pip needs
# --break-system-packages. Rocky does not, but its pip accepts the flag, so
# one command covers both. Rocky also does not bring in setuptools with
# python3-pip the way ubuntu does, hence it being listed here.
#
# Two modules the old py2 version of this file installed are intentionally
# left out:
#
#   pcrypto - does not build on python 3.12, pycryptodome replaces it.
#   pcappy  - python2 only, its packages do implicit relative imports which
#             python3 removed. lisp-itr.py, lisp-etr.py and lisp-rtr.py only
#             import pcappy under lisp_is_python2(), they use pcapy-ng under
#             lisp_is_python3().
#
RUN pip3 install --break-system-packages \
    cheroot bottle netifaces pcapy-ng pyOpenSSL requests setuptools \
    geopy ecdsa pycryptodome python-pytun future distro

#
# curve25519-donna is installed on its own because its C source assigns a
# void * to a long. Rocky 10 has gcc 14, which made -Wint-conversion an error
# rather than a warning, so the build fails unless it is demoted back. Ubuntu
# 24.04 still has gcc 13, where this flag is a no-op.
#
RUN CFLAGS="-Wno-error=int-conversion" pip3 install --break-system-packages \
    curve25519-donna

#
# Install what build/make-release.py needs so a lispers.net release can be
# built inside the container. pyobfuscate is not installed, it is python2 only
# and make-release.py sets obfuscate_on to False for a python3 build.
#
RUN pip3 install --break-system-packages pyflakes

#
# make-release.py builds a python2 release unless this is set. These images
# have no python2, so always build the python3 release.
#
ENV LISPERS.NET_PYTHON3=1

#
# The lispers.net-test-install.pyc in the release tarball has a stale module
# list, it tests for python2 module pcappy and tries to import "pcapy-ng",
# which is a pip distribution name and never a module name. Overwrite it with
# a build of the corrected script from this directory.
#
COPY ./lispers.net-test-install.py /lispers.net/.
RUN python3 -m compileall -b -q /lispers.net/lispers.net-test-install.py && \
    rm -f /lispers.net/lispers.net-test-install.py

#
# Start lispers.net with the release default lisp.config rather than letting
# lisp-core write a bare one on first start.
#
RUN cp /lispers.net/lisp.config.example /lispers.net/lisp.config

#
# Make prompt hostname/container name, allow web interface to work, and put us
# in the /lispers.net directory when you attach to container.
#
EXPOSE 8080
WORKDIR /lispers.net

#
# Start up LISP when container is created.
#
# Rocky's base image ships a /root/.tcshrc from the rootfiles rpm. tcsh reads
# ~/.tcshrc and only falls back to ~/.cshrc when it is absent, so that file
# has to be pointed at ours or none of these aliases load. Ubuntu ships no
# .tcshrc, where this symlink matches the one in Dino's home directory.
#
COPY ./RL.docker /lispers.net/RL
COPY ./.cshrc /root/.cshrc
RUN ln -sf /root/.cshrc /root/.tcshrc
CMD  /lispers.net/RL; sleep 1; /lispers.net/pslisp; tcsh

#------------------------------------------------------------------------------
