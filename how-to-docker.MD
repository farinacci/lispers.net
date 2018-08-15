
Quickstart Guide to Building Nexus/LISP Docker Images

(1) Install docker on your host computer system. Download docker from the
    docker download website https://download.docker.com for your OS platform.

(2) From the LLL-TAO directory, type:

    docker build -t tritium .

This will build a docker image called "tritium".

(3) To create and start the container, type:

    docker run -p 8080 --privileged --name nexus -h nexus -ti tritium

(4) To get into the container command-line shell, type:

    docker attach nexus

(5) To exit the container, type 2-character sequence:

    Control-P Control-Q

If you type control-D or exit, the container will stop.

(6) To look at your docker build images, type:

    docker images

You should see an image called "tritium" in the list.

(7) To look at your created containers, type:

    docker ps

You should see a container named "nexus"

When the container is started, the Nexus daemon and the LISP subsystem will
be operational.

-------------------------------------------------------------------------------





