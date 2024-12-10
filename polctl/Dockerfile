FROM golang:1.17

# Install python + python packages
RUN apt-get update && apt-get install -y python3 python3-pip
RUN pip3 install pyyaml click requests

RUN mkdir -p /scripts
COPY scripts /scripts
