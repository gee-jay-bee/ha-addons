ARG BUILD_FROM
FROM $BUILD_FROM

RUN \
  apk add --no-cache \
    python3 tcpdump

RUN python3 -m ensurepip --default-pip
RUN pip3 install scapy requests icmplib

# Copy data for add-on
COPY run.sh dhcp_tracker.py /
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]

