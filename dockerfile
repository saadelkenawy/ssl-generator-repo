FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

RUN microdnf update -y && \
    microdnf install -y \
      python3 \
      python3-pip \
      bash \
      which \
      openssl \
    && pip3 install --upgrade urllib3 setuptools \
    && microdnf clean all

COPY ssl-generator.sh /usr/local/bin/ssl-generator.sh
RUN chmod +x /usr/local/bin/ssl-generator.sh

WORKDIR /output

CMD ["tail", "-f", "/dev/null"]

