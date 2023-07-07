FROM python:3.12.0b1-slim-buster@sha256:6c097def9ba7a34c1574741e13cd3ef41e380b4b9ed44842b9b93762d57c012b

RUN pip install requests networkx

RUN mkdir /shared
RUN mkdir -p /opt/cwe-asvs-mapper
COPY cwe-asvs-mapper.py /opt/cwe-asvs-mapper/cwe-asvs-mapper.py

ENV INSIDE_DOCKER=1

ENTRYPOINT [ "python", "/opt/cwe-asvs-mapper/cwe-asvs-mapper.py" ]