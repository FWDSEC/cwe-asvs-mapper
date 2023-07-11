FROM python:3.12.0b1-slim-buster@sha256:6c097def9ba7a34c1574741e13cd3ef41e380b4b9ed44842b9b93762d57c012b

RUN pip install requests networkx

RUN mkdir /shared
RUN mkdir -p /opt/mappers/cwe-asvs-mapper
COPY cwe_asvs_mapper.py /opt/mappers/cwe_asvs_mapper.py
COPY cve_cwe_mapper.py /opt/mappers/cve_cwe_mapper.py
COPY main.py /opt/mappers/main.py

ENV INSIDE_DOCKER=1

ENTRYPOINT [ "python", "/opt/mappers/main.py" ]