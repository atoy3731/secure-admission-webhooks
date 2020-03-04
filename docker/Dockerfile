FROM centos:7

USER root

RUN yum update -y && \
    yum install -y python3 && \
    curl -s https://bootstrap.pypa.io/get-pip.py | python3

COPY requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt

COPY application /opt/application

RUN useradd service-user && \
    chown -R service-user:service-user /opt/application

WORKDIR /opt/application

USER service-user

CMD [ "python3", "Webhook.py" ]
