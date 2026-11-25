FROM ubuntu:26.04@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_* \
    && (id ubuntu >/dev/null 2>&1 || useradd --create-home --shell /bin/sh ubuntu) \
    && usermod --password '-' ubuntu
COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /usr/local/bin/start-ssh-fixture
EXPOSE 2222
ENTRYPOINT ["/bin/sh", "/usr/local/bin/start-ssh-fixture"]
