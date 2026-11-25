FROM debian:trixie-slim@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_* \
    && useradd --create-home --shell /bin/sh --password '-' ubuntu
COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /usr/local/bin/start-ssh-fixture
EXPOSE 2222
ENTRYPOINT ["/bin/sh", "/usr/local/bin/start-ssh-fixture"]
