# pinned by digest for reproducible builds; Dependabot proposes the updates
FROM python:3.14-alpine@sha256:f6a589d43c42b9e7f7dc67a12d37132491f362859a5d750607710cc56da3bc72

# fping and mtr are the probes; tzdata lets TZ set the time in the logs.
# PyMySQL (pure Python, no compiler) is the one package: it talks to MariaDB when DB=mariadb://...; SQLite needs none.
# It is pinned by hash in requirements.txt. Then pip and setuptools go, with what they bundle: nothing else is
# installed after this.
COPY requirements.txt /tmp/
# (a RUN of its own: a failed install, a hash that does not match, fails the build)
RUN python -m pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt
RUN python -m pip uninstall -y pip setuptools wheel; \
    rm -f /tmp/requirements.txt; \
    rm -rf /usr/local/lib/python3*/ensurepip /root/.cache; \
    apk add --no-cache fping mtr tini tzdata \
 && mkdir /data

WORKDIR /app
COPY smoketrace.py index.html targets.ini ./
COPY fonts ./fonts

# Runs as root inside the container on purpose: raw ICMP needs CAP_NET_RAW, and the compose files drop every
# other capability, so root here holds that one and nothing else (with no-new-privileges and a read-only root).
ENV DB=/data/smoketrace.db TARGETS=/data/targets.ini BIND=0.0.0.0 PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
VOLUME /data
EXPOSE 8099
# a push agent (SERVER) serves nothing; a pull agent (LISTEN=host:port) answers on its own port
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD [ -n "$SERVER" ] || { p="${LISTEN##*:}"; wget -qO- "http://127.0.0.1:${p:-${PORT:-8099}}/livez" >/dev/null; } || exit 1
# tini as PID 1 reaps every process that ends up orphaned (mtr's helpers when an mtr is killed); Python as PID 1
# would leave them as zombies until the container cannot start a process or a thread. -s: also under `init: true`.
ENTRYPOINT ["/sbin/tini", "-s", "--"]
CMD ["python", "smoketrace.py"]
