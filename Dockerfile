# pinned by digest for reproducible builds; Dependabot proposes the updates
FROM python:3.14-alpine@sha256:f6a589d43c42b9e7f7dc67a12d37132491f362859a5d750607710cc56da3bc72

# fping and mtr are the probes; tzdata lets TZ set the time in the logs.
# pip and setuptools only install packages, and smoketrace installs none: they go, with what they bundle.
RUN python -m pip uninstall -y pip setuptools wheel; \
    rm -rf /usr/local/lib/python3*/ensurepip /root/.cache; \
    apk add --no-cache fping mtr tzdata \
 && mkdir /data

WORKDIR /app
COPY smoketrace.py index.html targets.ini ./

# Runs as root inside the container on purpose: raw ICMP needs CAP_NET_RAW, and the compose files drop every
# other capability, so root here holds that one and nothing else (with no-new-privileges and a read-only root).
ENV DB=/data/smoketrace.db TARGETS=/data/targets.ini BIND=0.0.0.0 PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
VOLUME /data
EXPOSE 8099
# an agent (SERVER set) serves nothing, so only the server is asked
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD [ -n "$SERVER" ] || wget -qO- "http://127.0.0.1:${PORT:-8099}/livez" || exit 1
CMD ["python", "smoketrace.py"]
