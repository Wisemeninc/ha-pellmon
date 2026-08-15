# ha-pellmon — NBE pellet furnace <-> Home Assistant bridge.
#
# Single Python 3 process on a CURRENT base image. No PellMon, no
# Python 2, no D-Bus, no supervisord, no web UI: the entire legacy
# attack surface is gone. Talks the NBE UDP protocol directly using the
# protocol code vendored from the PellMon author's own py3
# implementation (motoz/nbetest, GPL).
FROM python:3.13-slim

# Run as an unprivileged user; the bridge needs no capabilities at all.
RUN useradd --system --uid 1000 --create-home bridge

WORKDIR /app
COPY bridge/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bridge/pellmon_ha_bridge.py bridge/nbe_gateway.py bridge/validation.py ./
COPY bridge/nbe/ ./nbe/

USER bridge

# All configuration and secrets arrive at runtime (env / mounted files);
# nothing is baked in. See .env.example.
ENV BRIDGE_CONFIG=/config/bridge_config.yaml \
    BRIDGE_LOGLEVEL=INFO

# The gateway touches /tmp/bridge-heartbeat every successful poll.
HEALTHCHECK --interval=60s --timeout=5s --start-period=60s CMD \
  python -c "import os,time,sys; sys.exit(0 if time.time()-os.path.getmtime('/tmp/bridge-heartbeat')<180 else 1)"

ENTRYPOINT ["python", "/app/pellmon_ha_bridge.py"]
