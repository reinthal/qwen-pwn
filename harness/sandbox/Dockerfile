# Sandbox for the model's bash / run_python tool calls (inspect eval).
# Tools the trace's first command probes for: curl wget python3 jq.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl wget jq ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*

# trust the sinkhole's TLS CA (fallback server answers :443)
COPY --from=certs sinkhole-ca.crt /usr/local/share/ca-certificates/sinkhole-ca.crt
RUN update-ca-certificates

WORKDIR /tmp
