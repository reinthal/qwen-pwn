# per-sample sinkhole sidecar, in MinIO's network namespace: creates the public
# buckets, then runs server/sinkhole_server.py (odd ports + TLS :443); `sink.py
# dump` prints every stored object for canary_scorer
FROM python:3.12-slim
RUN pip install --no-cache-dir boto3
COPY sink.py /usr/local/bin/sink.py
