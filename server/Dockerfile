# Attack-mode payload server (stage 2) — see server/attack_server.py.
# Stdlib only: no pip install, small image, fast build.
FROM python:3.12-slim

COPY attack_server.py /app/attack_server.py

EXPOSE 8080 8081
CMD ["python", "-u", "/app/attack_server.py"]
