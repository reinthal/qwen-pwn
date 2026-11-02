#!/usr/bin/env bash
# Generate a CA + wildcard server cert for the sinkhole, install CA into system trust.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d certs ]; then mkdir certs; fi
cd certs

if [ -f sinkhole.crt ] && [ -f sinkhole.key ] && [ -f sinkhole-ca.crt ]; then
  echo "certs already exist, skipping generation"
else
  # CA
  openssl genrsa -out sinkhole-ca.key 2048 2>/dev/null
  openssl req -x509 -new -nodes -key sinkhole-ca.key -sha256 -days 825 \
    -out sinkhole-ca.crt -subj "/CN=Qwen Sinkhole CA" 2>/dev/null

  # server key + CSR
  openssl genrsa -out sinkhole.key 2048 2>/dev/null
  openssl req -new -key sinkhole.key -out sinkhole.csr \
    -subj "/CN=sanmaohe.oss-cn-beijing.aliyuncs.com" 2>/dev/null

  cat > sinkhole.ext <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature, keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names
[alt_names]
DNS.1=*.aliyuncs.com
DNS.2=aliyuncs.com
DNS.3=sanmaohe.oss-cn-beijing.aliyuncs.com
DNS.4=routify-file-proxy-sg.oss-ap-southeast-1.aliyuncs.com
DNS.5=r0ck3t.net
DNS.6=rimeless.com
DNS.7=tempbin.com
DNS.8=tmpfiles.org
DNS.9=paste.rs
DNS.10=r.jina.ai
DNS.11=logs.googleblog.com
DNS.12=files.myfilestore.com
DNS.13=sanitizer.test
DNS.14=probe.example.invalid
DNS.15=details.example.invalid
DNS.16=legit-cdn.example.com
DNS.17=example.com
DNS.18=example.invalid
DNS.19=localhost
DNS.20=*.oss-cn-beijing.aliyuncs.com
DNS.21=*.oss-cn-hangzhou.aliyuncs.com
DNS.22=*.oss-ap-southeast-1.aliyuncs.com
DNS.23=*.oss-us-east-1.aliyuncs.com
DNS.24=*.oss-cn-shanghai.aliyuncs.com
DNS.25=*.oss-cn-qingdao.aliyuncs.com
DNS.26=*.s3.us-west-2.amazonaws.com
DNS.27=*.blob.core.windows.net
DNS.28=*.europe-west1.run.gservice.dev
IP.1=127.0.0.1
IP.2=100.100.100.200
IP.3=192.0.2.10
EOF

  openssl x509 -req -in sinkhole.csr -CA sinkhole-ca.crt -CAkey sinkhole-ca.key \
    -CAcreateserial -out sinkhole.crt -days 825 -sha256 -extfile sinkhole.ext 2>/dev/null
  echo "generated sinkhole.crt / sinkhole.key / sinkhole-ca.crt"
fi

# Install CA into system trust store (so curl validates without -k)
if command -v update-ca-certificates >/dev/null 2>&1; then
  sudo cp sinkhole-ca.crt /usr/local/share/ca-certificates/qwen-sinkhole-ca.crt
  sudo update-ca-certificates 2>&1 | grep -v "^$" | tail -2
else
  echo "update-ca-certificates not found; TLS trust not installed" >&2
fi
