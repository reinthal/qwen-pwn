#!/bin/sh
# certbot --deploy-hook for the r0ck3t.net lineage: hand the cert to the
# honeypot user and restart the HTTP service. Also run manually by deploy.sh.
set -eu
LINEAGE="${RENEWED_LINEAGE:-/etc/letsencrypt/live/r0ck3t.net}"
case "$LINEAGE" in
  */r0ck3t.net) ;;
  *) exit 0 ;;
esac
DEST=/var/lib/qwen-honeypot/certs
install -d -o qwen-honey -g qwen-honey -m 0750 "$DEST"
install -o qwen-honey -g qwen-honey -m 0640 "$LINEAGE/fullchain.pem" "$DEST/fullchain.pem"
install -o qwen-honey -g qwen-honey -m 0640 "$LINEAGE/privkey.pem"   "$DEST/privkey.pem"
systemctl restart qwen-honeypot-http.service
echo "qwen-honeypot: installed certs from $LINEAGE and restarted qwen-honeypot-http"
