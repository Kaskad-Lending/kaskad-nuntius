#!/bin/bash
echo "Waiting for proxy to become healthy on ALB..."
while true; do
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" https://oracle.kaskad.live/health)
  if [ "$HTTP_CODE" == "200" ]; then
    SIGNER=$(curl -s https://oracle.kaskad.live/prices | jq -r '.[0].signer_address // empty')
    echo "HEALTHY! Signer: $SIGNER"
    break
  fi
  sleep 5
done
