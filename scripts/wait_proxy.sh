#!/bin/bash
echo "Waiting for proxy to become healthy on ALB..."
while true; do
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://kaskad-oracle-alb-670133639.us-east-1.elb.amazonaws.com/health)
  if [ "$HTTP_CODE" == "200" ]; then
    SIGNER=$(curl -s http://kaskad-oracle-alb-670133639.us-east-1.elb.amazonaws.com/prices | jq -r '.[0].signer_address // empty')
    echo "HEALTHY! Signer: $SIGNER"
    break
  fi
  sleep 5
done
