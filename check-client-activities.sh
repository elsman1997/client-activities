#!/bin/bash

# === Lightsail Client Activities Checker ===

INSTANCE_NAME=$1
WORKING_DIR=${2:-/var/www/html/bexel26}

if [ -z "$INSTANCE_NAME" ]; then
  echo "Usage: $0 <instance-name> [working-directory]"
  exit 1
fi

if ! aws sts get-caller-identity >/dev/null 2>&1; then
    echo "Error: AWS credentials not configured for user $(whoami)" >&2
    exit 1
fi

echo "=== Lightsail Client Activities Checker ==="
echo "Instance: $INSTANCE_NAME"
echo "Working directory: $WORKING_DIR"

# Get IP address for instance
echo "Getting IP address for instance: $INSTANCE_NAME"
INSTANCE_IP=$(aws lightsail get-instance --instance-name "$INSTANCE_NAME" \
  --query "instance.publicIpAddress" --output text)

if [ "$INSTANCE_IP" == "None" ] || [ -z "$INSTANCE_IP" ]; then
  echo "Error: Could not retrieve IP for instance $INSTANCE_NAME"
  exit 1
fi

echo "Instance IP: $INSTANCE_IP"
echo "Connecting to instance and checking activities..."

# Run the session check remotely
RESULTS=$(ssh -o StrictHostKeyChecking=no ubuntu@"$INSTANCE_IP" bash <<EOF
  now=\$(date +%s)
  cd "$WORKING_DIR"
  for f in storage/framework/sessions/*; do
    if grep -a -q 'email' "\$f"; then
      email=\$(grep -a -oP 'email";s:\\d+:"\\K[^"]+' "\$f" | head -1)
      name=\$(grep -a -oP 'name";s:\\d+:"\\K[^"]+' "\$f" | head -1)
      last_mod=\$(stat -c %Y "\$f")
      age_min=\$(( (now - last_mod) / 60 ))
      echo "{\\"email\\": \\"\$email\\", \\"name\\": \\"\$name\\", \\"last_seen_min\\": \$age_min}"
    fi
  done
EOF
)

# Save results to a standard JSON file
OUTPUT_FILE="./activities.json"
echo "[" > "$OUTPUT_FILE"
echo "$RESULTS" | sed '$!s/$/,/' >> "$OUTPUT_FILE"
echo "]" >> "$OUTPUT_FILE"

echo "================================================"
echo "Activity check completed."
echo "Results saved to $OUTPUT_FILE"
