# macOS -- Enterprise Deployment

Deploy the Medusa Agent across a fleet of macOS endpoints using enterprise
management tools.

---

## Kandji

### Step 1: Deploy Agent Configuration (Custom Profile)

Create a custom configuration profile to pre-stage the agent config before
installation.

1. Navigate to **Library > Custom Profiles**
2. Click **Add Profile**
3. Upload a `.mobileconfig` profile containing the Medusa configuration:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key>
      <string>com.medusa.agent</string>
      <key>PayloadIdentifier</key>
      <string>com.medusa.agent.config</string>
      <key>PayloadUUID</key>
      <string>YOUR-UUID-HERE</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>customer_id</key>
      <string>YOUR_CUSTOMER_ID</string>
      <key>api_key</key>
      <string>YOUR_API_KEY</string>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>Medusa Agent Configuration</string>
  <key>PayloadIdentifier</key>
  <string>com.medusa.agent.profile</string>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>YOUR-PROFILE-UUID</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
```

4. Assign to target **Blueprints**

### Step 2: Install the Agent (Custom App)

1. Navigate to **Library > Custom Apps**
2. Click **Add Custom App**
3. Select **Install Type: Custom Script**
4. Use the following install script:

```bash
#!/bin/bash
# Medusa Agent deployment script for Kandji

CUSTOMER_ID="YOUR_CUSTOMER_ID"
API_KEY="YOUR_API_KEY"

# Install the Python package
pip3 install medusa-mcp

# Install the agent (silent mode)
medusa-agent install --customer-id "$CUSTOMER_ID" --api-key "$API_KEY"
```

5. Assign to target Blueprints

### Step 3: Audit Script

Create an audit script to verify deployment status:

```bash
#!/bin/bash
# Check if Medusa Agent is running
if launchctl list | grep -q "com.medusa.agent"; then
    echo "Medusa Agent is running"
    exit 0
else
    echo "Medusa Agent is NOT running"
    exit 1
fi
```

---

## Jamf Pro

### Step 1: Configuration Profile

Create a Configuration Profile to pre-deploy agent settings:

1. Navigate to **Computers > Configuration Profiles**
2. Click **New**
3. Add an **Application & Custom Settings** payload
4. Upload a `.plist` with the Medusa agent configuration:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>customer_id</key>
  <string>YOUR_CUSTOMER_ID</string>
  <key>api_key</key>
  <string>YOUR_API_KEY</string>
</dict>
</plist>
```

5. Set the **Preference Domain** to `com.medusa.agent`
6. Scope to target computer groups

### Step 2: Deployment Policy

1. Navigate to **Computers > Policies**
2. Click **New**
3. Add a **Scripts** payload with the install script:

```bash
#!/bin/bash
# Medusa Agent deployment script for Jamf Pro

CUSTOMER_ID="YOUR_CUSTOMER_ID"
API_KEY="YOUR_API_KEY"

# Install the Python package
pip3 install medusa-mcp

# Install the agent
medusa-agent install --customer-id "$CUSTOMER_ID" --api-key "$API_KEY"
```

4. Set **Trigger**: Enrollment Complete or Recurring Check-in
5. Set **Execution Frequency**: Once per computer
6. Scope to target computer groups

### Step 3: Extension Attribute (Compliance)

Create an Extension Attribute to report agent status:

1. Navigate to **Settings > Extension Attributes**
2. Click **New**
3. Set **Data Type**: String
4. Set **Input Type**: Script
5. Use this script:

```bash
#!/bin/bash
if launchctl list | grep -q "com.medusa.agent"; then
    echo "<result>Running</result>"
else
    echo "<result>Not Running</result>"
fi
```

6. Use in Smart Groups for compliance reporting

---

## Generic MDM

For other MDM solutions, deploy via shell script:

```bash
#!/bin/bash
# Generic Medusa Agent deployment

CUSTOMER_ID="YOUR_CUSTOMER_ID"
API_KEY="YOUR_API_KEY"

# Install
pip3 install medusa-mcp

# Configure and start
medusa-agent install --customer-id "$CUSTOMER_ID" --api-key "$API_KEY"

# Verify
medusa-agent status
```

---

## Pre-Stage Configuration

To deploy the agent config before installation:

```bash
# Pre-create the config directory and file
MEDUSA_DIR="$HOME/.medusa"
mkdir -p "$MEDUSA_DIR"

cat > "$MEDUSA_DIR/agent-config.yaml" << EOF
customer_id: "YOUR_CUSTOMER_ID"
api_key: "YOUR_API_KEY"
agent_id: ""
telemetry_enabled: true
policy_sync_enabled: true
config_watch_enabled: true
config_monitor_enabled: true
EOF
```

Then install without specifying credentials (the installer will detect the
existing config):

```bash
medusa-agent install --skip-register
```

---

## Configuration Management

### Silent Install Flags

| Flag              | Use Case                                    |
| ----------------- | ------------------------------------------- |
| `--skip-daemon`   | Install config only; start service later    |
| `--skip-register` | Use pre-staged config; no dashboard call    |

### Environment Variables

You can set these before installation for non-interactive deployment:

| Variable              | Description                |
| --------------------- | -------------------------- |
| `MEDUSA_CUSTOMER_ID`  | Customer identifier        |
| `MEDUSA_API_KEY`      | API authentication key     |

---

## Fleet Verification

After deployment, verify agent status across the fleet:

```bash
# Check if the launchd service is loaded
launchctl list | grep com.medusa.agent

# Check agent health
medusa-agent status

# Check security posture
medusa-agent monitor
```

See [Confirming Deployment](confirming-deployment.md) for detailed verification
steps.
