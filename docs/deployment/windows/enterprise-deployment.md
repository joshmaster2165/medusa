# Windows -- Enterprise Deployment

Deploy the Medusa Agent across a fleet of Windows endpoints using enterprise
management tools.

---

## Microsoft Intune

### Option A: PowerShell Script Deployment

Create a PowerShell script that installs and configures the agent:

```powershell
# medusa-deploy.ps1
# Deploy Medusa Agent via Intune

$customerID = "YOUR_CUSTOMER_ID"
$apiKey = "YOUR_API_KEY"

# Install the Python package
pip install medusa-mcp

# Install the agent (silent, no interactive prompts)
medusa-agent install --customer-id $customerID --api-key $apiKey
```

**Intune Configuration:**

1. Navigate to **Devices > Scripts and remediations > Platform scripts**
2. Click **Add > Windows 10 and later**
3. Upload `medusa-deploy.ps1`
4. Set **Run this script using the logged-on credentials** to **No** (run as SYSTEM)
5. Set **Run script in 64-bit PowerShell host** to **Yes**
6. Assign to target device groups

### Option B: Win32 App Package

For more control over detection and deployment:

1. Create a wrapper script:

    ```powershell
    # install.ps1
    pip install medusa-mcp
    medusa-agent install --customer-id %CUSTOMER_ID% --api-key %API_KEY%
    ```

2. Package using the [Microsoft Win32 Content Prep Tool](https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool):

    ```powershell
    IntuneWinAppUtil.exe -c .\source -s install.ps1 -o .\output
    ```

3. Upload the `.intunewin` package to Intune

4. **Detection Rule:**
    - Rule Type: **File**
    - Path: `%USERPROFILE%\.medusa`
    - File: `agent-config.yaml`
    - Detection Method: **File or folder exists**

5. **Install Command:** `powershell.exe -ExecutionPolicy Bypass -File install.ps1`
6. **Uninstall Command:** `medusa-agent uninstall`

---

## Group Policy (GPO)

### Startup Script Deployment

1. Create a deployment script (see PowerShell script above)
2. Open **Group Policy Management Console**
3. Create or edit a GPO linked to the target OU
4. Navigate to **Computer Configuration > Policies > Windows Settings > Scripts > Startup**
5. Add the PowerShell deployment script
6. The script runs at system startup with SYSTEM privileges

### Pre-Stage Configuration

To deploy the agent config before installation:

```powershell
# Pre-create the config directory and file
$medusaDir = "$env:USERPROFILE\.medusa"
New-Item -ItemType Directory -Path $medusaDir -Force

@"
customer_id: "YOUR_CUSTOMER_ID"
api_key: "YOUR_API_KEY"
agent_id: ""
telemetry_enabled: true
policy_sync_enabled: true
config_watch_enabled: true
config_monitor_enabled: true
"@ | Out-File -FilePath "$medusaDir\agent-config.yaml" -Encoding utf8
```

Then install without specifying credentials (the installer will detect the
existing config):

```powershell
medusa-agent install --skip-register
```

---

## SCCM / Configuration Manager

1. Create a new Application in SCCM
2. Use a Script-based deployment type
3. **Install Command:** `powershell.exe -ExecutionPolicy Bypass -File install.ps1`
4. **Detection Method:** File exists at `%USERPROFILE%\.medusa\agent-config.yaml`
5. **Uninstall Command:** `medusa-agent uninstall`
6. Deploy to target device collection

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

```powershell
# Check if the Windows Service exists and is running
sc.exe query MedusaAgent

# Check agent health
medusa-agent status

# Check security posture
medusa-agent monitor
```

See [Confirming Deployment](confirming-deployment.md) for detailed verification
steps.
