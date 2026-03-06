# Build Windows .msi installer for Medusa Agent
#
# Usage: .\build_msi.ps1 [-Version "0.1.0"]
#
# Prerequisites:
#   - PyInstaller: pip install pyinstaller
#   - WiX Toolset v3: https://wixtoolset.org/

param(
    [string]$Version = "0.1.0"
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Resolve-Path "$ScriptDir\..\.."
$BuildDir = "$RootDir\build\windows-msi"
$DistDir = "$RootDir\dist"

Write-Host "Building Medusa Agent v$Version for Windows..."

# Clean
if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

# Build standalone binary with PyInstaller
Write-Host "Building binary with PyInstaller..."
Set-Location $RootDir
pyinstaller `
    --onefile `
    --name medusa-agent `
    --hidden-import medusa.agent `
    --hidden-import medusa.gateway `
    --hidden-import medusa.connectors.config_discovery `
    --exclude-module medusa.checks `
    --exclude-module medusa.reporters `
    --exclude-module medusa.compliance `
    --distpath "$BuildDir\bin" `
    src\medusa\cli\agent_cli.py

# Generate WiX source
$WixSource = @"
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
    <Product
        Id="*"
        Name="Medusa Security Agent"
        Language="1033"
        Version="$Version"
        Manufacturer="Medusa Security"
        UpgradeCode="A1B2C3D4-E5F6-7890-ABCD-EF1234567890">

        <Package
            InstallerVersion="200"
            Compressed="yes"
            InstallScope="perMachine"
            Description="Medusa endpoint security agent for MCP" />

        <MajorUpgrade DowngradeErrorMessage="A newer version is already installed." />
        <MediaTemplate EmbedCab="yes" />

        <Feature Id="ProductFeature" Title="Medusa Agent" Level="1">
            <ComponentGroupRef Id="ProductComponents" />
        </Feature>

        <Directory Id="TARGETDIR" Name="SourceDir">
            <Directory Id="ProgramFiles64Folder">
                <Directory Id="INSTALLFOLDER" Name="Medusa Agent" />
            </Directory>
        </Directory>

        <ComponentGroup Id="ProductComponents" Directory="INSTALLFOLDER">
            <Component Id="MainExecutable" Guid="*">
                <File Id="MedusaAgentExe"
                      Source="$BuildDir\bin\medusa-agent.exe"
                      KeyPath="yes" />
            </Component>
        </ComponentGroup>

        <!-- Add to PATH -->
        <Component Id="PathComponent" Directory="INSTALLFOLDER" Guid="*">
            <Environment Id="PATH"
                         Name="PATH"
                         Value="[INSTALLFOLDER]"
                         Permanent="no"
                         Part="last"
                         Action="set"
                         System="yes" />
        </Component>
    </Product>
</Wix>
"@

$WixPath = "$BuildDir\medusa-agent.wxs"
$WixSource | Out-File -FilePath $WixPath -Encoding UTF8

# Build MSI with WiX
Write-Host "Building MSI..."
candle.exe -nologo -out "$BuildDir\medusa-agent.wixobj" $WixPath
light.exe -nologo -out "$DistDir\medusa-agent-$Version.msi" "$BuildDir\medusa-agent.wixobj"

Write-Host ""
Write-Host "Build complete: $DistDir\medusa-agent-$Version.msi"
Write-Host ""
Write-Host "To install:"
Write-Host "  msiexec /i medusa-agent-$Version.msi"
Write-Host ""
Write-Host "To configure:"
Write-Host "  medusa-agent install --customer-id YOUR_ID --api-key YOUR_KEY"
