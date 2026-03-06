#!/bin/bash
# Build macOS .pkg installer for Medusa Agent
#
# Usage: ./build_pkg.sh [version]
# Example: ./build_pkg.sh 0.1.0
#
# Prerequisites:
#   - PyInstaller: pip install pyinstaller
#   - macOS developer tools (pkgbuild, productbuild)

set -euo pipefail

VERSION="${1:-0.1.0}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$ROOT_DIR/build/macos-pkg"
DIST_DIR="$ROOT_DIR/dist"

echo "Building Medusa Agent v${VERSION} for macOS..."

# Clean
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/payload/usr/local/bin"
mkdir -p "$BUILD_DIR/payload/Library/LaunchAgents"
mkdir -p "$BUILD_DIR/scripts"
mkdir -p "$DIST_DIR"

# Build standalone binary with PyInstaller
echo "Building binary with PyInstaller..."
cd "$ROOT_DIR"
pyinstaller \
    --onefile \
    --name medusa-agent \
    --hidden-import medusa.agent \
    --hidden-import medusa.gateway \
    --hidden-import medusa.connectors.config_discovery \
    --exclude-module medusa.checks \
    --exclude-module medusa.reporters \
    --exclude-module medusa.compliance \
    --distpath "$BUILD_DIR/payload/usr/local/bin" \
    src/medusa/cli/agent_cli.py

# Copy launchd plist
cp "$SCRIPT_DIR/com.medusa.agent.plist" \
   "$BUILD_DIR/payload/Library/LaunchAgents/"

# Create postinstall script
cat > "$BUILD_DIR/scripts/postinstall" << 'POSTINSTALL'
#!/bin/bash
# Post-installation: set up directories
mkdir -p "$HOME/.medusa/logs"
chmod 755 /usr/local/bin/medusa-agent
echo "Medusa Agent installed successfully."
echo "Run 'medusa-agent install --customer-id YOUR_ID --api-key YOUR_KEY' to configure."
POSTINSTALL
chmod +x "$BUILD_DIR/scripts/postinstall"

# Build component package
echo "Building component package..."
pkgbuild \
    --root "$BUILD_DIR/payload" \
    --scripts "$BUILD_DIR/scripts" \
    --identifier "com.medusa.agent" \
    --version "$VERSION" \
    --install-location "/" \
    "$BUILD_DIR/medusa-agent-component.pkg"

# Build product package (distributable)
echo "Building product package..."
productbuild \
    --package "$BUILD_DIR/medusa-agent-component.pkg" \
    "$DIST_DIR/medusa-agent-${VERSION}.pkg"

echo ""
echo "Build complete: $DIST_DIR/medusa-agent-${VERSION}.pkg"
echo ""
echo "To install:"
echo "  sudo installer -pkg $DIST_DIR/medusa-agent-${VERSION}.pkg -target /"
echo ""
echo "To configure:"
echo "  medusa-agent install --customer-id YOUR_ID --api-key YOUR_KEY"
