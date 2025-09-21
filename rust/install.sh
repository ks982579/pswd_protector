#!/bin/bash

# pswdstore Installer Script
# Installs pswdstore password manager to ~/.local/bin

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Installation paths
INSTALL_DIR="$HOME/.local/bin"
BINARY_NAME="pswdstore"
TARGET_PATH="$INSTALL_DIR/$BINARY_NAME"

echo -e "${BLUE}=== pswdstore Password Manager Installer ===${NC}"
echo ""

# Check if we're in the right directory
if [[ ! -f "Cargo.toml" ]] || [[ ! -f "src/main.rs" ]]; then
    echo -e "${RED}Error: Please run this installer from the pswdstore project root directory${NC}"
    echo -e "${YELLOW}Expected files: Cargo.toml, src/main.rs${NC}"
    exit 1
fi

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}Error: Rust/Cargo is not installed${NC}"
    echo -e "${YELLOW}Please install Rust from: https://rustup.rs/${NC}"
    exit 1
fi

echo -e "${BLUE}📋 Installation Details:${NC}"
echo -e "  • Binary will be installed to: ${GREEN}$TARGET_PATH${NC}"
echo -e "  • Data file location: ${GREEN}$HOME/.pswdstore.json${NC}"
echo -e "  • Installation directory: ${GREEN}$INSTALL_DIR${NC}"
echo ""

# Create installation directory if it doesn't exist
if [[ ! -d "$INSTALL_DIR" ]]; then
    echo -e "${YELLOW}📁 Creating installation directory: $INSTALL_DIR${NC}"
    mkdir -p "$INSTALL_DIR"
fi

# Check if PATH includes ~/.local/bin
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]] && [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo -e "${YELLOW}⚠️  Warning: $INSTALL_DIR is not in your PATH${NC}"
    echo -e "${YELLOW}   You may need to add this line to your ~/.bashrc or ~/.profile:${NC}"
    echo -e "${YELLOW}   export PATH=\"\$HOME/.local/bin:\$PATH\"${NC}"
    echo ""
fi

# Build the project
echo -e "${BLUE}🔨 Building pswdstore (release mode)...${NC}"
if cargo build --release; then
    echo -e "${GREEN}✓ Build successful${NC}"
else
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi

# Check if binary was created
BINARY_SOURCE="target/release/$BINARY_NAME"
if [[ ! -f "$BINARY_SOURCE" ]]; then
    echo -e "${RED}Error: Binary not found at $BINARY_SOURCE${NC}"
    exit 1
fi

# Install the binary
echo -e "${BLUE}📦 Installing binary...${NC}"
if cp "$BINARY_SOURCE" "$TARGET_PATH"; then
    echo -e "${GREEN}✓ Binary installed to $TARGET_PATH${NC}"
else
    echo -e "${RED}✗ Failed to install binary${NC}"
    exit 1
fi

# Make sure it's executable
chmod +x "$TARGET_PATH"

# Test the installation
echo -e "${BLUE}🧪 Testing installation...${NC}"
if "$TARGET_PATH" --version &> /dev/null; then
    VERSION=$("$TARGET_PATH" --version 2>/dev/null || echo "unknown")
    echo -e "${GREEN}✓ Installation successful!${NC}"
    echo -e "${GREEN}  Version: $VERSION${NC}"
else
    echo -e "${RED}✗ Installation test failed${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}🎉 pswdstore has been successfully installed!${NC}"
echo ""
echo -e "${BLUE}📚 Quick Start:${NC}"
echo -e "  1. Initialize your password store:"
echo -e "     ${GREEN}pswdstore your-pin --init${NC}"
echo ""
echo -e "  2. Add your first password:"
echo -e "     ${GREEN}pswdstore your-pin --new${NC}"
echo ""
echo -e "  3. Search for passwords:"
echo -e "     ${GREEN}pswdstore your-pin --get domain${NC}"
echo ""
echo -e "  4. List all passwords safely:"
echo -e "     ${GREEN}pswdstore your-pin --list${NC}"
echo ""
echo -e "${BLUE}📖 For more commands, run:${NC}"
echo -e "     ${GREEN}pswdstore --help${NC}"
echo ""

# Check PATH and provide guidance
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]] && [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo -e "${YELLOW}⚠️  PATH Configuration Needed:${NC}"
    echo -e "   Add ~/.local/bin to your PATH by running:"
    echo -e "   ${GREEN}echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc${NC}"
    echo -e "   ${GREEN}source ~/.bashrc${NC}"
    echo ""
    echo -e "   Or for the current session only:"
    echo -e "   ${GREEN}export PATH=\"\$HOME/.local/bin:\$PATH\"${NC}"
    echo ""
fi

echo -e "${BLUE}🔒 Security Note:${NC}"
echo -e "  • Your passwords are encrypted with AES-256-GCM"
echo -e "  • Data is stored in: ${GREEN}$HOME/.pswdstore.json${NC}"
echo -e "  • Always use a strong, memorable PIN"
echo -e "  • Consider backing up your encrypted data file"
echo ""
echo -e "${GREEN}Happy password managing! 🔐${NC}"