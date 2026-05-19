#!/bin/bash

# Ligmashark Installation Script
# Distro-agnostic installer for libpcap, Go compilation, and global linking.

set -e

if [ -f /etc/debian_version ]; then
    echo "📦 Detected Debian/Ubuntu based system."
    sudo apt-get update
    sudo apt-get install -y libpcap-dev build-essential golang
elif [ -f /etc/arch-release ]; then
    echo "📦 Detected Arch Linux based system."
    sudo pacman -S --noconfirm libpcap base-devel go
elif [ -f /etc/fedora-release ]; then
    echo "📦 Detected Fedora based system."
    sudo dnf install -y libpcap-devel development-tools golang
else
    echo "⚠️ Unknown distribution. Please ensure 'libpcap' development headers and 'go' are installed manually."
fi


if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed or not in PATH. Please install Go 1.22+ and try again."
    exit 1
fi


echo "🛠️ Compiling Ligmashark..."
go mod tidy
go build -o ligmashark main.go

echo "🚚 Moving binary to /usr/local/bin..."
sudo mv ligmashark /usr/local/bin/ligmashark
sudo chmod +x /usr/local/bin/ligmashark


if command -v setcap &> /dev/null; then
    echo "🔒 Setting network capabilities on binary..."
    sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/ligmashark
fi

echo ""
echo "✅ Installation Complete!"
echo "🚀 You can now run the app from any terminal by typing: ligmashark"
echo ""
echo "Note: If you want AI analysis, make sure Ollama is installed (https://ollama.com)."


if ! command -v ollama &> /dev/null; then
    echo "💡 Pro-tip: Ollama was not detected. Install it to enable AI packet analysis!"
fi

exit 0