#!/bin/bash
echo "Setting up CyberTool..."

# Update system and install dependencies
sudo apt update
sudo apt install -y python3-pip nmap tor proxychains metasploit-framework

# Install Go for Amass
if ! command -v go &> /dev/null; then
    sudo apt install -y golang
fi

# Install Amass
go install github.com/OWASP/Amass/v3/...@master

# Install Python dependencies
pip install -r requirements.txt

# Prompt user to start Tor service
echo -n "Would you like to start Tor services now? (y/n): "
read -r choice
if [[ "$choice" =~ ^[Yy]$ ]]; then
    sudo systemctl start tor
    if [ $? -eq 0 ]; then
        echo "Tor service started successfully."
    else
        echo "Failed to start Tor service. Check system logs or start manually with 'sudo systemctl start tor'."
    fi
else
    echo "Skipping Tor service startup. You can start it later with 'sudo systemctl start tor'."
fi

# Start Metasploit RPC (update password in config.py if changed)
msfrpcd -P password -S &

echo "Setup complete! Ensure wordlists are in place and run 'python main.py --help'."
