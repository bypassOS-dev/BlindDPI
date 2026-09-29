#!/bin/bash
if sudo iptables --version | grep -q "iptables v"; then
    echo "Iptables has already been downloaded!"
else
    SUCCESSFLLY=false

    echo "Iptables DON'T FOUND!  Don't worry, we download it..."

    if command -v apt &> /dev/null; then
        sudo apt update &> /dev/null && sudo apt install -y iptables &> /dev/null && SUCCESSFLLY=true
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y iptables &> /dev/null && SUCCESSFLLY=true
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm iptables &> /dev/null && SUCCESSFLLY=true
    else
        echo "We couldn't determin your packet menager, sorry"
    fi

    if [ "$SUCCESSFLY" = true ]; then
        echo "Successflly! Move on..."
    else
        echo "We don't download iptables, sorry. Make it yourself!"
        exit 1
    fi
fi