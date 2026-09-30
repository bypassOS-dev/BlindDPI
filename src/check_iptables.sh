#!/bin/bash

#=======Checking for the iptables
if command -v iptables &> /dev/null; then
    echo "iptables is already installed!"
else
    SUCCESSFULLY=false

    echo "iptables not found! Installing..."

    if command -v apt &> /dev/null; then
        sudo apt update &> /dev/null && sudo apt install -y iptables &> /dev/null && SUCCESSFULLY=true
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y iptables &> /dev/null && SUCCESSFULLY=true
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm iptables &> /dev/null && SUCCESSFULLY=true
    else
        echo "Could not determine your package manager, sorry."
    fi

    if [ "$SUCCESSFULLY" = true ]; then
        echo "Successfully installed! Moving on..."
    else
        echo "Failed to install iptables. Please install it manually."
        exit 1
    fi
fi

#=======Checking for the ip6tables
if command -v ip6tables &> /dev/null; then
    echo "ip6tables is already installed!"
else
    SUCCESSFULLY=false

    echo "ip6tables not found! Installing..."

    if command -v apt &> /dev/null; then
        sudo apt update &> /dev/null
        sudo apt install -y iptables &> /dev/null && SUCCESSFULLY=true
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y iptables &> /dev/null && SUCCESSFULLY=true
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm iptables &> /dev/null && SUCCESSFULLY=true
    else
        echo "Could not determine your package manager, sorry."
    fi

    if [ "$SUCCESSFULLY" = true ]; then
        echo "Successfully installed! Moving on..."
    else
        echo "Failed to install ip6tables. Please install it manually."
        exit 1
    fi
fi