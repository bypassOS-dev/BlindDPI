#!/bin/bash

#=======Checking for the nft
if command -v nft &> /dev/null; then
    echo "nft is already installed!"
else
    SUCCESSFULLY=false

    echo "nft not found! Installing..."

    if command -v apt &> /dev/null; then
        sudo apt update &> /dev/null
        sudo apt install -y nftables &> /dev/null && SUCCESSFULLY=true
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y nftables &> /dev/null && SUCCESSFULLY=true
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm nftables &> /dev/null && SUCCESSFULLY=true
    else
        echo "Could not determine your package manager, sorry."
    fi

    if [ "$SUCCESSFULLY" = true ]; then
        echo "Successfully installed! Moving on..."
    else
        echo -e "Failed to install nftables. Please install it manually(Ask AI or just to google it: \n'How install nftables to <<your_OS>>')."
        exit 1
    fi
fi
