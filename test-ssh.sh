#!/bin/bash

# Simple test script to verify GitHub secrets format
echo "=== Testing GitHub Secrets Format ==="
echo "Current directory: $(pwd)"
echo "Files in directory:"
ls -la

echo ""
echo "=== SSH Key Content Check ==="
if [ -f "ec2keypair.pem" ]; then
    echo "Local SSH key found. First and last lines:"
    head -1 ec2keypair.pem
    tail -1 ec2keypair.pem
    echo ""
    echo "SSH key validation:"
    ssh-keygen -l -f ec2keypair.pem
else
    echo "ERROR: ec2keypair.pem not found in current directory"
fi

echo ""
echo "=== Connection Test ==="
echo "Testing SSH connection..."
ssh -i ec2keypair.pem -o ConnectTimeout=10 -o StrictHostKeyChecking=no ec2-user@16.16.25.121 "echo 'Direct SSH test: SUCCESS'"
