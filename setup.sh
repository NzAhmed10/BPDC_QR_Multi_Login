#!/bin/bash

# Install Chrome
apt-get update
wget http://dl.google.com/linux/deb/pool/main/g/google-chrome-unstable/google-chrome-unstable_114.0.5735.6-1_amd64.deb
sudo apt-get install -f ./google-chrome-unstable_114.0.5735.6-1_amd64.deb

sudo ln -s /opt/google/chrome-unstable/google-chrome google-chrome-stable