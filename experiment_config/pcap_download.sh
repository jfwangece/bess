#!/bin/bash

cd /local

# Download packet traces
sudo apt install -y python python-pip
pip install gdown==4.5.1
gdown "https://drive.google.com/uc?id=1F-G15cEi6TYZzVgbd5s3aCMhgLEQL0wX&amp;export=download&amp;confirm=t&amp;uuid=a4809991-9afa-4614-b866-a5733730946b"
