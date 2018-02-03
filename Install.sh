#!/usr/bin/env bash

# Tested with CentOS 7

# Install Python3, Pip, Virtualenv and git

sudo yum -y install git
sudo yum -y install gcc
sudo yum -y install epel-release
sudo yum -y install python34
sudo yum -y install python34-devel
sudo yum -y install python34-setuptools
sudo python3 /usr/lib/python3.4/site-packages/easy_install.py pip
sudo -H pip3 install --upgrade pip
sudo -H pip3 install virtualenv

# Create VirtualEnv and activate

cd ~
virtualenv venv --python=python3.4
source venv/bin/activate

pip3 install -r google-python-security/requirements.txt