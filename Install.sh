#!/bin/bash

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
