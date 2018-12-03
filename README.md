[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![Generic badge](https://img.shields.io/badge/Python-2.7.X-<COLOR>.svg)](https://www.python.org/download/releases/2.7/)

# Auto_OpenVPN

Auto_OpenVPN is made to help you automate the process of creating OpenVPN configuration.

You can use the pre-built configuration file (Site-to-Site VPN) or you can create your own configuration file if needed by changing values in config_file_generator().

# Installation

- Be sure you have read and write rights in the directory where you are going to use this script.

  if not, run ```chown -R <user>: <file>```.

- In order to access your server via SSH tunnel you need an SSH client correctly configured. We recommand to use SSH key authentification.

- You must have ```sudo``` and a user in the group ```sudo``` in order to perform the commands in root mode.

  If not, run ```apt install sudo```.

- OpenSSL is required to generate certificates, OpenVPN and Easy-rsa are required to create keys.

  Make sure OpenVPN and OpenSSL are both installed before using this script.

  If not run ```apt install openvpn openssl easy-rsa```.

- PyOpenSSL is needed, to install it, RUN ```pip install pyopenssl```

# How it works

This script is designed to be run on the OpenVPN server. 

It will create 2 files : server file .conf - client file .conf

Leave the server file on the server machine and move the client file to the client machine. When finished, you will be asked if you want to transfer the client file on the client machine via scp and if you want to enable OpenVPN at boot on the server and via SSH on the client.



1.  First check if the configuration file for OpenVPN fits your needs, if not change the values in config_file_generator().

    Change `server_config_file['remote']` and `client_config_file['remote']` with the correct address of your server and client.
    
    config_file_generator() uses both key and value of the dict to create the configuration file, so be sure of what your doing before      changing them.

2.  run the script.

    It will create all the CA and Cert needed for OpenVPN, create the configuration file, generate a DH key and a tls key.

    At the end you will only have a serverVPN.conf and clientVPN.conf file.
    
3.  You will be asked if you want to transfer the client file on the client machine via scp.
    Make sure the correct address of your client machine has been changed in server_config_file['remote'].

4.  You will be asked if you want to enable OpenVPN at boot on both machine.

5.  The serverVPN.ovpn is your server file, move this one on the concerned server machine in /etc/openvpn/.

6.  The clientVPN.ovpn is your client file, move this one on the concerned client machine in /etc/openvpn/.

    To start the VPN connection run on the server machine the client file using ```openvpn serverVPN.conf``` and on the client machine the client file using ```openvpn clientVPN.conf```.
    

    Enjoy !

# TESTED

TESTED OK DEBIAN 9.X

TESTED OK PYTHON 2.7.X
