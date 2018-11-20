# Auto_OpenVPN

Auto_OpenVPN is made to help you automate the process of creating OpenVpn configurations.

You can use the pre-built configuration file or you can create your own configuration file if needed by changing values in config_file_generator().

# Installation

OpenSSL is required to generate certificates and OpenVPN is required to create keys.

Make sure OpenVPN and OpenSSL are both installed before using this script.

If not run ```apt install openvpn openssl easy-rsa```.

To install needed python packages, RUN ```pip install pyopenssl```

# How it works

1.  First check if the configuration file for OpenVPN fits your needs, if not change the values in config_file_generator().

    config_file_generator() uses both key and value of the dict to create the configuration file, so be sure of what your doing before    changing them.

2.  run the script.

  It will create all the CA and Cert needed for OpenVPN, create the configuration file, generate a DH key and a tls key.

  At the end you will only have a serverVPN.ovpn and clientVPN.ovpn file.

3.  The serverVPN.ovpn is your server file, so move this one on the concerned server in /etc/openvpn/.

4.  The clientVPN.ovpn is your client file, so move this one on the concerned client in /etc/openvpn/.

To start the VPN connection run both server and client file using ```openvpn serverVPN.ovpn``` or ```openvpn clientVON.ovpn```

If you want OpenVPN to start the connection at every launch use ```systemctl enable openvpn```

Enjoy !

# TESTED

TESTED OK DEBIAN 9.X
TESTED OK PYTHON 2.7.X
