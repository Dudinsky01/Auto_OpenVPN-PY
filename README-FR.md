# Auto_OpenVPN

Auto_OpenVPN a pour but de vous aider à automatiser le processus de création des fichiers de configuration OpenVPN.

Vous pouvez utilisez la configuration pré-remplis ou créez votre propre configuration qui répondra mieux a vos besoins en modifiant les valeurs dans config_file_generator().

# Installation

OpenSSL est requis pour générer les certificats et OpenVPN est requis pour générer les clés de sécurité.

Soyez sûr que OpenVPN et OpenSSL sont installés avant d'utiliser ce script.

Si ce n'est pas le cas, Exécutez la commande suivante : ```apt install openvpn openssl easyrsa```

Pour installer les paquets python qui sont nécessaire, Exécutez la commande suivante : ```pip install pyopenssl```

# Comment ca marche ?

Ce script a été conçu pour être lançé depuis la machine qui jouera le role de serveur OpenVPN. Deux fichiers seront crée : fichier server.ovpn - fichier client.ovpn

Laissez le fichier server.ovpn sur la machine qui jouera le rôle de serveur et déplacez le fichier client.ovpn sur la machine cliente. À la fin du script, il vous sera demandé si vous souhaitez déplacez le fichier client via scp.



1.  Vérifiez que le fichier de configuration par défaut réponde à vos besoins, si ce n'est pas le cas, modifiez les valeurs contenues dans  config_file_generator().

    config_file_generator() utilise la clé et la valeur contenue dans le dictionnaire pour créer le fichier de configuration, Donc assuré vous de faire correspondre la clé et la valeur lors de toutes modifications.

2.  Lancez le script

    Cela créera les CA et Cert nécéssaires pour OpenVPN, les fichiers de configuration pour le server et le client ainsi qu'une clé DH et une clé TLS.

    À la fin du script, vous obtiendrez un fichier serverVPN.ovpn et un fichier clientVPN.ovpn.

3.  Le fichier serverVPN.ovpn est votre fichier serveur, déplacé le dans le dossier ```/etc/openvpn/``` sur la machine serveur.

4.  Le  fichier clientVPN.ovpn est votre fichier client, déplacé le dans le dossier ```/etc/openvpn/``` sur la machine cliente.

    Pour démmarrer la connexion VPN, éxécutez la commande suivante sur le serveur et le client : ```openvpn serverVPN.ovpn``` et ```openvpn clientVPN.ovpn```

    Si vous souhaitez démmarrer la connexion VPN à chaques démmarage, éxécutez la commande suivante sur la machine serveur et la machine cliente : ```systemctl enable openvpn```

    Enjoy !

# TEST

TESTÉ OK DEBIAN 9.X

TESTÉ OK PYTHON 2.7.X
