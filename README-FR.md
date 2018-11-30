# Auto_OpenVPN

Auto_OpenVPN a pour but de vous aider à automatiser le processus de création des fichiers de configuration OpenVPN.

Vous pouvez utilisez la configuration pré-remplis ou créez votre propre configuration qui répondra mieux a vos besoins en modifiant les valeurs dans config_file_generator().

# Prérequis

- OpenSSL est requis pour générer les certificats, OpenVPN et Easy-rsa sont requis pour générer les clés de sécurité.

- Soyez sûr que OpenVPN, Easy-rsa et OpenSSL sont installés avant d'utiliser ce script.

- Si ce n'est pas le cas, Exécutez la commande suivante : ```apt install openvpn openssl easy-rsa```

- Pour installer les paquets python qui sont nécessaire, Exécutez la commande suivante : ```pip install pyopenssl```

- Disposer d'un accès SSH correctement configuré afin de pouvoir accéder au client depuis le serveur.
  Il est recommandé d'utiliser l'échange par clés afin de ne pas avoir à rentrer de mot de passe.
  
- Assurer vous de disposer des droits en lecture et écriture dans le dossier où vous éxecuter le script.

- Diposer de ```sudo```et d'un utilisateur dans le groupe ```sudo``` afin de pouvoir éxecuter des commandes en mode root.

# Comment ca marche ?

Ce script a été conçu pour être lançé depuis la machine qui jouera le role de serveur OpenVPN. Deux fichiers seront crée : fichier server.conf - fichier client.conf

Laissez le fichier server.conf sur la machine qui jouera le rôle de serveur et déplacez le fichier client.conf sur la machine cliente. À la fin du script, il vous sera demandé si vous souhaitez déplacez le fichier client via scp et si vous souhaitez activer OpenVPN au démarrage de vos machines serveur et client.



1.  Vérifiez que le fichier de configuration par défaut réponde à vos besoins, si ce n'est pas le cas, modifiez les valeurs contenues dans  config_file_generator().

    config_file_generator() utilise la clé et la valeur contenue dans le dictionnaire pour créer le fichier de configuration, Donc assuré vous de faire correspondre la clé et la valeur lors de toutes modifications.

2.  Lancez le script

    Cela créera les CA et Cert nécéssaires pour OpenVPN, les fichiers de configuration pour le server et le client ainsi qu'une clé DH et une clé TLS.

    À la fin du script, vous obtiendrez un fichier serverVPN.conf et un fichier clientVPN.conf.

3.  Le fichier serverVPN.conf est votre fichier serveur, déplacé le dans le dossier ```/etc/openvpn/``` sur la machine serveur.

4.  Le  fichier clientVPN.conf est votre fichier client, déplacé le dans le dossier ```/etc/openvpn/``` sur la machine cliente.

    Pour démmarrer la connexion VPN, éxécutez la commande suivante sur le serveur : ```openvpn serverVPN.conf``` et éxecutez la commande suivante sur le client : ```openvpn clientVPN.conf```.

    Si vous souhaitez activez la connexion VPN à chaque démmarage, éxécutez la commande suivante sur la machine serveur et la machine cliente : ```systemctl enable openvpn@votrefichier.conf```

    Enjoy !

# TEST

TESTÉ OK DEBIAN 9.X

TESTÉ OK PYTHON 2.7.X
