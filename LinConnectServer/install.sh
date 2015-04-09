#!/bin/bash
set -e
read -p "Install LinConnect server? [Y/N]" -n 1 -r
echo    # (optional) move to a new line
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    exit 1
fi

read -p "Install dependencies automatically (for Debian-based distros) [Y/N]" -n 1 -r
echo    # (optional) move to a new line
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    read -p "Install dependencies automatically (for Fedora distros) [Y/N]" -n 1 -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]
    then
	echo "Please manually install the following:"
	echo "* python2"
	echo "* python-pip"
	echo "* python-gobject"
	echo "* libavahi-compat-libdnssd1"
	echo "* cherrypy (python package)"
	
    else
	echo "Installing dependencies..."
	sudo yum install -y python2 python-pip pygobject2 git avahi-compat-libdns_sd
	echo "Installing Python dependencies..."
	sudo pip install cherrypy
    fi
else
	echo "Installing dependencies..."
	sudo apt-get install -y python-pip python-gobject git libavahi-compat-libdnssd1 gir1.2-notify-0.7
	echo "Installing Python dependencies..."
	sudo pip install cherrypy
fi

read -p "Press any key to continue..." -n 1 -r

echo "Installing LinConnect..."
git clone -q https://github.com/david-barbion/linconnect-server.git ~/.linconnect
cd ~/.linconnect
echo "Setting up LinConnect..."
git remote add upstream https://github.com/david-barbion/linconnect-server.git

read -p "Autostart LinConnect server on boot? [Y/N]" -n 1 -r
echo    # (optional) move to a new line
if [[ $REPLY =~ ^[Yy]$ ]]
then
    mkdir -p ~/.config/autostart/
	printf '[Desktop Entry]\nVersion=1.0\nType=Application\nHidden=false\nTerminal=false\nIcon=phone\nName=LinConnect\nExec=%s/.linconnect/LinConnectServer/update.sh\nPath=%s/.linconnect/LinConnectServer' $HOME $HOME > ~/.config/autostart/linconnect-server.desktop
	chmod +x ~/.config/autostart/linconnect-server.desktop
fi

chmod +x ~/.linconnect/LinConnectServer/update.sh

read -p "Install complete. Start LinConnect server now? [Y/N]" -n 1 -r
echo    # (optional) move to a new line
if [[ $REPLY =~ ^[Yy]$ ]]
then
    ~/.linconnect/LinConnectServer/update.sh
fi
