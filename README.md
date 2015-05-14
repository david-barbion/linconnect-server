linconnect-server
=================

Mirror Android notifications on a Linux desktop.

Bluetooth capable LinConnect Client from Varod: https://github.com/varod/linconnect-client/tree/bluetooth

Original LinConnect Client from Hauckwill: https://github.com/hauckwill/linconnect-client/

Introduction
------------
LinConnect is a project to mirror *all* Android notifications on a Linux desktop using LibNotify.

This application is hugely based on Hauckwill jobs (https://github.com/hauckwill/linconnect-server). It also contains bluetooth support added by Evilny0 (https://github.com/evilny0/linconnect-server/tree/bluetooth).

Installation
------------

**Requirements**

* python2
* python-pip
* python-gobject
* libavahi-compat-libdnssd1
* cherrypy (python package)

**Running**

Simply run `linconnect_server.py` to start the server, then start the Android application. The Android application will detect the server and display it in the server list. Selecting it will send a test notification to the server.

**Simple Setup (tested on Ubuntu 13.10 and 14.10)**

Enter the following command into a console to install the server, set it to autostart, and run LinConnect. The server will be automatically updated daily.

```bash
$ wget --quiet https://raw.github.com/hauckwill/linconnect-server/master/LinConnectServer/install.sh; \
chmod +x install.sh; \
./install.sh
```

To remove LinConnect, delete the ~/.linconnect directory.
        
Client Download
---------------

![alt text](https://developer.android.com/images/brand/en_app_rgb_wo_60.png "Google Play")

A binary of the client may be downloaded from the Google Play Store.

https://play.google.com/store/apps/details?id=com.willhauck.linconnectclient

Check Varod github page for bluetooth aware client also: https://github.com/varod/linconnect-client
