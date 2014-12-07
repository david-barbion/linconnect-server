'''
    LinConnect: Mirror Android notifications on Linux Desktop

    Copyright (C) 2013  Will Hauck

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

from __future__ import print_function

# Imports
try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser
import os
import sys
import select
import threading
import platform
import re
import glob
import hashlib

import cherrypy
import subprocess
from gi.repository import Notify
from gi.repository import GLib
import pybonjour
import shutil
import base64

import bluetooth
import json
import time

app_name = 'linconnect-server'
version = "2.20"

# Global Variables
_notification_header = ""
_notification_description = ""

# Configuration
script_dir = os.path.abspath(os.path.dirname(__file__))

def user_specific_location(type, file):
    dir = os.path.expanduser(os.path.join('~/.' + type, app_name))
    if not os.path.isdir(dir):
        os.makedirs(dir)
    return os.path.join(dir, file)

conf_file = user_specific_location('config', 'conf.ini')
icon_path_format = user_specific_location('cache', 'icon_cache_%s.png')

# Clear the icon cache
for icon_cache_file in glob.glob(icon_path_format % '*'):
    os.unlink(icon_cache_file)

old_conf_file = os.path.join(script_dir, 'conf.ini')
if os.path.isfile(old_conf_file):
    if os.path.isfile(conf_file):
        print("Both old and new config files exist: %s and %s, ignoring old one" % (old_conf_file, conf_file))
    else:
        print("Old config file %s found, moving to a new location: %s" % (old_conf_file, conf_file))
        shutil.move(old_conf_file, conf_file)
del old_conf_file

try:
    with open(conf_file):
        print("Loading conf.ini")
except IOError:
    print("Creating conf.ini")
    with open(conf_file, 'w') as text_file:
        text_file.write("""[connection]
port = 9090
enable_bonjour = 1
enable_bluetooth = 1

[other]
enable_instruction_webpage = 1
notify_timeout = 5000""")

parser = ConfigParser.ConfigParser()
parser.read(conf_file)
del conf_file

# Must append port because Java Bonjour library can't determine it
_service_name = platform.node()

class Notification(object):
    if parser.getboolean('other', 'enable_instruction_webpage') == 1:
        with open(os.path.join(script_dir, 'index.html'), 'rb') as f:
            _index_source = f.read()

        def index(self):
            return self._index_source % (version, "<br/>".join(get_local_ip()))

        index.exposed = True

    def notif(self, notificon):
        global _notification_header
        global _notification_description

        # Get notification data from HTTP header
        try:
            new_notification_header = base64.urlsafe_b64decode(cherrypy.request.headers['NOTIFHEADER'])
            new_notification_description = base64.urlsafe_b64decode(cherrypy.request.headers['NOTIFDESCRIPTION'])
        except:
            # Maintain compatibility with old application
            new_notification_header = cherrypy.request.headers['NOTIFHEADER'].replace('\x00', '').decode('iso-8859-1', 'replace').encode('utf-8')
            new_notification_description = cherrypy.request.headers['NOTIFDESCRIPTION'].replace('\x00', '').decode('iso-8859-1', 'replace').encode('utf-8')

        # Ensure the notification is not a duplicate
        if (_notification_header != new_notification_header) \
        or (_notification_description != new_notification_description):
            _notification_header = new_notification_header
            _notification_description = new_notification_description

            # Icon should be small enough to fit into modern PCs RAM.
            # Alternatively, can do this in chunks, twice: first to count MD5, second to copy the file.
            icon_data = notificon.file.read()
            icon_path = icon_path_format % hashlib.md5(icon_data).hexdigest()

            if not os.path.isfile(icon_path):
                with open(icon_path, 'w') as icon_file:
                    icon_file.write(icon_data)

            # Send the notification
            notif = Notify.Notification.new(_notification_header, _notification_description, icon_path)
            # Add 'value' hint to display nice progress bar if we see percents in the notification
            percent_match = re.search(r'(1?\d{2})%', _notification_header + _notification_description)
            if percent_match:
                notif.set_hint('value', GLib.Variant('i', int(percent_match.group(1))))
            if parser.has_option('other', 'notify_timeout'):
                notif.set_timeout(parser.getint('other', 'notify_timeout'))
            try:
                notif.show()
            except:
                # Workaround for org.freedesktop.DBus.Error.ServiceUnknown
                Notify.uninit()
                Notify.init("com.willhauck.linconnect")
                notif.show()

        return "true"
    notif.exposed = True

class bluetoothClientThread(threading.Thread):
	def __init__ (self, sock, info):
		threading.Thread.__init__(self)
		self.client_sock = sock
		self.client_info = info

	def run(self):
		print ("Starting bluetooth client thread")
		self.client_sock.setblocking(0)

		header_data_json = base64.b64decode(self.get_data())
		print ("Received [%s]" % header_data_json)
		header_data = json.loads(header_data_json)

		self.write_data(base64.b64encode("HEADEROK"))

		_notification_header = header_data["notificationheader"]
		_notification_description = header_data["notificationdescription"]

		icon_data = self.get_data()

		if (len(icon_data)):
			print ("Received icon (%s bytes)" % len(icon_data))
			self.write_data(base64.b64encode("ICONOK"))
			icon_path = icon_path_format % hashlib.md5(icon_data).hexdigest()
			if not os.path.isfile(icon_path):
				with open(icon_path, 'w') as icon_file:
					icon_file.write(icon_data)
			notif = Notify.Notification.new(_notification_header,_notification_description,icon_path)
		else:
			print ("No icon data received")
			notif = Notify.Notification.new(_notification_header,_notification_description)

		try:
			notif.show()
		except:
			pass

		print ("Closing client socket")
		self.client_sock.close()

	def get_data(self):
		total_data = []
		begin = time.time()
		timeout = 1
		while True:
			if (total_data and time.time()-begin > timeout):
				break
			elif (time.time()-begin > timeout*2):
				break

			try:
				data = self.client_sock.recv(1024)
				if data:
					total_data.append(data)
					begin = time.time()
				else:
					time.sleep(0.1)
			except IOError:
				pass

		return ''.join(total_data)

	def write_data(self,data):
		try:
			self.client_sock.send(data)
		except IOError:
			pass

def register_callback(sdRef, flags, errorCode, name, regtype, domain):
    if errorCode == pybonjour.kDNSServiceErr_NoError:
        print("Registered Bonjour service " + name)


def initialize_bonjour():
    sdRef = pybonjour.DNSServiceRegister(name=_service_name,
                                     regtype="_linconnect._tcp",
                                     port=int(parser.get('connection', 'port')),
                                     callBack=register_callback)
    try:
        try:
            while True:
                ready = select.select([sdRef], [], [])
                if sdRef in ready[0]:
                    pybonjour.DNSServiceProcessResult(sdRef)
        except KeyboardInterrupt:
            pass
    finally:
        sdRef.close()


def get_local_ip():
    ips = []
    for ip in subprocess.check_output("/sbin/ip address | grep -i 'inet ' | awk {'print $2'} | sed -e 's/\/[^\/]*$//'", shell=True).split("\n"):
        if ip.__len__() > 0 and not ip.startswith("127."):
            ips.append(ip + ":" + parser.get('connection', 'port'))
    return ips

def bluetooth_server():
	server_sock=bluetooth.BluetoothSocket( bluetooth.RFCOMM )
	server_sock.bind(("",bluetooth.PORT_ANY))
	server_sock.listen(1)

	port = server_sock.getsockname()[1]
	uuid = "ef466c25-8211-438a-9f39-b8ddecf1fbb8"
	bluetooth.advertise_service( server_sock, "linnconnect-server",
						       service_id = uuid,
						       service_classes = [ uuid, bluetooth.SERIAL_PORT_CLASS ],
						       profiles = [ bluetooth.SERIAL_PORT_PROFILE ],
						       )

	print ("Bluetooth server started, waiting for connections on RFCOMM channel %d" % port)

	try:
		while True:
			client_sock, client_info = server_sock.accept()
			print ("Accepted connection from ", client_info)
			th = bluetoothClientThread(client_sock,client_info)
			th.start()

	except IOError:
		pass

	print ("Bluetooth server exiting. Closing server socket.")
	server_sock.close()

# Initialization
if not Notify.init("com.willhauck.linconnect"):
    raise ImportError("Error initializing libnotify")

# Start Bonjour if desired
if parser.getboolean('connection', 'enable_bonjour') == 1:
    thr = threading.Thread(target=initialize_bonjour)
    thr.start()

# Start Bluetooth server if desired
if parser.getboolean('connection', 'enable_bluetooth') == 1:
    thr = threading.Thread(target=bluetooth_server)
    thr.start()

config_instructions = "Configuration instructions at http://localhost:" + parser.get('connection', 'port')
print(config_instructions)
notif = Notify.Notification.new("Notification server started (version " + version + ")", config_instructions, "info")
notif.show()

cherrypy.server.socket_host = '0.0.0.0'
cherrypy.server.socket_port = int(parser.get('connection', 'port'))

cherrypy.quickstart(Notification())
