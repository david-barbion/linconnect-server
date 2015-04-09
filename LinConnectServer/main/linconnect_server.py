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
from dbus.mainloop.glib import threads_init
threads_init()

from gi.repository import Gtk
from gi.repository import Gdk
from gi.repository import GObject
from gi.repository import AppIndicator3 as AppIndicator
from gi.repository import Notify
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

import gettext
gettext.bindtextdomain('linconnect-server', 'locale')
gettext.textdomain('linconnect-server')
_ = gettext.gettext

import shutil
import base64
from ZeroconfService import ZeroconfService

import bluetooth
import json
import time

import logging

app_name = 'linconnect-server'
version = "2.20"

# initialize logger
FORMAT='%(asctime)s %(name)s %(levelname)s %(message)s'
logging.basicConfig(format=FORMAT,level=logging.INFO)
logger = logging.getLogger(app_name)

# Global Variables
_notification_header = ""
_notification_description = ""
_notification_disabled = False

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
        logger.info("Both old and new config files exist: %s and %s, ignoring old one" % (old_conf_file, conf_file))
    else:
        logger.info("Old config file %s found, moving to a new location: %s" % (old_conf_file, conf_file))
        shutil.move(old_conf_file, conf_file)
del old_conf_file

try:
    with open(conf_file):
        logger.info("Loading conf.ini")
except IOError:
    logger.warning("Creating conf.ini")
    with open(conf_file, 'w') as text_file:
        text_file.write("""[connection]
port = 9090
enable_bluetooth = 1
enable_avahi = 1

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
		logger.debug ("Starting bluetooth client thread")
		self.client_sock.setblocking(True)

		bluetooth_data = self.read_data()
		try:
			header_data_json = base64.b64decode(bluetooth_data)
		except:
			logger.error("Malformed data [%s]" % bluetooth_data)
			self.client_sock.close()
			return

		logger.debug ("Received [%s]" % header_data_json)
		try:
			header_data = json.loads(header_data_json)
		except:
			logger.error("Malformed json data [%s]" % header_data_json)
			self.client_sock.close()
			return

		self.write_data(base64.b64encode("HEADEROK"))

		_notification_header = header_data["notificationheader"]
		_notification_description = header_data["notificationdescription"]

		icon_data = self.read_data()

		if (len(icon_data)):
			logger.debug ("Received icon (%s bytes)" % len(icon_data))
			self.write_data(base64.b64encode("ICONOK"))
			icon_path = icon_path_format % hashlib.md5(icon_data).hexdigest()
			if not os.path.isfile(icon_path):
				with open(icon_path, 'w') as icon_file:
					icon_file.write(icon_data)
  			notif = Notify.Notification.new(_notification_header,_notification_description,icon_path)
		else:
			logger.debug ("No icon data received")
			notif = Notify.Notification.new(_notification_header,_notification_description)

		if not _notification_disabled:
			try:
				notif.show()
			except:
				pass
		else:
			logger.debug("Notification disabled, skipped")

		logger.debug ("Closing client socket")
		self.client_sock.close()

	def read_data(self):
		data = ''
		try:
			while True:
				ready = select.select([self.client_sock,],[], [],2)
				if ready[0]:
					data += self.client_sock.recv(4096)
					logger.debug("data received %s" % data)
				else: 
					break
		except: # TODO get error
			pass
		logger.info("received %d bytes" % len(data))
		return data

	def write_data(self,data):
		try:
			self.client_sock.send(data)
		except IOError:
			pass

class LinconnectIndicator():
    def __init__(self):
        self.ind = AppIndicator.Indicator.new("Linconnect Indicator",
                                          "linconnect",
                                           AppIndicator.IndicatorCategory.APPLICATION_STATUS)
        self.ind.set_status(AppIndicator.IndicatorStatus.ACTIVE)
#        self.ind.set_attention_icon("indicator-messages-new")
        self.ind.set_icon_theme_path(os.getcwd() + "/res")
        #self.isIntegrated = self.checkIntegrated()
        self.ind.set_icon_full('linconnect', 'program icon')
        self.menu_setup()
        self.ind.set_menu(self.menu)
    
    def menu_setup(self):
        self.menu = Gtk.Menu()

        self.switch_notifications_item = Gtk.CheckMenuItem(_("Notifications"))
        self.switch_notifications_item.connect("activate", self.switch)
        self.switch_notifications_item.set_active(True)
        self.switch_notifications_item.show()

        self.seperator_item = Gtk.SeparatorMenuItem()
        self.seperator_item.show()

        self.about_item = Gtk.MenuItem(_("About"))
        self.about_item.connect("activate", self.about)
        self.about_item.show()

        self.exit_item = Gtk.MenuItem(_("Exit Linconnect"))
        self.exit_item.connect("activate", self.quit)
        self.exit_item.show()

        self.menu.append(self.switch_notifications_item)
        self.menu.append(self.about_item)
        self.menu.append(self.seperator_item)
        self.menu.append(self.exit_item)

    def switch(self, widget, data=None):
        global _notification_disabled
        if widget.get_active():
          _notification_disabled = False
          self.ind.set_icon_full('linconnect', 'program icon on')
          logger.info("Notification switched on")
        else:
          _notification_disabled = True
          self.ind.set_icon_full('linconnect-off', 'program icon off')
          logger.info("Notification switched off")

    def about(self, widget, data=None):
       dialog = Gtk.MessageDialog(None, 0, Gtk.MessageType.INFO,
                        Gtk.ButtonsType.OK, "Linconnect-server")
       dialog.format_secondary_text(_("Mirror Android notifications on Linux Desktop"))
       dialog.run()
       dialog.destroy()

    def quit(self, widget, data=None):
        logger.debug("should exit")
        for thread in threading.enumerate():
            if thread.isAlive():
                try:
                    thread._Thread__stop()
                except:
                    logger.error(str(thread.getName()) + ' could not be terminated')
        cherrypy.engine.exit()
        Gtk.main_quit()

class LinconnectServerThread(threading.Thread):
    def __init__(self):
         threading.Thread.__init__(self)

    def initialize(self):
        # Start Avahi service in a thread if desired
        if parser.getboolean('connection', 'enable_avahi') == 1:
            self.avahi_thr = threading.Thread(target=publish_service)
            self.avahi_thr.start()

        # Start Bluetooth server if desired
        if parser.getboolean('connection', 'enable_bluetooth') == 1:
            self.bluetooth_thr = threading.Thread(target=bluetooth_server)
            self.bluetooth_thr.start()

        config_instructions = "Configuration instructions at http://localhost:" + parser.get('connection', 'port')
        logger.info(config_instructions)
        notif = Notify.Notification.new("Notification server started (version " + version + ")", config_instructions, "info")
        notif.show()
    
    def run(self):
        try:
            cherrypy.server.socket_host = parser.get('connection', 'listen')
        except:
            cherrypy.server.socket_host = '0.0.0.0'
        cherrypy.server.socket_port = int(parser.get('connection', 'port'))
        cherrypy.log.screen = False
        cherrypy.quickstart(Notification())
        logger.info("LinconnectServerThread exited")

def publish_service():
    """
    Registering and publishing a service using Avahi
    """

    service = ZeroconfService(name=_service_name,
                              stype="_linconnect._tcp",
                              port=int(parser.get('connection', 'port')))
    service.publish()


def get_local_ip():
    port = parser.get('connection', 'port')
    if cherrypy.server.socket_host != "0.0.0.0":
        return [cherrypy.server.socket_host + ":" + port]
    iplines = (line.strip() for line in subprocess.check_output("/sbin/ip address", shell=True).split('\n'))
    addresses = reduce(lambda a,v:a+v,(re.findall(r"inet ([\d.]+/\d+)",line) for line in iplines))
    return [(ip + ":" + port) for ip, subnet in (addr.split('/') for addr in addresses if '.' in addr) if not ip.startswith("127.")]

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

	logger.info ("Bluetooth server started, waiting for connections on RFCOMM channel %d" % port)

	try:
		while True:
			client_sock, client_info = server_sock.accept()
			logger.info ("Accepted connection from {0}".format(client_info))
			th = bluetoothClientThread(client_sock,client_info)
			th.start()

	except IOError:
		pass

	logger.info ("Bluetooth server exiting. Closing server socket.")
	server_sock.close()

########
# MAIN #
########
# Initialization
if not Notify.init("com.willhauck.linconnect"):
    raise ImportError("Error initializing libnotify")

indicator = LinconnectIndicator()
server = LinconnectServerThread()
server.initialize()
server.start()
Gdk.threads_init()
Gtk.main()
