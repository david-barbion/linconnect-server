import dbus
import sys

__all__ = ["ZeroconfService"]
sys.dont_write_bytecode = True


class ZeroconfService:
    """
    A very simple class to publish a network service with Zeroconf using avahi.
    """

    def __init__(self, name, port, stype="_linconnect._tcp", domain="", host="", text=""):
        self.name = name
        self.port = port
        self.stype = stype
        self.domain = domain
        self.host = host
        self.text = text

        # AVAHI Configuration Variables
        self.DBUS_NAME = "org.freedesktop.Avahi"
        self.DBUS_PATH_SERVER = "/"
        self.DBUS_INTERFACE_SERVER = self.DBUS_NAME + ".Server"
        self.DBUS_INTERFACE_ENTRY_GROUP = self.DBUS_NAME + ".EntryGroup"
        self.IF_UNSPEC = -1
        self.PROTO_UNSPEC = -1


    def publish(self):
        bus = dbus.SystemBus()
        server = dbus.Interface(bus.get_object(self.DBUS_NAME,
                                               self.DBUS_PATH_SERVER),
                                               self.DBUS_INTERFACE_SERVER)

        g = dbus.Interface(bus.get_object(self.DBUS_NAME,
                                          server.EntryGroupNew()),
                           self.DBUS_INTERFACE_ENTRY_GROUP)

        g.AddService(self.IF_UNSPEC, self.PROTO_UNSPEC, dbus.UInt32(0),
                     self.name, self.stype, self.domain, self.host,
                     dbus.UInt16(self.port), self.text)

        g.Commit()
        self.group = g

    def unpublish(self):
        self.group.Reset()


def test():
    service = ZeroconfService(name="TestService", port=3000)
    service.publish()
    raw_input("Press anykey to unpublish the service ")
    service.unpublish()
