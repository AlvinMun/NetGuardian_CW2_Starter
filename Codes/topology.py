#!/usr/bin/env python3
"""NetGuardian Task 1: Mininet enterprise topology."""
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

HOSTS = {
    "h1": ("10.0.1.11/16", "00:00:00:00:01:11", "s1"),
    "h2": ("10.0.1.12/16", "00:00:00:00:01:12", "s1"),
    "h3": ("10.0.2.21/16", "00:00:00:00:02:11", "s2"),
    "h4": ("10.0.2.22/16", "00:00:00:00:02:12", "s2"),
    "h5": ("10.0.2.23/16", "00:00:00:00:02:13", "s2"),
    "h6": ("10.0.3.31/16", "00:00:00:00:03:11", "s3"),
    "h7": ("10.0.3.40/16", "00:00:00:00:03:20", "s3"),
    "h8": ("10.0.3.99/16", "00:00:00:00:03:99", "s3"),
}

def build():
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=False,
                  build=False)
    c0 = net.addController("c0", controller=RemoteController,
                           ip="127.0.0.1", port=6633)
    switches = {}
    for name in ("s1", "s2", "s3"):
        switches[name] = net.addSwitch(name, protocols="OpenFlow13",
                                       failMode="secure")
    # Switch chain as shown in Fig. 1.
    net.addLink(switches["s1"], switches["s2"])
    net.addLink(switches["s2"], switches["s3"])
    for name, (ip, mac, sw) in HOSTS.items():
        host = net.addHost(name, ip=ip, mac=mac)
        net.addLink(host, switches[sw])
    net.build()
    c0.start()
    for sw in switches.values():
        sw.start([c0])
    return net

def main():
    net = build()
    try:
        info("*** NetGuardian topology started. Use nodes, net, dump, pingall.\n")
        CLI(net)
    finally:
        net.stop()

if __name__ == "__main__":
    setLogLevel("info")
    main()
