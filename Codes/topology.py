"""Create the Fig. 1 Mininet network and connect it to an external controller."""

import argparse
from contextlib import contextmanager

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController

from settings import (
    CONTROLLER_IP, CONTROLLER_PORT, HOST_PORTS, HOSTS, SWITCH_IDS, SWITCH_LINKS,
)


@contextmanager
def enterprise_network(controller_ip=CONTROLLER_IP, controller_port=CONTROLLER_PORT):
    net = Mininet(build=False, controller=None)
    try:
        net.addController("c0", controller=RemoteController,
                          ip=controller_ip, port=controller_port)
        for name, dpid in SWITCH_IDS.items():
            net.addSwitch(name, cls=OVSKernelSwitch, dpid=f"{dpid:016x}",
                          protocols="OpenFlow13", failMode="secure")
        for name, (ip, mac, switch) in HOSTS.items():
            net.addHost(name, ip=ip, mac=mac)
            net.addLink(name, switch, port1=0, port2=HOST_PORTS[name])
        for left, right in SWITCH_LINKS:
            net.addLink(left, right)
        net.start()
        if not net.waitConnected(timeout=12):
            raise RuntimeError("Not all OpenFlow switches connected to Ryu")
        yield net
    finally:
        net.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller-ip", default=CONTROLLER_IP)
    parser.add_argument("--controller-port", type=int, default=CONTROLLER_PORT)
    args = parser.parse_args()
    setLogLevel("info")
    with enterprise_network(args.controller_ip, args.controller_port) as network:
        CLI(network)
