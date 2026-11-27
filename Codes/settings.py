"""Addresses from the coursework and shared OpenFlow settings."""

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
HOST_IP = {name: entry[0].split("/")[0] for name, entry in HOSTS.items()}
HOST_BY_IP = {ip: name for name, ip in HOST_IP.items()}
SWITCH_IDS = {"s1": 1, "s2": 2, "s3": 3}
SWITCH_LINKS = (("s1", "s2"), ("s2", "s3"))
# Keep host-facing ports fixed so flow observations can be attributed at ingress.
HOST_PORTS = {"h1": 1, "h2": 2, "h3": 1, "h4": 2, "h5": 3,
              "h6": 1, "h7": 2, "h8": 3}
INGRESS = {
    HOST_IP[name]: (SWITCH_IDS[entry[2]], HOST_PORTS[name])
    for name, entry in HOSTS.items()
}

CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6633
SERVICE_PORT = 8080
FLOW_IDLE = 5
FORWARD_PRIORITY = 10
POLICY_PRIORITY = 100
MITIGATION_PRIORITY = 200
SYN_FLOW_COOKIE = 0x17
MITIGATION_COOKIE = 0x18
