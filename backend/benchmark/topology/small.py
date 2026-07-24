from mininet.link import TCLink
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController


def create_network(controller_ip="127.0.0.1", controller_port=6653):
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True)
    net.addController(
        "c0",
        controller=RemoteController,
        ip=controller_ip,
        port=controller_port,
    )

    s1 = net.addSwitch("s1", protocols="OpenFlow13")

    h1 = net.addHost("h1", ip="10.0.0.1/24")
    h2 = net.addHost("h2", ip="10.0.0.2/24")
    h3 = net.addHost("h3", ip="10.0.0.3/24")

    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)

    return net


def start_services(net, assets):
    import time
    for asset in assets:
        if asset.get("service") != "http":
            continue
        host_name = asset.get("host")
        if not host_name:
            continue
        host = net.get(host_name)
        port = int(asset.get("port", 80))
        host.cmd("pkill -9 -f 'http.server'")
        host.cmd(f"nohup python3 -m http.server {port} >/tmp/{host_name}_http.log 2>&1 &")
        time.sleep(0.5)
