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
    s2 = net.addSwitch("s2", protocols="OpenFlow13")
    net.addLink(s1, s2)

    hosts = []
    for idx in range(1, 7):
        host = net.addHost(f"h{idx}", ip=f"10.0.0.{idx}/24")
        hosts.append(host)

    for host in hosts[:3]:
        net.addLink(host, s1)
    for host in hosts[3:]:
        net.addLink(host, s2)

    return net


def start_services(net, assets):
    for asset in assets:
        if asset.get("service") != "http":
            continue
        host_name = asset.get("host")
        if not host_name:
            continue
        host = net.get(host_name)
        port = int(asset.get("port", 80))
        host.cmd(f"python3 -m http.server {port} >/tmp/{host_name}_http.log 2>&1 &")
