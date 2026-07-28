from mininet.link import TCLink
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController


def create_network(controller_ip="127.0.0.1", controller_port=6653):
    """
    Small Topology Host Role Mapping (6 Web/DB Servers, 6 Benign Users, 6 Attackers):
      - Attackers (6):     att1 (h1: 10.0.0.1) .. att6 (10.0.0.6)
      - Benign Users (6):  usr1 (h2: 10.0.0.7) .. usr6 (10.0.0.12)
      - Web Servers (3):   ws1  (h3: 10.0.0.13), ws2 (10.0.0.14), ws3 (10.0.0.15)
      - DB Servers (3):    db1  (10.0.0.16), db2 (10.0.0.17), db3 (10.0.0.18)
    Total = 18 hosts
    """
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True)
    net.addController(
        "c0",
        controller=RemoteController,
        ip=controller_ip,
        port=controller_port,
    )

    s1 = net.addSwitch("s1", protocols="OpenFlow13")

    # 6 Attackers (10.0.0.1 .. 10.0.0.6)
    h1 = net.addHost("h1", ip="10.0.0.1/24")  # att1
    attackers = [h1] + [net.addHost(f"att{i}", ip=f"10.0.0.{i}/24") for i in range(2, 7)]

    # 6 Benign Users (10.0.0.7 .. 10.0.0.12)
    h2 = net.addHost("h2", ip="10.0.0.7/24")  # usr1
    users = [h2] + [net.addHost(f"usr{i}", ip=f"10.0.0.{i+6}/24") for i in range(2, 7)]

    # 3 Web Servers (10.0.0.13 .. 10.0.0.15)
    h3 = net.addHost("h3", ip="10.0.0.13/24")  # ws1
    web_servers = [h3] + [net.addHost(f"ws{i}", ip=f"10.0.0.{12+i}/24") for i in range(2, 4)]

    # 3 DB Servers (10.0.0.16 .. 10.0.0.18)
    db_servers = [net.addHost(f"db{i}", ip=f"10.0.0.{15+i}/24") for i in range(1, 4)]

    # Add 1 Mbps link capacity shaping on all links
    all_hosts = attackers + users + web_servers + db_servers
    for host in all_hosts:
        net.addLink(host, s1, bw=1)

    return net


def start_services(net, assets):
    import time
    server_names = ["h3", "ws2", "ws3", "db1", "db2", "db3"]
    for host_name in server_names:
        if host_name in net:
            host = net.get(host_name)
            port = 8080
            host.cmd(f"fuser -k -9 {port}/tcp 2>/dev/null || true")
            cmd = (
                f"nohup python3 -c \"from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler; "
                f"ThreadingHTTPServer(('0.0.0.0', {port}), SimpleHTTPRequestHandler).serve_forever()\" "
                f">/tmp/{host_name}_http.log 2>&1 &"
            )
            host.cmd(cmd)
            time.sleep(0.2)
