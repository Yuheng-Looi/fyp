from mininet.link import TCLink
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController


def create_network(controller_ip="127.0.0.1", controller_port=6653):
    """
    Large Topology Host Role Mapping (14 Web/DB Servers, 14 Benign Users, 14 Attackers):
      - Attackers (14):    att1 (h1: 10.0.0.1) .. att14 (10.0.0.14)
      - Benign Users (14): usr1 (h3: 10.0.0.15) .. usr14 (10.0.0.28)
      - Web Servers (7):   ws1  (h5: 10.0.0.29) .. ws7 (10.0.0.35)
      - DB Servers (7):    db1  (h6: 10.0.0.36) .. db7 (10.0.0.42)
    Total = 42 hosts across 4 switches
    """
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True)
    net.addController(
        "c0",
        controller=RemoteController,
        ip=controller_ip,
        port=controller_port,
    )

    s1 = net.addSwitch("s1", protocols="OpenFlow13")
    s2 = net.addSwitch("s2", protocols="OpenFlow13")
    s3 = net.addSwitch("s3", protocols="OpenFlow13")
    s4 = net.addSwitch("s4", protocols="OpenFlow13")

    net.addLink(s1, s2, bw=10)
    net.addLink(s2, s3, bw=10)
    net.addLink(s3, s4, bw=10)

    # 14 Attackers (10.0.0.1 .. 10.0.0.14)
    h1 = net.addHost("h1", ip="10.0.0.1/24")  # att1
    h2 = net.addHost("h2", ip="10.0.0.2/24")  # att2
    attackers = [h1, h2] + [net.addHost(f"att{i}", ip=f"10.0.0.{i}/24") for i in range(3, 15)]

    # 14 Benign Users (10.0.0.15 .. 10.0.0.28)
    h3 = net.addHost("h3", ip="10.0.0.15/24")  # usr1
    h4 = net.addHost("h4", ip="10.0.0.16/24")  # usr2
    users = [h3, h4] + [net.addHost(f"usr{i}", ip=f"10.0.0.{i+14}/24") for i in range(3, 15)]

    # 7 Web Servers (10.0.0.29 .. 10.0.0.35)
    h5 = net.addHost("h5", ip="10.0.0.29/24")  # ws1
    web_servers = [h5] + [net.addHost(f"ws{i}", ip=f"10.0.0.{28+i}/24") for i in range(2, 8)]

    # 7 DB Servers (10.0.0.36 .. 10.0.0.42)
    h6 = net.addHost("h6", ip="10.0.0.36/24")  # db1
    db_servers = [h6] + [net.addHost(f"db{i}", ip=f"10.0.0.{35+i}/24") for i in range(2, 8)]

    # Attach hosts across s1, s2, s3, s4
    for host in attackers[:7] + users[:7]:
        net.addLink(host, s1, bw=10)
    for host in attackers[7:] + users[7:]:
        net.addLink(host, s2, bw=10)

    for host in web_servers[:4] + db_servers[:4]:
        net.addLink(host, s3, bw=10)
    for host in web_servers[4:] + db_servers[4:]:
        net.addLink(host, s4, bw=10)

    return net


def start_services(net, assets):
    import time
    web_names = ["h5"] + [f"ws{i}" for i in range(2, 8)]
    db_names = ["h6"] + [f"db{i}" for i in range(2, 8)]
    for host_name in web_names + db_names:
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
            time.sleep(0.15)
