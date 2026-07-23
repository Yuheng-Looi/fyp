from __future__ import annotations

from functools import partial
from typing import Dict


WEB_SERVER_IP = "10.0.0.100"
DB_SERVER_IP = "10.0.0.200"
WEB_SERVER_HOST = "h_web"
DB_SERVER_HOST = "h_db"
SERVER_IP = WEB_SERVER_IP
SERVER_HOST = WEB_SERVER_HOST

SMALL_BENIGN_HOSTS = [f"h_user_{idx}" for idx in range(1, 4)]
SMALL_ATTACK_HOSTS = [f"h_key{idx}" for idx in range(1, 3)]
LARGE_BENIGN_HOSTS = [f"h_user_{idx}" for idx in range(1, 11)]
LARGE_ATTACK_HOSTS = [f"h_key{idx}" for idx in range(1, 6)]

# Explicit host role definitions for Distributed Adaptive IDS Cyber-Range
NODE_ROLES = {
    "Normal Users": SMALL_BENIGN_HOSTS + LARGE_BENIGN_HOSTS,
    "Attackers": SMALL_ATTACK_HOSTS + LARGE_ATTACK_HOSTS,
    "Victim Servers": [WEB_SERVER_HOST, DB_SERVER_HOST]
}


def get_benign_hosts(profile: str) -> list[str]:
    return SMALL_BENIGN_HOSTS if profile == "SMALL" else LARGE_BENIGN_HOSTS


def get_attack_hosts(profile: str) -> list[str]:
    return SMALL_ATTACK_HOSTS if profile == "SMALL" else LARGE_ATTACK_HOSTS


def build_topology(profile: str):
    try:
        from mininet.link import TCLink
        from mininet.topo import Topo
        from mininet.node import OVSSwitch
    except Exception as exc:  # pragma: no cover - import-time guard
        raise RuntimeError("Mininet is required to run the benchmark") from exc

    class BenchmarkTopo(Topo):
        def build(self) -> None:
            switch = self.addSwitch("s1")
            self.addHost(WEB_SERVER_HOST, ip=f"{WEB_SERVER_IP}/24")
            self.addHost(DB_SERVER_HOST, ip=f"{DB_SERVER_IP}/24")
            hosts = get_benign_hosts(profile) + get_attack_hosts(profile)
            for idx, host in enumerate(hosts, start=1):
                self.addHost(host, ip=f"10.0.0.{idx}/24")

            self.addLink(WEB_SERVER_HOST, switch, bw=100)
            self.addLink(DB_SERVER_HOST, switch, bw=1000)
            for host in hosts:
                self.addLink(host, switch)

    return BenchmarkTopo(), partial(OVSSwitch, protocols="OpenFlow13"), TCLink


def create_network(profile: str, use_remote_controller: bool, controller_ip: str, controller_port: int):
    try:
        from mininet.net import Mininet
        from mininet.node import RemoteController
    except Exception as exc:  # pragma: no cover - import-time guard
        raise RuntimeError("Mininet is required to run the benchmark") from exc

    topo, switch_cls, link_cls = build_topology(profile)
    if use_remote_controller:
        controller = partial(RemoteController, ip=controller_ip, port=controller_port)
        switch_kwargs = {"failMode": "secure"}
    else:
        controller = None
        switch_kwargs = {"failMode": "standalone"}

    switch_cls = partial(switch_cls, **switch_kwargs)

    net = Mininet(
        topo=topo,
        controller=controller,
        switch=switch_cls,
        link=link_cls,
        autoSetMacs=True,
        autoStaticArp=True,
        waitConnected=use_remote_controller,
    )

    # Wrap net.start to automatically run the Flask app on h_web_server when Mininet starts
    orig_start = net.start
    def custom_start():
        orig_start()
        victim_host = net.get(WEB_SERVER_HOST)
        # Run the lightweight Flask Victim Server in the background on port 80
        victim_host.cmd("PYTHONPATH=/home/fyp2025/.local/lib/python3.11/site-packages /home/fyp2025/fyp/backend/benchmark/benchmarkenv/bin/python /home/fyp2025/fyp/backend/app.py --port 80 > /tmp/flask_victim.log 2>&1 &")
        print(f"[topology] Spin up Flask app on Victim Server {WEB_SERVER_HOST} (IP {victim_host.IP()})")
    net.start = custom_start

    return net


def get_host_map(net) -> Dict[str, object]:
    return {host.name: host for host in net.hosts}


def get_server_interface_name() -> str:
    return f"{WEB_SERVER_HOST}-eth0"


def get_db_interface_name() -> str:
    return f"{DB_SERVER_HOST}-eth0"
