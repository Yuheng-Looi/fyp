#!/usr/bin/env python3
"""
Bring up a small Mininet topology, mirror interesting ports on s1 to a
host-facing monitor interface (default: s1-snoop), and generate sample
traffic so the live Flask server can classify flows in real time.

Run with sudo:
  sudo python3 live.py
"""

import argparse
import os
import subprocess
import sys
import time

MININET_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'mininet'))
DEFAULT_MONITOR_IFACE = 's1-snoop'
SWITCH_NAME = 's1'


def check_cmd(cmd: str) -> bool:
    from shutil import which
    return which(cmd) is not None


def ensure_environment():
    if os.geteuid() != 0:
        print('This script must be run with sudo/root', file=sys.stderr)
        sys.exit(1)
    if not check_cmd('ovs-vsctl'):
        print('ovs-vsctl not found. Install Open vSwitch before running.', file=sys.stderr)
        sys.exit(1)
    if not check_cmd('ip'):
        print('ip command not found. Install iproute2 before running.', file=sys.stderr)
        sys.exit(1)
    sys.path.insert(0, MININET_PATH)


def cleanup_stale_mininet():
    if not check_cmd('mn'):
        return
    print('Clearing any stale Mininet state (mn -c)...')
    subprocess.run(['mn', '-c'], check=False)


def parse_args():
    parser = argparse.ArgumentParser(description='Start Mininet topology and mirror traffic to a host monitor interface')
    parser.add_argument('--monitor-iface', default=DEFAULT_MONITOR_IFACE,
                        help='Name of the internal OVS port to mirror (default: s1-snoop)')
    parser.add_argument('--mirror-ports', nargs='+',
                        help='Explicit s1 port names to mirror (defaults to s1-eth1 and s1-eth2)')
    parser.add_argument('--ping-count', type=int, default=5,
                        help='Number of ICMP packets to send from h1 to h2')
    parser.add_argument('--iperf-duration', type=int, default=10,
                        help='iperf3 duration in seconds (set to 0 to skip)')
    parser.add_argument('--skip-ping', action='store_true', help='Skip the ping traffic generator')
    parser.add_argument('--skip-iperf', action='store_true', help='Skip the iperf3 traffic generator')
    parser.add_argument('--iperf-bin', default='iperf3', help='iperf binary to use (default: iperf3)')
    parser.add_argument('--no-cli', action='store_true',
                        help='Keep topology running without dropping into the Mininet CLI')
    return parser.parse_args()


def add_monitor_interface(switch: str, monitor_iface: str):
    print(f'Creating internal monitor port {monitor_iface} on {switch}...')
    cmd = [
        'ovs-vsctl', '--may-exist', 'add-port', switch, monitor_iface,
        '--', 'set', 'Interface', monitor_iface, 'type=internal'
    ]
    subprocess.run(cmd, check=True)
    subprocess.run(['ip', 'link', 'set', monitor_iface, 'up'], check=True)


def configure_mirror(switch: str, monitor_iface: str, source_ports):
    if not source_ports:
        raise RuntimeError('No source ports specified for mirroring')
    subprocess.run(['ovs-vsctl', 'clear', 'Bridge', switch, 'mirrors'], check=False)
    print(f'Mirroring {", ".join(source_ports)} to {monitor_iface}...')
    cmd = ['ovs-vsctl']
    aliases = []
    for idx, port in enumerate(source_ports):
        alias = f'@p{idx}'
        aliases.append(alias)
        cmd += ['--', f'--id={alias}', 'get', 'Port', port]
    cmd += [
        '--', '--id=@monitor', 'get', 'Port', monitor_iface,
        '--', 'set', 'Bridge', switch, 'mirrors=@m',
        '--', '--id=@m', 'create', 'Mirror', 'name=snoop0',
        f"select-src-port={','.join(aliases)}",
        f"select-dst-port={','.join(aliases)}",
        'output-port=@monitor'
    ]
    subprocess.run(cmd, check=True)


def cleanup_monitor(switch: str, monitor_iface: str):
    subprocess.run(['ovs-vsctl', 'clear', 'Bridge', switch, 'mirrors'], check=False)
    subprocess.run(['ip', 'link', 'set', monitor_iface, 'down'], check=False)
    subprocess.run(['ovs-vsctl', '--if-exists', 'del-port', switch, monitor_iface], check=False)


def generate_ping(h1, h2, count: int):
    if count <= 0:
        return
    print(f'Pinging {h2.IP()} from {h1.name} ({count} packets)')
    print(h1.cmd(f'ping -c {count} {h2.IP()}'))


def generate_iperf(h1, h2, duration: int, binary: str):
    if duration <= 0:
        return
    if not check_cmd(binary):
        print(f'{binary} not found on host; skipping iperf test')
        return
    print(f'Starting {binary} server on {h2.name} for {duration}s test')
    h2.cmd(f'{binary} -s &')
    time.sleep(1)
    print(h1.cmd(f'{binary} -c {h2.IP()} -t {duration}'))
    h2.cmd(f'pkill -f {binary}')


def main():
    ensure_environment()
    cleanup_stale_mininet()
    args = parse_args()

    try:
        from mininet.net import Mininet
        from mininet.node import OVSSwitch
        from mininet.link import TCLink
        from mininet.cli import CLI
    except Exception as exc:
        print('Failed to import Mininet from local repo:', MININET_PATH, file=sys.stderr)
        print(exc, file=sys.stderr)
        sys.exit(1)

    net = Mininet(link=TCLink, switch=OVSSwitch, controller=None)
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    h1 = net.addHost('h1')
    h2 = net.addHost('h2')

    net.addLink(h1, s1)
    net.addLink(s1, s2)
    net.addLink(s2, h2)

    net.start()
    time.sleep(1)

    monitor_iface = args.monitor_iface
    mirror_ports = args.mirror_ports or [f'{SWITCH_NAME}-eth1', f'{SWITCH_NAME}-eth2']

    try:
        add_monitor_interface(SWITCH_NAME, monitor_iface)
        configure_mirror(SWITCH_NAME, monitor_iface, mirror_ports)
    except subprocess.CalledProcessError as exc:
        print(f'Failed to configure monitor interface: {exc}', file=sys.stderr)
        net.stop()
        sys.exit(1)

    print(f"Monitor interface '{monitor_iface}' is ready. Start live capture in the dashboard using this name.")

    if not args.skip_ping:
        generate_ping(h1, h2, args.ping_count)
    else:
        print('Skipping ping generation (per flag)')

    if not args.skip_iperf:
        generate_iperf(h1, h2, args.iperf_duration, args.iperf_bin)
    else:
        print('Skipping iperf generation (per flag)')

    print('Live traffic is flowing. You can keep generating additional traffic from the CLI or hosts.')

    try:
        if args.no_cli:
            print('Topology is running. Press Ctrl+C to stop.')
            while True:
                time.sleep(1)
        else:
            print("Dropping into Mininet CLI. Type 'exit' when finished.")
            CLI(net)
    except KeyboardInterrupt:
        print('\nKeyboard interrupt received, stopping...')
    finally:
        print('Cleaning up monitor interface and Mininet topology...')
        cleanup_monitor(SWITCH_NAME, monitor_iface)
        net.stop()
        print('Done.')


if __name__ == '__main__':
    main()
