from lib.actions.lib.scan import run_scan, should_resume_scan, resume_scan
from lib.actions.lib.utils import format_ports
from lib.state import save_state


def service_detection(current_state):
    output_filename = "service_detection.xml"
    hosts = current_state["hosts"]
    for address in hosts:
        host = hosts[address]
        ports = get_open_nonfingerprinted_ports(host)
        if len(ports) > 0:
            run_scan(
                    ["-Pn", "-sV", "-p", format_ports(ports), "-oX", output_filename],
                    address,
                    output_filename,
                    current_state)
            mark_ports_as_fingerprinted(host)
            save_state(current_state)

def get_open_nonfingerprinted_ports(host):
    open_ports = []
    if "ports" in host:
        ports = host["ports"]
        if "tcp" in ports:
            tcp_ports = ports["tcp"]
            for portid in tcp_ports:
                port = tcp_ports[portid]
                if ("state" in port) and (port["state"] == "open") and (not "fingerprinted" in port):
                    open_ports.append(portid)
    return open_ports

def mark_ports_as_fingerprinted(host):
    if "ports" in host:
        ports = host["ports"]
        if "tcp" in ports:
            tcp_ports = ports["tcp"]
            for portid in tcp_ports:
                port = tcp_ports[portid]
                if ("state" in port) and (port["state"] == "open"):
                    port["fingerprinted"] = True

