from lib.actions.lib.scan import run_scan
from lib.actions.lib.top_ports import format_ports
from lib.state import save_state


def get_number_of_hosts(port_map_entry):
    return len(port_map_entry["hosts"])

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

def mark_hosts_as_fingerprinted(current_state, portid, hosts_set):
    hosts = current_state["hosts"]
    for address in hosts:
        if address in hosts_set:
            host = hosts[address]
            if "ports" in host:
                ports = host["ports"]
                if "tcp" in ports:
                    tcp_ports = ports["tcp"]
                    if portid in tcp_ports:
                        tcp_ports[portid]["fingerprinted"] = True

def get_host_with_most_open_ports(hosts):
    host_with_most_open_ports = None
    for address in hosts:
        host = hosts[address]
        ports = get_open_nonfingerprinted_ports(host)
        num_of_open_ports = len(ports)
        if num_of_open_ports > 0:
            if (host_with_most_open_ports is None) or (num_of_open_ports > len(host_with_most_open_ports["ports"])):
                host_with_most_open_ports = {"address": address, "ports": ports}
    return host_with_most_open_ports

def service_detection(current_state):
    open_ports_map = {}

    hosts = current_state["hosts"]
    for address in hosts:
        host = hosts[address]
        ports = get_open_nonfingerprinted_ports(host)
        num_of_open_ports = len(ports)
        if num_of_open_ports > 0:
            for port in ports:
                if not port in open_ports_map:
                    open_ports_map[port] = {address}
                else:
                    open_ports_map[port].add(address)

    open_ports_list = []
    for portid in open_ports_map:
        open_ports_list.append({"port": portid, "hosts": open_ports_map[portid]})

    open_ports_list = sorted(open_ports_list, key=get_number_of_hosts, reverse=True)
    for port_map_entry in open_ports_list:
        host_with_most_open_ports = get_host_with_most_open_ports(current_state["hosts"])
        portid = port_map_entry["port"]
        hosts = port_map_entry["hosts"]
        if len(hosts) >= len(host_with_most_open_ports["ports"]):
            output_filename = "service_detection_" + portid + ".xml"
            run_scan([
                "-Pn", "-sV", "-p",  portid,
                "-oX", output_filename,
                ],
                     list(hosts), # Convert from set to list
                     output_filename,
                     current_state)
            mark_hosts_as_fingerprinted(current_state, portid, hosts)
            save_state(current_state)
        else:
            address = host_with_most_open_ports["address"]
            ports = host_with_most_open_ports["ports"]
            output_filename = "service_detection_" + address + ".xml"
            run_scan([
                "-Pn", "-sV", "-p",  format_ports(ports),
                "-oX", output_filename,
                ],
                     address,
                     output_filename,
                     current_state)
            mark_ports_as_fingerprinted(current_state["hosts"][address])
            save_state(current_state)
            service_detection(current_state)
            return

