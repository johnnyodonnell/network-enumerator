import json
import os
import re
import sys
import subprocess
import xml.etree.ElementTree as ET


# This script should ultimately perform a few important functions
# 1. Execute a basic host discovery phase # 2. Scan for the top 2 ports on each known host
# 3. Scan for the top 10 ports on each known host
# 4. Scan for the top 100 ports on each known host
# 5. Scan for the top 1000 ports on each known host
# 6. Scan for all ports on each known host
# 7. Perform service detection on all known open ports
# 8. Perform service detection with special scripts on all known open ports
#       (i.e. jdwp)
# 9. Execute an advanced host discovery phase
# 10. Execute an advanced port discovery phase
# 11. Perform service detection on newly discovered ports

# Top ports are based on my own experience
top_2_ports = [80, 443]
top_10_ports = [21, 22, 445, 3306, 5432, 6379, 8080, 8443]
# Top ports based on nmap's recommendation
top_100_ports = [7, 9, 13, 23, 25, 26, 37, 53, 79, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 444, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8081, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156]

state_file_name = "current_state.json"

# From https://stackoverflow.com/q/5067604
def get_function_name(func):
    # Sounds like this could be deprecated at some point
    return func.__name__

def format_ports(ports):
    return ",".join([str(port) for port in ports])

def get_remaining_ports():
    ports_remaining = []

    ports_seen = top_2_ports + top_10_ports + top_100_ports
    ports_seen_map = {}
    for port in ports_seen:
        ports_seen_map[port] = True

    final_port = 65535
    left_port = 1
    for port in range(1, final_port + 1):
        if port in ports_seen:
            if port == left_port:
                left_port = port + 1
            elif (port - 1) == left_port:
                ports_remaining.append(str(left_port))
            else:
                ports_remaining.append(str(left_port) + "-" + str(port - 1))
            left_port = port + 1
        elif port == final_port:
            if port == left_port:
                ports_remaining.append(str(left_port))
            else:
                ports_remaining.append(str(left_port) + "-" + str(port))

    return format_ports(ports_remaining)

def read_state():
    current_state = {}
    if os.path.isfile(state_file_name):
        with open(state_file_name) as f:
            current_state = json.load(f)
    else:
        save_state(current_state)
    return current_state

def save_state(current_state):
    with open (state_file_name, "w") as f:
        json.dump(current_state, f)

def stage_init(current_state, state_name):
    current_state["stage"] = state_name
    current_state["stage_status"] = "in-progress"
    save_state(current_state)

def stage_complete(current_state):
    current_state["stage_status"] = "done"
    save_state(current_state)

def run_scan(args, target, output_filename, current_state):
    command = [
            "sudo", "nmap", "-v",
            # This is to ensure that groups can be completed quickly,
            # but this should ultimately be configurable.
            # See more: https://nmap.org/book/man-performance.html
            "--max-hostgroup", "4"
            ]
    command += args
    if type(target) is list:
        command += target
    elif os.path.isfile(target):
        command += ["-iL", target]
    else:
        command.append(target)
    subprocess.run(command)
    copy_output_to_state(output_filename, current_state)

def should_resume_scan(output_filename):
    return os.path.isfile(output_filename)

def resume_scan(output_filename, target, current_state):
    subprocess.run(["sudo", "nmap", "--resume", output_filename])
    copy_output_to_state(output_filename, current_state)

def process_host(host_map, host):
    address = host.find("address").get("addr")

    state = host.find("status").get("state")
    if state == "up":
        if not address in host_map:
            host_map[address] = {}
        host_map[address]["status"] = "up"

    ports = host.find("ports")
    if ports is not None:
        ports = ports.findall("port")
        if not "ports" in host_map[address]:
            host_map[address]["ports"] = {}
        if not "tcp" in host_map[address]["ports"]:
            host_map[address]["ports"]["tcp"] = {}
        for port in ports:
            portid = port.get("portid")
            if not portid in host_map[address]["ports"]["tcp"]:
                host_map[address]["ports"]["tcp"][portid] = {}
            state = port.find("state")
            if state is not None:
                state = state.get("state")
                if state:
                    host_map[address]["ports"]["tcp"][portid]["state"] = state
            service = port.find("service")
            if service is not None:
                service_info = {
                        "name": service.get("name"),
                        "product": service.get("product"),
                        "version": service.get("version"),
                        }
                host_map[address]["ports"]["tcp"][portid]["service"] = service_info

def copy_output_to_state(output_filename, current_state):
    if not "hosts" in current_state:
        current_state["hosts"] = {}

    host_map = current_state["hosts"]
    with open(output_filename) as f:
        raw = f.read()
        # Handle bug with how nmap adds `</nmaprun>` tags
        xml = re.sub(r"</nmaprun>", "", raw)
        xml += "</nmaprun>"
        tree = ET.fromstring(xml)
        hosthints = tree.findall("hosthint")
        for hosthint in hosthints:
            process_host(host_map, hosthint)
        hosts = tree.findall("host")
        for host in hosts:
            process_host(host_map, host)
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
                port["fingerprinted"] = True

def get_active_hosts(current_state):
    active_hosts = []
    if "hosts" in current_state:
        hosts = current_state["hosts"]
        for address in hosts:
            host = hosts[address]
            if host["status"] == "up":
                active_hosts.append(address)
    return active_hosts

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

def scan_all_ports(current_state):
    output_filename = "all_ports.xml"
    if should_resume_scan(output_filename):
        resume_scan(output_filename, current_state["target"], current_state)
    else:
        run_scan(
                ["-Pn", "-p", get_remaining_ports(), "-oX", output_filename],
                get_active_hosts(current_state),
                output_filename,
                current_state)

def scan_top_100_ports(current_state):
    output_filename = "top_100_ports.xml"
    if should_resume_scan(output_filename):
        resume_scan(output_filename, current_state["target"], current_state)
    else:
        run_scan(
                ["-Pn", "-p", format_ports(top_100_ports), "-oX", output_filename],
                get_active_hosts(current_state),
                output_filename,
                current_state)

def scan_top_10_ports(current_state):
    output_filename = "top_10_ports.xml"
    if should_resume_scan(output_filename):
        resume_scan(output_filename, current_state["target"], current_state)
    else:
        run_scan(
                ["-Pn", "-p", format_ports(top_10_ports), "-oX", output_filename],
                get_active_hosts(current_state),
                output_filename,
                current_state)

def scan_top_2_ports(current_state):
    output_filename = "top_2_ports.xml"
    if should_resume_scan(output_filename):
        resume_scan(output_filename, current_state["target"], current_state)
    else:
        run_scan(
                ["-p", format_ports(top_2_ports), "-oX", output_filename],
                current_state["target"],
                output_filename,
                current_state)


action_order = [
        scan_top_2_ports,
        scan_top_10_ports,
        scan_top_100_ports,
        service_detection,
        scan_all_ports,
        service_detection,
        ]

def get_stage_name(index, action):
    return str(index) + "-" + get_function_name(action)

def determine_action(current_state):
    actions_complete = {}

    if "stage" in current_state:
        stage = current_state["stage"]
        for i, action in enumerate(action_order):
            if get_stage_name(i, action) == stage:
                break
            actions_complete[action] = True

    for i, action in enumerate(action_order):
        if (not action in actions_complete) or (not actions_complete[action]):
            stage_init(current_state, get_stage_name(i, action))
            action(current_state)
            stage_complete(current_state)

    print("Enumeration complete.")


def main():
    current_state = read_state()
    if not "target" in current_state:
        if len(sys.argv) < 2:
            print("A target must be specified")
            exit()
        current_state["target"] = sys.argv[1]
        save_state(current_state)

    determine_action(current_state)
    save_state(current_state)

main()

