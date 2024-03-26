import json
import os
import re
import sys
import subprocess
import xml.etree.ElementTree as ET


# This script should ultimately perform a few important functions
# 1. Execute a basic host discovery phase
# 2. Scan for the top 2 ports on each known host
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
state_file_name = "current_state.json"

def format_ports(ports):
    return ",".join([str(port) for port in ports])

def get_remaining_ports():
    ports_remaining = []

    ports_seen = top_2_ports + top_10_ports
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

def run_scan(args, target):
    command = [
            "sudo", "nmap",
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

def should_resume_scan(output_filename):
    return os.path.isfile(output_filename)

def resume_scan(output_filename, target):
    subprocess.run(["sudo", "nmap", "--resume", output_filename])

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
            state = port.find("state").get("state")
            if not portid in host_map[address]["ports"]["tcp"]:
                host_map[address]["ports"]["tcp"][portid] = {}
            if state:
                host_map[address]["ports"]["tcp"][portid]["state"] = state

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

def get_open_ports(host):
    open_ports = []
    if "ports" in host:
        ports = host["ports"]
        if "tcp" in ports:
            tcp_ports = ports["tcp"]
            for portid in tcp_ports:
                port = tcp_ports[portid]
                if ("state" in port) and (port["state"] == "open"):
                    open_ports.append(portid)
    return open_ports

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
    stage_init(current_state, "service_detection")
    output_filename = "service_detection.xml"
    hosts = current_state["hosts"]
    for address in hosts:
        host = hosts[address]
        if not "fingerprinted" in host:
            run_scan(
                    ["-Pn", "-sV", "-p" format_ports(get_open_ports(host)), "-oX", output_filename],
                    address)
            copy_output_to_state(output_filename, current_state)
            host["fingerprinted"] = True
            save_state(current_state)
    stage_complete(current_state)

def scan_all_ports(current_state):
    stage_init(current_state, "all_ports")
    output_filename = "all_ports.xml"
    if should_resume_scan(output_filename):
        resume_scan(output_filename, current_state["target"])
    else:
        run_scan(
                ["-Pn", "-p", get_remaining_ports(), "-oX", output_filename],
                get_active_hosts(current_state))
    copy_output_to_state(output_filename, current_state)
    stage_complete(current_state)

def scan_top_10_ports(current_state):
    stage_init(current_state, "top_10_ports")
    output_filename = "top_10_ports.xml"
    if should_resume_scan(output_filename):
        resume_scan(output_filename, current_state["target"])
    else:
        run_scan(
                ["-Pn", "-p", format_ports(top_10_ports), "-oX", output_filename],
                get_active_hosts(current_state))
    copy_output_to_state(output_filename, current_state)
    stage_complete(current_state)

def scan_top_2_ports(current_state):
    stage_init(current_state, "top_2_ports")
    output_filename = "top_2_ports.xml"
    if should_resume_scan(output_filename):
        resume_scan(output_filename, current_state["target"])
    else:
        run_scan(
                ["-p", format_ports(top_2_ports), "-oX", output_filename],
                current_state["target"])
    copy_output_to_state(output_filename, current_state)
    stage_complete(current_state)

def determine_action(current_state):
    if (not "stage" in current_state) or ((current_state["stage"] == "top_2_ports") and (current_state["stage_status"] == "in-progress")):
        scan_top_2_ports(current_state)
    elif (current_state["stage"] == "top_2_ports") or ((current_state["stage"] == "top_10_ports") and (current_state["stage_status"] == "in-progress")):
        scan_top_10_ports(current_state)
    elif (current_state["stage"] == "top_10_ports") or ((current_state["stage"] == "all_ports") and (current_state["stage_status"] == "in-progress")):
        scan_all_ports(current_state)
    else:
        print("Enumeration complete.")
        return

    determine_action(current_state)

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

