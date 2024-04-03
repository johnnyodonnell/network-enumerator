import os
import re
import subprocess
import xml.etree.ElementTree as ET

from lib.state import save_state


def run_scan(args, target, output_filename, current_state):
    command = [
            "sudo", "nmap", "-v",
            "--max-scan-delay", "5ms", "--max-retries", "1",
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

def process_host(current_stage, host_map, host):
    address = host.find("address").get("addr")

    state = host.find("status").get("state")
    if state == "up":
        if not address in host_map:
            host_map[address] = {}
        host_map[address]["status"] = "up"

        if not "stages_complete" in host_map[address]:
            host_map[address]["stages_complete"] = {}
        host_map[address]["stages_complete"][current_stage] = True

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
            process_host("hosthint", host_map, hosthint)
        hosts = tree.findall("host")
        for host in hosts:
            process_host(current_state["stage"], host_map, host)
    save_state(current_state)

