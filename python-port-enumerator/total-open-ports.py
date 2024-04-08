import json


def main():
    current_state = {}
    with open("current_state.json") as f:
        current_state = json.load(f)

    stage = current_state["stage"]
    total_open_ports = 0

    hosts = current_state["hosts"]
    for address in hosts:
        host = hosts[address]
        if ("status" in host) and (host["status"] == "up") and ("ports" in host):
            ports = host["ports"]
            if "tcp" in ports:
                tcp_ports = ports["tcp"]
                for portid in tcp_ports:
                    port = tcp_ports[portid]
                    if ("state" in port) and (port["state"] == "open"):
                        total_open_ports += 1

    print("Total open ports: " + str(total_open_ports))

main()

