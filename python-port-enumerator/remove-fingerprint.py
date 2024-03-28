import json


state_file_name = "current_state.json"

def main():
    with open(state_file_name) as f:
        current_state = json.load(f)

    hosts = current_state["hosts"]
    for address in hosts:
        host = hosts[address]
        ports = host["ports"]
        tcp_ports = ports["tcp"]
        for portid in tcp_ports:
            port = tcp_ports[portid]
            if "fingerprinted" in port:
                port["fingerprinted"] = False
                port.pop("fingerprinted", None)

    with open (state_file_name, "w") as f:
        json.dump(current_state, f)

main()

