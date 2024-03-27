import json


def num_of_ports(host):
    return len(host["ports"])

def get_port_id(port):
    return int(port["id"])

def get_num_of_hosts_not_fingerprinted(hosts):
    num_of_hosts = 0

    for address in hosts:
        host = hosts[address]
        if ("status" in host) and (host["status"] == "up") and ("ports" in host):
            ports = host["ports"]
            if "tcp" in ports:
                tcp_ports = ports["tcp"]
                for portid in tcp_ports:
                    port = tcp_ports[portid]
                    if ("state" in port) and (port["state"] == "open") and (not "fingerprinted" in port):
                        num_of_hosts += 1
                        break

    return num_of_hosts


def main():
    current_state = {}
    with open("current_state.json") as f:
        current_state = json.load(f)

    host_list = []

    hosts = current_state["hosts"]
    for address in hosts:
        host = hosts[address]
        if ("status" in host) and (host["status"] == "up") and ("ports" in host):
            host_map = {}
            host_list.append(host_map)
            host_map["address"] = address
            port_list = []
            host_map["ports"] = port_list
            ports = host["ports"]
            if "tcp" in ports:
                tcp_ports = ports["tcp"]
                for portid in tcp_ports:
                    port = tcp_ports[portid]
                    if ("state" in port) and (port["state"] == "open"):
                        port_map = {}
                        port_list.append(port_map)
                        port_map["id"] = portid
                        if ("service" in port):
                            service = port["service"]
                            port_map["name"] = service["name"]
                            port_map["product"] = service["product"]
                            port_map["version"] = service["version"]

    host_list = sorted(host_list, key=num_of_ports)

    for host in host_list:
        print("Host: " + host["address"])
        ports = sorted(host["ports"], key=get_port_id)
        for port in ports:
            portid = port["id"]
            name = str(port["name"] if ("name" in port) else None)
            product = str(port["product"] if ("product" in port) else None)
            version = str(port["version"] if ("version" in port) else None)
            print(f'{portid:<7}{name:<15}{product:<10}{version:<10}')
        print("")

    print("Total hosts: " + str(len(host_list)))
    print("Hosts not fingerprinted: " + str(get_num_of_hosts_not_fingerprinted(hosts)))

main()

