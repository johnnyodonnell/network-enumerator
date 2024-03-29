
def get_active_hosts(current_state):
    active_hosts = []
    if "hosts" in current_state:
        hosts = current_state["hosts"]
        for address in hosts:
            host = hosts[address]
            if host["status"] == "up":
                active_hosts.append(address)
    return active_hosts

