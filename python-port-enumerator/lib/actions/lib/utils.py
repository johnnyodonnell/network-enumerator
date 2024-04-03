
def always_true(host):
    return True

def get_remaining_hosts(current_state):
    stage = current_state["stage"]
    return get_active_hosts(
            current_state,
            lambda host: ((not "stages_complete" in host) or (not stage in host["stages_complete"]) or (not host["stages_complete"][stage])))

def get_active_hosts(current_state, additional_constraint = always_true):
    active_hosts = []
    if "hosts" in current_state:
        hosts = current_state["hosts"]
        for address in hosts:
            host = hosts[address]
            if (host["status"] == "up") and additional_constraint(host):
                active_hosts.append(address)
    return active_hosts

