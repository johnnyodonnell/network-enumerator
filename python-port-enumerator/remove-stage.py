import json


state_file_name = "current_state.json"

def main():
    with open(state_file_name) as f:
        current_state = json.load(f)

    stage = current_state["stage"]

    hosts = current_state["hosts"]
    for address in hosts:
        host = hosts[address]
        if ("stages_complete" in host) and (stage in host["stages_complete"]):
            del host["stages_complete"][stage]

    with open (state_file_name, "w") as f:
        json.dump(current_state, f)

main()

