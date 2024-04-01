import sys

from lib.state import read_state, save_state
from lib.actions.scan_top_2_ports import scan_top_2_ports
from lib.actions.scan_top_10_ports import scan_top_10_ports
from lib.actions.scan_top_100_ports import scan_top_100_ports
from lib.actions.scan_top_1000_ports import scan_top_1000_ports
from lib.actions.scan_all_ports import scan_all_ports
from lib.actions.service_detection import service_detection


# This script should ultimately perform a few important functions
# 1. Execute a basic host discovery phase # 2. Scan for the top 2 ports on each known host
# 3. Scan for the top 10 ports on each known host
# 4. Scan for the top 100 ports on each known host # 5. Scan for the top 1000 ports on each known host
# 6. Scan for all ports on each known host
# 7. Perform service detection on all known open ports
# 8. Perform service detection with special scripts on all known open ports
#       (i.e. jdwp)
# 9. Execute an advanced host discovery phase
# 10. Execute an advanced port discovery phase
# 11. Perform service detection on newly discovered ports


# From https://stackoverflow.com/q/5067604
def get_function_name(func):
    # Sounds like this could be deprecated at some point
    return func.__name__

def stage_init(current_state, state_name):
    current_state["stage"] = state_name
    current_state["stage_status"] = "in-progress"
    save_state(current_state)

def stage_complete(current_state):
    current_state["stage_status"] = "done"
    save_state(current_state)

action_order = [
        scan_top_2_ports,
        scan_top_10_ports,
        scan_top_100_ports,
        service_detection,
        scan_top_1000_ports,
        service_detection,
        scan_all_ports,
        service_detection,
        ]

def get_stage_name(index, action):
    return str(index) + "-" + get_function_name(action)

def determine_action(current_state):
    stages_complete = {}

    if "stage" in current_state:
        current_stage = current_state["stage"]
        for i, action in enumerate(action_order):
            stage = get_stage_name(i, action)
            if stage == current_stage:
                break
            stages_complete[stage] = True

    for i, action in enumerate(action_order):
        stage = get_stage_name(i, action)
        if (not stage in stages_complete) or (not stages_complete[stage]):
            stage_init(current_state, stage)
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

