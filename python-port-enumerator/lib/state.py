import json
import os


state_file_name = "current_state.json"

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

