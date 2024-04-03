from lib.actions.lib.scan import run_scan
from lib.actions.lib.top_ports import get_top_2_ports


def scan_top_2_ports(current_state):
    output_filename = "top_2_ports.xml"
    run_scan(
            ["-p", get_top_2_ports(), "-oX", output_filename],
            current_state["target"],
            output_filename,
            current_state)


