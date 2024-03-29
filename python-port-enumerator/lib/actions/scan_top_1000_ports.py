from lib.actions.lib.scan import run_scan, should_resume_scan, resume_scan
from lib.actions.lib.top_ports import get_top_1000_ports
from lib.actions.lib.utils import get_active_hosts


def scan_top_100_ports(current_state):
    output_filename = "top_1000_ports.xml"
    if should_resume_scan(output_filename):
        resume_scan(output_filename, current_state["target"], current_state)
    else:
        run_scan(
                [
                    "-Pn", "-p", get_top_1000_ports(),
                    "-oX", output_filename,
                    ],
                get_active_hosts(current_state),
                output_filename,
                current_state)

