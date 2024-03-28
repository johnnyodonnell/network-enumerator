from lib.actions.lib.scan import run_scan, should_resume_scan, resume_scan
from lib.actions.lib.top_ports import top_100_ports
from lib.actions.lib.utils import format_ports, get_active_hosts


def scan_top_100_ports(current_state):
    output_filename = "top_100_ports.xml"
    if should_resume_scan(output_filename):
        resume_scan(output_filename, current_state["target"], current_state)
    else:
        run_scan(
                [
                    "-Pn", "-p", format_ports(top_100_ports),
                    "-oX", output_filename,
                    "--max-hostgroup", "32"
                    ],
                get_active_hosts(current_state),
                output_filename,
                current_state)

