from lib.actions.lib.scan import run_scan, should_resume_scan, resume_scan
from lib.actions.lib.top_ports import get_remaining_ports
from lib.actions.lib.utils import get_active_hosts


def scan_all_ports(current_state):
    output_file_basename = "all_ports"
    if should_resume_scan(output_file_basename):
        resume_scan(output_file_basename, current_state["target"], current_state)
    else:
        run_scan(
                [
                    "-Pn", "-p", get_remaining_ports(),
                    "--max-hostgroup", "4"
                    ],
                get_active_hosts(current_state),
                output_file_basename,
                current_state)

