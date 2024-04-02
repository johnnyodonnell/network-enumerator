from lib.actions.lib.scan import run_scan, should_resume_scan, resume_scan
from lib.actions.lib.top_ports import get_top_2_ports


def scan_top_2_ports(current_state):
    output_file_basename = "top_2_ports"
    if should_resume_scan(output_file_basename):
        resume_scan(output_file_basename, current_state["target"], current_state)
    else:
        run_scan(
                [
                    "-p", get_top_2_ports(),
                    ],
                current_state["target"],
                output_file_basename,
                current_state)


