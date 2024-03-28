from lib.actions.lib.scan import run_scan, should_resume_scan, resume_scan
from lib.actions.lib.top_ports import top_2_ports
from lib.actions.lib.utils import format_ports


def scan_top_2_ports(current_state):
    output_filename = "top_2_ports.xml"
    if should_resume_scan(output_filename):
        resume_scan(output_filename, current_state["target"], current_state)
    else:
        run_scan(
                ["-p", format_ports(top_2_ports), "-oX", output_filename],
                current_state["target"],
                output_filename,
                current_state)


