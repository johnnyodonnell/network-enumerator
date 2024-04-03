from lib.actions.lib.scan import run_scan
from lib.actions.lib.top_ports import get_remaining_ports
from lib.actions.lib.utils import get_remaining_hosts


def scan_all_ports(current_state):
    output_filename = "all_ports.xml"
    run_scan(
            [
                "-Pn", "-p", get_remaining_ports(),
                "-oX", output_filename,
                "--max-hostgroup", "4"
                ],
            get_remaining_hosts(current_state),
            output_filename,
            current_state)

