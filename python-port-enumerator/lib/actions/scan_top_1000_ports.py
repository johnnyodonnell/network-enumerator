from lib.actions.lib.scan import run_scan
from lib.actions.lib.top_ports import get_top_1000_ports
from lib.actions.lib.utils import get_remaining_hosts


def scan_top_1000_ports(current_state):
    output_filename = "top_1000_ports.xml"
    run_scan(
            [
                "-Pn", "-p", get_top_1000_ports(),
                "-oX", output_filename,
                ],
            get_remaining_hosts(current_state),
            output_filename,
            current_state)

