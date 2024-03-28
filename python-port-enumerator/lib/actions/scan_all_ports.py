from lib.actions.lib.scan import run_scan, should_resume_scan, resume_scan
from lib.actions.lib.top_ports import top_2_ports, top_10_ports, top_100_ports
from lib.actions.lib.utils import format_ports, get_active_hosts


def get_remaining_ports():
    ports_remaining = []

    ports_seen = top_2_ports + top_10_ports + top_100_ports
    ports_seen_map = {}
    for port in ports_seen:
        ports_seen_map[port] = True

    final_port = 65535
    left_port = 1
    for port in range(1, final_port + 1):
        if port in ports_seen:
            if port == left_port:
                left_port = port + 1
            elif (port - 1) == left_port:
                ports_remaining.append(str(left_port))
            else:
                ports_remaining.append(str(left_port) + "-" + str(port - 1))
            left_port = port + 1
        elif port == final_port:
            if port == left_port:
                ports_remaining.append(str(left_port))
            else:
                ports_remaining.append(str(left_port) + "-" + str(port))

    return format_ports(ports_remaining)

def scan_all_ports(current_state):
    output_filename = "all_ports.xml"
    if should_resume_scan(output_filename):
        resume_scan(output_filename, current_state["target"], current_state)
    else:
        run_scan(
                [
                    "-Pn", "-p", get_remaining_ports(),
                    "-oX", output_filename,
                    "--max-hostgroup", "4"
                    ],
                get_active_hosts(current_state),
                output_filename,
                current_state)

