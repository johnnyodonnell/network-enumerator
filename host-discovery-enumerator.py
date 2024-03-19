import subprocess
import sys


commands = [
        {
            "name": "Ping Scans",
            "commands": [
                "-sn -PE -PP -PM",
                ],
            },
        {
            "name": "Web Ports",
            "commands": [
                "-Pn -p 80,443 --open 172.17.64.82/20",
                ],
            },
        {
            "name": "TCP SYN Scan, Top 10 ports",
            "commands": [
                "-Pn --top-ports 10 --open 172.17.64.82/20",
                ],
            },
        {
            "name": "TCP SYN Scan, Top 100 ports",
            "commands": [
                "-Pn --top-ports 100 --open 172.17.64.82/20",
                ],
            },
        {
            "name": "TCP ACK Scan, Top 10 ports",
            "commands": [
                "-sA -Pn --top-ports 10 --open 172.17.64.82/20",
                ],
            },
        {
            "name": "TCP ACK Scan, Top 100 ports",
            "commands": [
                "-sA -Pn --top-ports 100 --open 172.17.64.82/20",
                ],
            },
        {
            "name": "TCP Window Scan, Top 10 ports",
            "commands": [
                "-sW -Pn --top-ports 10 --open 172.17.64.82/20",
                ],
            },
        {
            "name": "Special TCP Scans, Top 10 ports",
            "commands": [
                "-sN -Pn --top-ports 10 --open 172.17.64.82/20",
                "-sF -Pn --top-ports 10 --open 172.17.64.82/20",
                "-sX -Pn --top-ports 10 --open 172.17.64.82/20",
                "-sM -Pn --top-ports 10 --open 172.17.64.82/20",
                ],
            },
        {
            "name": "TCP SYN Scan, All ports",
            "commands": [
                "-Pn -p- --open 172.17.64.82/20",
                ],
            },
        {
            "name": "TCP Ack Scan, All ports",
            "commands": [
                "-sA -Pn -p- --open 172.17.64.82/20",
                ],
            },
        {
            "name": "TCP Window Scan, All ports",
            "commands": [
                "-sW -Pn -p- --open 172.17.64.82/20",
                ],
            },
        {
            "name": "Special Scans, All ports",
            "commands": [
                "-sN -Pn -p- --open 172.17.64.82/20",
                "-sF -Pn -p- --open 172.17.64.82/20",
                "-sX -Pn -p- --open 172.17.64.82/20",
                "-sM -Pn -p- --open 172.17.64.82/20",
                ],
            },
        ]

def get_full_name(index, name):
    return str(index) + ". " + name

def print_commands():
    for i in range (0, len(commands)):
        command_set = commands[i]
        print(get_full_name(i + 1, command_set["name"]))
    print()


def run(target, index = 1):
    for i in range(index - 1, len(commands)):
        command_set = commands[i]
        print("Now running: " + get_full_name(i + 1, command_set["name"]))
        for command in command_set["commands"]:
            subprocess.run(["sudo", "nmap", target])


def main():
    print_commands()
    target = sys.argv[1]
    index = 1 if (len(sys.argv) <= 2) else sys.argv[2]
    run(target, index)

if __name__ == "__main__":
    main()

