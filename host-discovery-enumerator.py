import subprocess
import sys


commands = [
        {
            "name": "Basic Ping Scans",
            "commands": [
                "-sn -PE -PP", # Including timestamp '-PP' because it is included in the default nmap host discovery phase
                ],
            },
        {
            "name": "Special Ping Scans",
            "commands": [
                "-sn -PM",
                ],
            },
        {
            "name": "Web Ports",
            "commands": [
                "-Pn -p 80,443 --open",
                ],
            },
        {
            "name": "TCP SYN Scan, Top 10 ports",
            "commands": [
                "-Pn --top-ports 10 --open",
                ],
            },
        {
            "name": "TCP SYN Scan, Top 100 ports",
            "commands": [
                "-Pn --top-ports 100 --open",
                ],
            },
        {
            "name": "TCP ACK Scan, Top 10 ports",
            "commands": [
                "-sA -Pn --top-ports 10 --open",
                ],
            },
        {
            "name": "TCP ACK Scan, Top 100 ports",
            "commands": [
                "-sA -Pn --top-ports 100 --open",
                ],
            },
        {
            "name": "TCP Window Scan, Top 10 ports",
            "commands": [
                "-sW -Pn --top-ports 10 --open",
                ],
            },
        {
            "name": "Special TCP Scans, Top 10 ports",
            "commands": [
                "-sN -Pn --top-ports 10 --open",
                "-sF -Pn --top-ports 10 --open",
                "-sX -Pn --top-ports 10 --open",
                "-sM -Pn --top-ports 10 --open",
                ],
            },
        {
            "name": "TCP SYN Scan, All ports",
            "commands": [
                "-Pn -p- --open",
                ],
            },
        {
            "name": "TCP Ack Scan, All ports",
            "commands": [
                "-sA -Pn -p- --open",
                ],
            },
        {
            "name": "TCP Window Scan, All ports",
            "commands": [
                "-sW -Pn -p- --open",
                ],
            },
        {
            "name": "Special Scans, All ports",
            "commands": [
                "-sN -Pn -p- --open",
                "-sF -Pn -p- --open",
                "-sX -Pn -p- --open",
                "-sM -Pn -p- --open",
                ],
            },
        ]

def get_full_name(index, name):
    return str(index) + ". " + name

def print_commands():
    print("Scan Types")
    for i in range (0, len(commands)):
        command_set = commands[i]
        print(get_full_name(i + 1, command_set["name"]))
    print()


def run(target, index = 1):
    for i in range(index - 1, len(commands)):
        command_set = commands[i]
        print("-- Now running: " + get_full_name(i + 1, command_set["name"]) + "---")
        for command in command_set["commands"]:
            subprocess_args = ["sudo", "nmap"]
            subprocess_args.extend(command.split(" "))
            subprocess_args.append(target)
            print(" ".join(subprocess_args))
            subprocess.run(subprocess_args)

def main():
    print_commands()
    target = sys.argv[1]
    index = 1 if (len(sys.argv) <= 2) else int(sys.argv[2])
    run(target, index)

if __name__ == "__main__":
    main()

