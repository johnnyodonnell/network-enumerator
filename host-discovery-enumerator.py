import subprocess
import sys


commands = [
        # 1. Ping scans
        [
            "-sn -PE -PP -PM",
            ],
        # 2. Web ports
        [
            "-Pn -p 80,443 --open 172.17.64.82/20",
            ],
        # 3. TCP SYN Scan, Top 10 ports
        [
            "-Pn --top-ports 10 --open 172.17.64.82/20",
            ],
        # 4. TCP SYN Scan, Top 100 ports
        [
            "-Pn --top-ports 100 --open 172.17.64.82/20",
            ],
        # 5. TCP ACK Scan, Top 10 ports
        [
            "-sA -Pn --top-ports 10 --open 172.17.64.82/20",
            ],
        # 6. TCP ACK Scan, Top 100 ports
        [
            "-sA -Pn --top-ports 100 --open 172.17.64.82/20",
            ],
        # 7. TCP Window Scan, Top 10 ports
        [
            "-sW -Pn --top-ports 10 --open 172.17.64.82/20",
            ],
        # 8. Special TCP Scans, Top 10 ports
        [
            "-sN -Pn --top-ports 10 --open 172.17.64.82/20",
            "-sF -Pn --top-ports 10 --open 172.17.64.82/20",
            "-sX -Pn --top-ports 10 --open 172.17.64.82/20",
            "-sM -Pn --top-ports 10 --open 172.17.64.82/20",
            ],
        # 9. TCP SYN Scan, All ports
        [
            "-Pn -p- --open 172.17.64.82/20",
            ],
        # 10. TCP Ack Scan, All ports
        [
            "-sA -Pn -p- --open 172.17.64.82/20",
            ],
        # 11. TCP Window Scan, All ports
        [
            "-sW -Pn -p- --open 172.17.64.82/20",
            ],
        # 12. Special Scans, All ports
        [
            "-sN -Pn -p- --open 172.17.64.82/20",
            "-sF -Pn -p- --open 172.17.64.82/20",
            "-sX -Pn -p- --open 172.17.64.82/20",
            "-sM -Pn -p- --open 172.17.64.82/20",
            ],
        ]



def run(target, index = 1):
    for i in range(index - 1, len(commands)):
        command_set = commands[i]
        for command in command_set:
            subprocess.run(["sudo", "nmap", target])


def main():
    target = sys.argv[1]
    index = 1 if (len(sys.argv) <= 2) else sys.argv[2]
    run(target, index)

if __name__ == "__main__":
    main()

