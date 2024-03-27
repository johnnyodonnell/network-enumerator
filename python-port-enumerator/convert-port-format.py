
ports = []

# Retrieved by running `nmap --top-ports 100 localhost -v -oG -`
# Command from https://security.stackexchange.com/a/78625
raw_ports = "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157"

raw_split = raw_ports.split(",")

for entry in raw_split:
    range_split = entry.split("-")
    if len(range_split) == 1:
        ports.append(int(range_split[0]))
    elif len(range_split) > 2:
        print("Malformed range.")
        exit()
    else:
        for port in range(int(range_split[0]), int(range_split[1]) + 1):
            ports.append(port)

print(ports)
print(len(ports))

