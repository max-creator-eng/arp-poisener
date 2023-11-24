import nmap
import socket


nm = nmap.PortScanner()


ip_address = socket.gethostbyname(socket.gethostname())


subnet_mask = "/24"


try:
    nm.scan(hosts=f"{ip_address}{subnet_mask}", arguments="-sn")
except nmap.nmap.PortScannerError as e:
    print(f"An error occurred while scanning: {e}")

# Print the table header
print("{:<20} {:<20} {:<20} {}".format("Hostname", "IP Address", "MAC Address", "Status"))
print("{:-<20} {:-<20} {:-<20} {:-<}".format("", "", "", ""))

# Iterate over each host and print its details
for host in sorted(nm.all_hosts()):
    if "vendor" in nm[host]["vendor"]:
        device_vendor = nm[host]["vendor"]["vendor"]
    else:
        device_vendor = "Unknown"
    status = nm[host]["status"]["state"]
    hostname = socket.getfqdn(host)
    if status == "up":
        if "mac" in nm[host]["addresses"]:
            mac_address = nm[host]["addresses"]["mac"]
        else:
            mac_address = "Unknown"
        print("{:<20} {:<20} {:<20} {}".format(hostname, host, mac_address, "Online"))
    else:
        print("{:<20} {:<20} {:<20} {}".format(hostname, host, device_vendor, "Offline"))
