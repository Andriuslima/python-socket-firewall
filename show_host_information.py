import socket
import time
from platform import python_version

print("Retrieving host information...")
print(python_version())

hostname = socket.gethostname()
ip_address_info = socket.gethostbyname_ex(hostname)
ip_address = socket.gethostbyname(hostname)
print("Hostname: ", hostname)
print("IP Address: ", ip_address)
print("Extra info: ", ip_address_info)
