import socket
import sys
from binascii import hexlify

interface = sys.argv[1]

print("Retrieving host information from interface ", interface)

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((interface, 0))

hostname = s.getsockname()
mac = s.getsockname()[4]
print("Hostname: ", hostname)
print(str(type(mac)))
print("Mac: ", hexlify(mac))

s.close()
