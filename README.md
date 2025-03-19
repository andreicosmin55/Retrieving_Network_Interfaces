ifconfig.py

Python script created to retrieve information about the network interfaces ARP of a Linux system. It uses sysfs and procfs to get the necessary data, so it should work on most Linux distributions.

Short Description of how the program works:
  - select each directory from /sys/class/net/* (all the directories present here are net interfaces)
  - read the content of certain files from /sys/class/net/{if_name}/ (like /address contains MAC address, etc) for the general specifications (MAC address, speed, mtu, operstate)
  - with each interface name, determine the ipv4 address and mask from /proc/net/fib_trie and /proc/net/route (exception loopback interface that is not present under /route)
  - with each interface name, determine the ipv6 address and mask from /proc/net/if_inet6 and /proc/net/ipv6_route (exception loopback interface which can be determined only with /ipv6_route)
  - combine all data in a json format and print it
