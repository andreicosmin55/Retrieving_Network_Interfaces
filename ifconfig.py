import os
import json
import ipaddress

''' 
    # hex_to_ip(): function used to convert a hexadecimal IPv4 address to dotted decimal format.
    # Input: str -> Output: str
'''
def hex_to_ip(hex_str):
    if not isinstance(hex_str, str):
        raise ValueError("Input must be a string.")

    # length must be 8 for accurate conversion
    if len(hex_str) != 8:
        raise ValueError("Input must be an 8-character hexadecimal string.")

    # conversion from big-endian format hexadecimal to little-endian format decimal
    return '.'.join(str(int(hex_str[i:i+2], 16)) for i in range(6, -2, -2))

''' 
    # decimal_to_ip(): function used to convert a decimal IPv4 subnet mask to dotted decimal format.
    # Input: int -> Output: str
'''
def decimal_to_ip(decimal):
    if not isinstance(decimal, int):
        raise ValueError("Input must be an integer.")

    # 1-32 value for int is valid
    if decimal < 1 or decimal > 32:
        raise ValueError("Input must be between 1 and 32.")

    # 32-bit mask with decimal number of ones
    mask = (0xFFFFFFFF << (32 - decimal)) & 0xFFFFFFFF

    # split into four octets
    octets = [
        (mask >> 24) & 0xFF,
        (mask >> 16) & 0xFF,
        (mask >> 8) & 0xFF,
        mask & 0xFF
    ]

    return '.'.join(map(str, octets))

'''
    # get_inet(): function used to get the IPv4 address and netmask of an interface from /proc/net/ files.
    # Input: str -> Output: dict
'''
def get_inet(interface):
    net_tuple = "null"

    # treat special case of loopback interface since it is not present in /proc/net/route
    if interface == "lo":
        try:
            with open("/proc/net/fib_trie", "r") as f:
                lines = f.readlines()
                matching_line = None
                mask_flag = False
                prev_line = None
                for line in lines:
                    # first line matching 127. contains the actual subnet mask
                    if not mask_flag and "127." in line and "/" in line:
                        mask_flag = True
                        parts = line.split('/')
                        if len(parts) > 1:
                            mask = int(parts[1].split()[0])
                        else:
                            mask = "null"
                    if '/32 host' in line and '127.' in prev_line:
                        matching_line = prev_line.split()[1] if len(line.split()) > 1 else None
                    prev_line = line
                if matching_line and mask:
                    net_tuple = {"address": matching_line, "netmask": decimal_to_ip(mask)}

        except FileNotFoundError:
            print("Error: /proc/net/fib_trie not found.")
        except PermissionError:
            print("Error: Permission denied when accessing /proc/net/fib_trie.")
        except Exception as e:
            print(f"Unexpected error: {e}")
        return net_tuple

    else:
        # extract other local routes from /proc/net/fib_trie
        try:
            with open("/proc/net/fib_trie", "r") as f:
                lines = f.readlines()
                local_routes = []
                flag = False  # flag used to check if line starts with "Local:", then append all the lines after it
                for line in lines:
                    if line.strip().startswith("Local:"):
                        flag = True
                    if flag:
                        local_routes.append(line.strip())
        except FileNotFoundError:
            print("Error: /proc/net/fib_trie not found.")
            local_routes = []
        except PermissionError:
            print("Error: Permission denied when accessing /proc/net/fib_trie.")
            local_routes = []
        except Exception as e:
            print(f"Unexpected error: {e}")
            local_routes = []

        # extract network routes from /proc/net/route
        network_routes = {}
        try:
            with open("/proc/net/route", "r") as f:
                for line in f.readlines()[1:]:  # skip the header line
                    parts = line.split()
                    iface, net_dest, _, _, _, _, _, mask = parts[:8]
                    if iface == interface and net_dest != "00000000" and mask != "FFFFFFFF":
                        if iface not in network_routes:
                            network_routes[iface] = [(net_dest, mask)]
        except FileNotFoundError:
            print("Error: /proc/net/route not found.")
        except PermissionError:
            print("Error: Permission denied when accessing /proc/net/route.")
        except Exception as e:
            print(f"Unexpected error: {e}")

        for _, networks in network_routes.items():
            for net_hex, mask_hex in networks:
                net_dec, mask_dec = hex_to_ip(net_hex), hex_to_ip(mask_hex)

                matching_line = None
                flag = False
                # find the last matching net address before reaching the one containing "/32 host"
                for line in local_routes:
                    if net_dec in line.split():
                        flag = True
                    if '/32 host' in line:
                        flag = False
                    if flag:
                        matching_line = line.split()[1] if len(line.split()) > 1 else None

                if matching_line:
                    net_tuple = {"address": matching_line, "netmask": mask_dec}

            return net_tuple

'''
    # hex_to_ipv6(): function used to convert a hexadecimal string IPv6 address to colon separated format.
    # Input: str -> Output: str
'''
def hex_to_ipv6(hex_addr):
    if not isinstance(hex_addr, str):
        raise ValueError("Input must be a string.")

    # length must be 32 for accurate conversion
    if len(hex_addr) != 32:
        raise ValueError("Input must be a 32-character hexadecimal string.")

    return ":".join(hex_addr[i:i+4] for i in range(0, 32, 4))

'''
    # hex_to_mask(): function used to convert a hexadecimal mask to colon separated format.
    # Input: int -> Output: str
'''
def hex_to_mask(prefix_len):
    prefix_len = int(prefix_len, 16)
    # first prefix_len bits are set to one, the rest until 128 to zero
    mask_bits = f"{'1' * prefix_len}{'0' * (128 - prefix_len)}"

    # conversion from binary to hex, and display 0 instead of 0000
    return ":".join(hex(int(mask_bits[i:i+16], 2))[2:].lstrip("0") or "0" for i in range(0, 128, 16))

'''
    # get_inet6(): function used to get the IPv6 address and subnet mask of an interface from /proc/net/ files.
    # Input: str -> Output: dict
'''
def get_inet6(ifname):
    final_ipv6_addr = None

    if ifname == "lo":
        try:
            with open("/proc/net/ipv6_route", "r") as f:
                for line in f:
                    parts = line.split()
                    dest, prefix_len, _, _, _, _, _, _, _, iface = parts[:10]
                    if iface == ifname and dest != "00000000000000000000000000000000" and prefix_len != "00":
                        return {"ipv6_addr": str(ipaddress.ip_address(hex_to_ipv6(dest))), "network_mask": hex_to_mask(prefix_len)}
                return "null"
        except FileNotFoundError:
            print("Error: /proc/net/if_inet6 not found.")
        except PermissionError:
            print("Error: Permission denied when accessing /proc/net/if_inet6")
        except Exception as e:
            print(f"Unexpected error: {e}")

    else:
        try:
            with open("/proc/net/if_inet6", "r") as f:
                for line in f:
                    parts = line.split()
                    ipv6_addr, _, prefix_len, scope, _, iface = parts
                    if iface == ifname and scope == "20":  # scopeid 0x20<link>
                        final_ipv6_addr = hex_to_ipv6(ipv6_addr)
                        break
        except FileNotFoundError:
            print("Error: /proc/net/if_inet6 not found.")
        except PermissionError:
            print("Error: Permission denied when accessing /proc/net/if_inet6")
        except Exception as e:
            print(f"Unexpected error: {e}")

        if not final_ipv6_addr:
            return "null"

        network_mask = None
        with open("/proc/net/ipv6_route", "r") as f:
            for line in f:
                parts = line.split()
                dest, prefix_len, _, _, _, _, _, _, _, iface = parts[:10]
                # name-check, check for the first 4 hextet to be the same, destination netmask should not be 128
                if iface == ifname and hex_to_ipv6(dest).startswith(final_ipv6_addr[:19]) and int(prefix_len, 16) != 128:
                    network_mask = hex_to_mask(prefix_len)
                    break

        return {"ipv6_addr": str(ipaddress.ip_address(final_ipv6_addr)), "network_mask": network_mask}

'''
    # get_interfaces_info(): function used to get the details of all network interfaces present in /sys/class/net
    # Output: list 
'''
def get_interfaces_info():
    net_path = "/sys/class/net/"
    interfaces = []

    for ifname in os.listdir(net_path):
        iface_path = os.path.join(net_path, ifname)
        if not os.path.isdir(iface_path):
            continue

        def read_file(path):
            try:
                with open(path, "r") as file:
                    return file.read().strip()
            except (FileNotFoundError, PermissionError, OSError):
                return None

        # build the json
        interfaces.append({
            "ifname": ifname,
            "hwaddr": read_file(os.path.join(iface_path, "address")),
            "operstate": read_file(os.path.join(iface_path, "operstate")).upper(),
            "inet": get_inet(ifname),
            "inet6": get_inet6(ifname),
            "mtu": read_file(os.path.join(iface_path, "mtu")),
            "link_speed": read_file(os.path.join(iface_path, "speed"))
        })

    return interfaces


if __name__ == "__main__":
    interfaces_info = get_interfaces_info()
    data = {"count": len(interfaces_info), "interfaces": interfaces_info}
    print(json.dumps(data, indent=2))

