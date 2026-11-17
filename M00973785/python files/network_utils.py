import subprocess     # Used to run Windows system commands
import re             # Used for parsing command output safely
import psutil         # Used to read network interface details
import socket         # Used to identify IPv4 addresses
import ipaddress      # Used to calculate subnet from IP + netmask


def get_default_ipv4_interface_ip():
    """
    Determines which local IPv4 address is used for the default route.

    """

    # Run Windows routing table command
    result = subprocess.run(
        ["route", "print", "-4"],     # "-4" restricts output to IPv4 routes
        capture_output=True,
        text=True,
        check=False
    )

    routing_table = result.stdout

    # Parse line by line
    for line in routing_table.splitlines():

        line = line.strip()

        # We only care about default route entries
        if not line.startswith("0.0.0.0"):
            continue

        # Split columns safely (handles variable spacing)
        parts = re.split(r"\s+", line)

        # Validate structure of default route
        if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":

            gateway = parts[2]         # Not used yet, but useful later
            interface_ip = parts[3]    # THIS is what we want

            return interface_ip

    return None


def detect_active_subnet():
    """
    Uses the default-route interface IP to locate the correct subnet.

    

    This avoids selecting VirtualBox / VMware networks.
    """

    # Step 1 — Determine which IP Windows is actually using
    default_ip = get_default_ipv4_interface_ip()

    if not default_ip:
        return None

    # Get interface status (up/down)
    stats = psutil.net_if_stats()

    # Step 2 — Find matching interface inside psutil data
    for interface, addrs in psutil.net_if_addrs().items():

        # Skip interfaces that are down
        if interface in stats and not stats[interface].isup:
            continue

        for addr in addrs:

            # Only IPv4 addresses
            if addr.family != socket.AF_INET:
                continue

            ip = addr.address
            netmask = addr.netmask

            # Match interface used for default route
            if ip != default_ip:
                continue

            ip_obj = ipaddress.IPv4Address(ip)

            # Safety filters

            # Skip localhost
            if ip_obj.is_loopback:
                continue

            # Skip APIPA
            if ip_obj in ipaddress.IPv4Network("169.254.0.0/16"):
                continue

            # Calculate subnet from IP + netmask
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)

            return {
                "interface": interface,
                "ip": ip,
                "netmask": netmask,
                "network": str(network),
                "num_hosts": network.num_addresses
            }

    return None