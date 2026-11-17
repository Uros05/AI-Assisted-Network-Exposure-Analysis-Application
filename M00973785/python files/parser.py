import xml.etree.ElementTree as ET


def parse_nmap_xml(xml_file: str):
    """
    Parses an Nmap XML output file and returns a list of hosts.
    Each host includes:
      - ip
      - mac (optional)
      - vendor (optional)
      - hostname (optional)
      - open_ports (list)
    """

    tree = ET.parse(xml_file)
    root = tree.getroot()

    results = []

    for host in root.findall("host"):
        # Skip hosts that are not up
        status_elem = host.find("status")
        if status_elem is None or status_elem.get("state") != "up":
            continue

        # Get IP and MAC (if present)
        ip = None
        mac = None
        vendor = None

        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor")

        # Get hostname (if present)
        hostname = None
        hn = host.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name")

        # Extract open ports
        open_ports = []

        for port in host.findall("ports/port"):
            state_elem = port.find("state")
            if state_elem is None:
                continue

            if state_elem.get("state") != "open":
                continue

            service_elem = port.find("service")

            open_ports.append({
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "service": service_elem.get("name") if service_elem is not None else None,
                "product": service_elem.get("product") if service_elem is not None else None,
                "version": service_elem.get("version") if service_elem is not None else None,
                "extrainfo": service_elem.get("extrainfo") if service_elem is not None else None
            })

        results.append({
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "hostname": hostname,
            "open_ports": open_ports
        })

    return results