from typing import List, Dict, Any, Optional
from pathlib import Path
from llama_cpp import Llama


PORT_EXPLANATIONS = {
    53: {
        "name": "DNS",
        "purpose": "Used to translate names like websites into network addresses.",
        "why_it_matters": (
            "This is often expected on a router or network device, but it should still be limited "
            "to the devices that actually need to use it."
        ),
        "how_to_reduce": [
            "Confirm the device is supposed to provide DNS",
            "Restrict access to trusted local devices",
            "Disable unnecessary network services on the device",
        ],
    },
    80: {
        "name": "HTTP",
        "purpose": "Used for web interfaces and web services.",
        "why_it_matters": (
            "This may be normal if the device has a browser-based interface, but it can increase exposure "
            "if management pages are left accessible more broadly than needed."
        ),
        "how_to_reduce": [
            "Confirm the web interface is expected",
            "Use strong credentials for admin pages",
            "Restrict access to trusted devices only",
        ],
    },
    135: {
        "name": "MSRPC",
        "purpose": "Used by Windows for internal communication between services.",
        "why_it_matters": (
            "This can be normal on Windows systems, but it still increases the number of network services "
            "available to other devices."
        ),
        "how_to_reduce": [
            "Review whether the device needs to be reachable by other local systems",
            "Restrict access through the firewall if appropriate",
            "Keep Windows updated",
        ],
    },
    139: {
        "name": "NetBIOS Session Service",
        "purpose": "Associated with older Windows network communication and file-sharing related features.",
        "why_it_matters": (
            "This may not be needed on all systems and can increase exposure if older networking features "
            "remain enabled unnecessarily."
        ),
        "how_to_reduce": [
            "Turn off unused file-sharing or discovery features",
            "Restrict access through the firewall",
            "Review whether legacy networking features are still needed",
        ],
    },
    445: {
        "name": "SMB / Microsoft-DS",
        "purpose": "Used by Windows for file sharing, printer sharing, and related network communication.",
        "why_it_matters": (
            "If this service is exposed when it is not needed, other devices on the local network may be able "
            "to reach shared resources or interact more directly with the system."
        ),
        "how_to_reduce": [
            "Turn off file and printer sharing if it is not needed",
            "Disable unused SMB-related sharing features",
            "Use Windows Firewall to restrict access",
            "Limit access to trusted local devices only",
        ],
    },
    443: {
        "name": "HTTPS",
        "purpose": "Used for secure web interfaces and encrypted web services.",
        "why_it_matters": (
            "This may be expected for a secure web interface, but it should still be protected with strong "
            "credentials and limited access."
        ),
        "how_to_reduce": [
            "Confirm the secure web service is needed",
            "Use strong passwords",
            "Restrict management access to trusted devices",
        ],
    },
    22: {
        "name": "SSH",
        "purpose": "Used for secure remote administration.",
        "why_it_matters": (
            "Remote administration services deserve attention because they allow direct management access "
            "to the device."
        ),
        "how_to_reduce": [
            "Disable SSH if it is not needed",
            "Restrict access to trusted IPs or devices",
            "Use strong authentication",
        ],
    },
    23: {
        "name": "Telnet",
        "purpose": "Used for remote login, usually without encryption.",
        "why_it_matters": (
            "This deserves high attention because Telnet does not protect traffic with encryption."
        ),
        "how_to_reduce": [
            "Disable Telnet if possible",
            "Replace it with SSH or another safer option",
            "Restrict access immediately if it must remain enabled",
        ],
    },
    3389: {
        "name": "Remote Desktop",
        "purpose": "Used for remote graphical access to Windows systems.",
        "why_it_matters": (
            "Remote access services increase exposure because they allow direct interactive access to the device."
        ),
        "how_to_reduce": [
            "Disable Remote Desktop if it is not needed",
            "Restrict access to trusted devices",
            "Use strong credentials and keep the system updated",
        ],
    },
}


MODEL_PATH = Path("models/Phi-3-mini-4k-instruct-q4.gguf")


def get_model() -> Llama:
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Model file not found: {MODEL_PATH}")

    return Llama(
        model_path=str(MODEL_PATH),
        n_ctx=4096,
        verbose=False,
    )


def classify_risk(port: int, service: Optional[str]) -> str:
    svc = (service or "").lower().strip()

    if port == 23:
        return "Critical"
    if port in (445, 3389, 5900, 27017):
        return "High"
    if port in (22, 21, 25, 110, 143, 3306, 5432):
        return "Medium"
    if port in (80, 443):
        return "Low"

    if "rdp" in svc or "ms-wbt-server" in svc:
        return "High"
    if "ssh" in svc or "ftp" in svc:
        return "Medium"
    if "http" in svc:
        return "Low"

    return "Low"


def build_host_label(host: Dict[str, Any]) -> str:
    ip = host.get("ip") or "unknown"
    hostname = host.get("hostname") or ""
    vendor = host.get("vendor") or ""

    if hostname:
        return f"{hostname} ({ip})"
    if vendor:
        return f"{vendor} ({ip})"
    return ip


def infer_device_type(host: Dict[str, Any]) -> str:
    hostname = (host.get("hostname") or "").lower()
    vendor = (host.get("vendor") or "").lower()
    combined = f"{hostname} {vendor}"

    router_words = [
        "router", "gateway", "d-link", "dlink", "linksys", "netgear",
        "tp-link", "tplink", "mikrotik", "ubiquiti", "asus"
    ]
    mobile_words = [
        "iphone", "android", "galaxy", "pixel", "huawei",
        "xiaomi", "phone", "mobile"
    ]
    computer_words = [
        "windows", "desktop", "laptop", "pc", "workstation"
    ]
    printer_words = [
        "printer", "epson", "canon", "brother", "lexmark"
    ]
    tv_console_words = [
        "playstation", "xbox", "bravia", "television", "tv", "sony interactive entertainment"
    ]

    if any(word in combined for word in router_words):
        return "router"
    if any(word in combined for word in mobile_words):
        return "mobile device"
    if any(word in combined for word in computer_words):
        return "computer"
    if any(word in combined for word in printer_words):
        return "printer"
    if any(word in combined for word in tv_console_words):
        return "media or console device"

    ports = {
        int(p.get("port", 0))
        for p in (host.get("open_ports") or [])
        if str(p.get("port", "")).isdigit()
    }

    if 445 in ports or 139 in ports or 135 in ports:
        return "possible Windows computer"
    if 53 in ports and (80 in ports or 443 in ports):
        return "possible router or network device"

    return "unknown device"


def get_port_explanation(port: int, service: Optional[str]) -> Optional[Dict[str, Any]]:
    if port in PORT_EXPLANATIONS:
        return PORT_EXPLANATIONS[port]

    svc = (service or "").lower().strip()

    if "https" in svc:
        return PORT_EXPLANATIONS.get(443)
    if "http" in svc:
        return PORT_EXPLANATIONS.get(80)
    if "ssh" in svc:
        return PORT_EXPLANATIONS.get(22)
    if "rdp" in svc or "ms-wbt-server" in svc:
        return PORT_EXPLANATIONS.get(3389)
    if "ftp" in svc:
        return {
            "name": "FTP",
            "purpose": "Used for file transfer between systems.",
            "why_it_matters": (
                "File transfer services may expose files or credentials if they are not configured carefully."
            ),
            "how_to_reduce": [
                "Disable FTP if it is not needed",
                "Use a more secure alternative if possible",
                "Restrict access to trusted devices",
            ],
        }
    if "asterisk" in svc:
        return {
            "name": "Asterisk / VoIP service",
            "purpose": "Associated with communication-related services.",
            "why_it_matters": (
                "Communication-related services may deserve review if they are not expected on the device."
            ),
            "how_to_reduce": [
                "Confirm the service is expected for the device",
                "Restrict access to trusted local devices only",
                "Disable the service if it is not needed",
            ],
        }
    if port >= 49152:
        return {
            "name": f"Port {port}",
            "purpose": f"A high-numbered service labelled as {service or 'unknown'}.",
            "why_it_matters": (
                "High-numbered ports are not automatically dangerous, but they should be reviewed to confirm "
                "they are expected for this device."
            ),
            "how_to_reduce": [
                "Check whether this service is expected for the device",
                "Disable unnecessary services if the device allows it",
                "Limit access to trusted local devices only",
            ],
        }

    return None


def get_highest_risk_for_host(host: Dict[str, Any]) -> str:
    open_ports = host.get("open_ports") or []
    if not open_ports:
        return "Low"

    risks = []
    for p in open_ports:
        port_num = int(p.get("port", 0)) if str(p.get("port", "")).isdigit() else 0
        service = p.get("service") or "unknown"
        risks.append(classify_risk(port_num, service))

    if "Critical" in risks:
        return "Critical"
    if "High" in risks:
        return "High"
    if "Medium" in risks:
        return "Medium"
    return "Low"


def get_most_important_port(host: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    open_ports = host.get("open_ports") or []
    if not open_ports:
        return None

    priority = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

    def key_fn(port_data: Dict[str, Any]) -> tuple:
        port_num = int(port_data.get("port", 0)) if str(port_data.get("port", "")).isdigit() else 0
        service = port_data.get("service") or "unknown"
        risk = classify_risk(port_num, service)
        return (priority.get(risk, 99), port_num)

    return sorted(open_ports, key=key_fn)[0]


def build_selected_device_context(host: Dict[str, Any]) -> str:
    label = build_host_label(host)
    ip = host.get("ip") or "unknown"
    hostname = host.get("hostname") or "None"
    vendor = host.get("vendor") or "Unknown"
    device_type = infer_device_type(host)

    open_ports = host.get("open_ports") or []
    port_list = ", ".join(str(p.get("port", "?")) for p in open_ports) if open_ports else "None"

    lines = [
        f"Selected device label: {label}",
        f"Selected device IP: {ip}",
        f"Selected device hostname: {hostname}",
        f"Selected device vendor: {vendor}",
        f"Inferred device type: {device_type}",
        f"Detected open ports on this device: {port_list}",
        f"Highest risk label on this device: {get_highest_risk_for_host(host)}",
    ]
    return "\n".join(lines)


def build_factual_findings(hosts: List[Dict[str, Any]]) -> str:
    if not hosts:
        return "No hosts were provided for analysis."

    host = hosts[0]
    label = build_host_label(host)
    open_ports = host.get("open_ports") or []

    lines = [f"Selected device: {label}", ""]

    if not open_ports:
        lines.append("Observed exposures:")
        lines.append("- No open ports detected")
        return "\n".join(lines)

    lines.append("Observed exposures:")

    for p in open_ports:
        try:
            port_num = int(p.get("port", 0))
        except (TypeError, ValueError):
            port_num = 0

        protocol = p.get("protocol", "tcp")
        service = p.get("service") or "unknown"
        product = p.get("product") or ""
        version = p.get("version") or ""
        extrainfo = p.get("extrainfo") or ""
        risk = classify_risk(port_num, service)

        details = " ".join(x for x in [product, version, extrainfo] if x).strip()

        if details:
            lines.append(f"- port {port_num}/{protocol} running {service} ({details}), risk={risk}")
        else:
            lines.append(f"- port {port_num}/{protocol} running {service}, risk={risk}")

    return "\n".join(lines)


def build_explanation_hints(hosts: List[Dict[str, Any]]) -> str:
    if not hosts:
        return "No explanation hints available."

    host = hosts[0]
    label = build_host_label(host)
    lines = []

    for p in host.get("open_ports") or []:
        try:
            port_num = int(p.get("port", 0))
        except (TypeError, ValueError):
            port_num = 0

        service = p.get("service") or "unknown"
        explanation = get_port_explanation(port_num, service)
        if not explanation:
            continue

        how_to_reduce = "; ".join(explanation["how_to_reduce"])

        lines.append(f"Host: {label}")
        lines.append(f"Port: {port_num}")
        lines.append(f"Service: {service}")
        lines.append(f"Name: {explanation['name']}")
        lines.append(f"Meaning: {explanation['purpose']}")
        lines.append(f"Why attention may be needed: {explanation['why_it_matters']}")
        lines.append(f"How exposure can often be reduced: {how_to_reduce}")
        lines.append("")

    if not lines:
        return "No additional explanation hints were generated for the observed services."

    return "\n".join(lines).strip()


def build_open_ports_summary_line(host: Dict[str, Any]) -> str:
    open_ports = host.get("open_ports") or []
    label = build_host_label(host)

    if not open_ports:
        return f"- No open ports were detected on {label}."

    parts = []
    for p in open_ports:
        port_num = p.get("port", "?")
        service = p.get("service") or "unknown"
        parts.append(f"port {port_num} ({service})")

    return f"- Open ports on {label} include " + ", ".join(parts) + "."


def build_important_port_summary_line(host: Dict[str, Any]) -> str:
    important = get_most_important_port(host)
    if not important:
        return "- No specific port stands out from this scan."

    port_num = int(important.get("port", 0)) if str(important.get("port", "")).isdigit() else 0
    service = important.get("service") or "unknown"
    risk = classify_risk(port_num, service)

    if risk in ("Critical", "High"):
        return f"- The most important or highest-risk port is port {port_num} ({service})."

    return f"- No port stands out as high risk, but port {port_num} ({service}) is a useful one to review first."


def build_why_this_matters_block(host: Dict[str, Any]) -> str:
    important = get_most_important_port(host)
    if not important:
        return (
            "Why this may matter:\n"
            "- No specific port stands out from this scan.\n"
        )

    port_num = int(important.get("port", 0)) if str(important.get("port", "")).isdigit() else 0
    service = important.get("service") or "unknown"
    explanation = get_port_explanation(port_num, service)
    device_type = infer_device_type(host)

    if explanation:
        base = explanation["why_it_matters"]
    else:
        base = "This port exposes a network service that other devices may be able to reach."

    if device_type == "router" and port_num == 53:
        detail = (
            "This is commonly expected on a router because it helps devices on the network translate names into addresses."
        )
    else:
        detail = f"Port {port_num} ({service}) deserves the most attention on this device."

    return (
        "Why this may matter:\n"
        f"- {detail}\n"
        f"- {base}\n"
    )


def build_next_step_block(host: Dict[str, Any]) -> str:
    important = get_most_important_port(host)
    if not important:
        return (
            "Next step:\n"
            "- You can ask below if you want more detail about this result.\n"
        )

    port_num = int(important.get("port", 0)) if str(important.get("port", "")).isdigit() else 0
    open_ports = host.get("open_ports") or []
    port_numbers = [str(p.get("port", "?")) for p in open_ports]

    if len(port_numbers) == 1:
        ask_text = f"port {port_num}"
    elif len(port_numbers) == 2:
        ask_text = f"port {port_numbers[0]} or port {port_numbers[1]}"
    else:
        ask_text = ", ".join(f"port {p}" for p in port_numbers[:-1]) + f", or port {port_numbers[-1]}"

    return (
        "Next step:\n"
        f"- You can ask for more details about {ask_text}, or how to secure these ports on your device.\n"
    )


def build_no_open_ports_response(host: Dict[str, Any]) -> str:
    label = build_host_label(host)
    return (
        "Summary:\n"
        f"- No open ports were detected on {label} in this scan.\n"
        "- This suggests the device is not currently exposing obvious local network services.\n\n"
        "Why this may matter:\n"
        "- Fewer exposed services usually means less visible network exposure from this scan result.\n"
        "- There is nothing notable to explain from open ports alone in this case.\n\n"
        "Recommended next steps:\n"
        "1. Leave the device as it is unless you expected a service to be visible.\n"
        "2. Re-scan later if the device role changes or new services are enabled.\n"
        "3. Ask below if you want clarification about this result.\n"
    )


def build_chat_prompt(host: Dict[str, Any], question: str, last_port: Optional[int] = None) -> str:
    selected_device_context = build_selected_device_context(host)
    explanation_hints = build_explanation_hints([host])
    findings_text = build_factual_findings([host])

    focus_line = ""
    if last_port is not None:
        focus_line = f"Current focus port: {last_port}\n\n"

    instructions = (
        "You are a cybersecurity assistant for a university project.\n"
        "Answer a follow-up question about one selected device only.\n"
        "Use only the supplied facts and explanation hints.\n"
        "Do not mention other devices.\n"
        "Do not claim confirmed vulnerability, compromise, malware, or attack.\n"
        "Do not provide exploitation steps.\n"
        "Only answer the user's actual question.\n"
        "Do not restart the full summary unless the user explicitly asks for a summary.\n"
        "If the user asks about one specific port, only answer about that port.\n"
        "If a focus port is provided, answer only about that port unless the user clearly changes to another port.\n"
        "If the user uses a vague follow-up like 'explain more' or 'what does it do', continue talking about the focus port.\n"
        "Do not switch to a different port unless the user explicitly asks.\n"
        "If the answer is not supported by the supplied information, say that the scan does not provide enough information.\n"
        "Keep the answer short, direct, and easy for a non-technical user to understand.\n"
        "Do not repeat the prompt or metadata.\n"
        "If the user asks how to close, disable, or restrict a port, you may give general operating system steps (such as stopping a service, closing an application, or using firewall settings), but do not provide advanced or exploitation instructions.\n"
        "Do not output selected device context, factual findings, or explanation hints.\n"
        "Keep the answer under 120 words.\n"
    )

    return (
        f"<|user|>\n"
        f"{instructions}\n\n"
        f"{focus_line}"
        f"Selected device context:\n{selected_device_context}\n\n"
        f"Factual findings:\n{findings_text}\n\n"
        f"Explanation hints:\n{explanation_hints}\n\n"
        f"User question:\n{question}\n"
        f"<|assistant|>\n"
    )


def clean_model_output(text: str) -> str:
    if not text:
        return "No AI explanation was generated."

    leak_markers = [
        "Author:",
        "You are a cybersecurity assistant",
        "You are a cybersecurity analysis assistant",
        "Strict rules:",
        "Selected device context:",
        "Factual findings:",
        "Explanation hints:",
        "User question:",
        "**User follow-up question:**",
        "(Word count:",
        "(Note:",
        "Written in English:",
        "Detected open ports on this",
        "<|user|>",
        "<|assistant|>",
    ]

    cut_positions = []
    for marker in leak_markers:
        pos = text.find(marker)
        if pos != -1:
            cut_positions.append(pos)

    if cut_positions:
        text = text[:min(cut_positions)].strip()

    for frag in ["ta:", "Written in English:", "Detected open ports on this"]:
        text = text.replace(frag, "")

    lines = [line.rstrip() for line in text.splitlines()]
    text = "\n".join(lines).strip()
    text = text.replace("\n\n\n", "\n\n")

    return text or "No AI explanation was generated."


def run_local_model(prompt: str, max_tokens: int = 220) -> str:
    llm = get_model()

    response = llm(
        prompt,
        max_tokens=max_tokens,
        temperature=0.0,
        stop=["<|user|>", "</s>"],
    )

    return response["choices"][0]["text"].strip()


def analyse_scan(hosts: List[Dict[str, Any]], use_real_llm: bool = True) -> str:
    if not hosts:
        return "No AI explanation was generated."

    host = hosts[0]
    open_ports = host.get("open_ports") or []
    if not open_ports:
        return build_no_open_ports_response(host)

    # Python owns the main result structure completely
    return (
        "Summary:\n"
        f"{build_open_ports_summary_line(host)}\n"
        f"{build_important_port_summary_line(host)}\n\n"
        f"{build_why_this_matters_block(host)}\n"
        f"{build_next_step_block(host)}"
    ).strip()


def analyse_single_host(host: Dict[str, Any], use_real_llm: bool = True) -> str:
    return analyse_scan([host], use_real_llm=use_real_llm)


def answer_question(host: Dict[str, Any], question: str, last_port: Optional[int] = None, use_real_llm: bool = True) -> str:
    question = (question or "").strip()
    if not question:
        return "Please enter a question about the selected device or its ports."

    open_ports = host.get("open_ports") or []
    if not open_ports:
        return (
            "No open ports were visible for this device in the scan, so there is no additional port-specific detail to explain.\n\n"
            "This result suggests lower visible network exposure from this scan, but the scan does not provide more detail beyond that."
        )

    if not use_real_llm:
        return (
            "QUESTION:\n"
            + question
            + "\n\n"
            + build_selected_device_context(host)
            + "\n\n"
            + build_factual_findings([host])
            + "\n\n"
            + build_explanation_hints([host])
        )

    prompt = build_chat_prompt(host, question, last_port=last_port)
    text = run_local_model(prompt, max_tokens=180)
    cleaned = clean_model_output(text)

    if not cleaned:
        return "The scan does not provide enough information to answer that clearly."

    return cleaned