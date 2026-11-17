import sys
from parser import parse_nmap_xml
from ai_analysis import analyse_single_host, answer_question
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")


def main():
    if len(sys.argv) < 4:
        print("ERROR: Missing XML path, selected host IP, or mode")
        sys.exit(1)

    xml_path = sys.argv[1]
    selected_ip = sys.argv[2]
    mode = sys.argv[3].strip().lower()

    try:
        hosts = parse_nmap_xml(xml_path)

        selected_host = None
        for host in hosts:
            if (host.get("ip") or "") == selected_ip:
                selected_host = host
                break

        if not selected_host:
            print(f"ERROR: Host with IP {selected_ip} was not found in the scan results")
            sys.exit(1)

        if mode == "explain":
            result = analyse_single_host(selected_host, use_real_llm=True)

        elif mode == "chat":
            if len(sys.argv) < 5:
                print("ERROR: Missing chat question")
                sys.exit(1)

            question = sys.argv[4].strip()
            if not question:
                print("ERROR: Chat question is empty")
                sys.exit(1)

            last_port = None
            if len(sys.argv) >= 6:
                try:
                    last_port = int(sys.argv[5])
                except ValueError:
                    last_port = None

            result = answer_question(selected_host, question, last_port=last_port, use_real_llm=True)

        else:
            print(f"ERROR: Unsupported mode '{mode}'. Use 'explain' or 'chat'")
            sys.exit(1)

        print(result, flush=True)

    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()