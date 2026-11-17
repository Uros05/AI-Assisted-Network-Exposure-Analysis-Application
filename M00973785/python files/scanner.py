import subprocess 
from datetime import datetime 
from pathlib import Path 


def run_nmap_scan(target_network: str, output_dir: str = "scans") -> str: 
    
    """ 
    Executes an Nmap scan and saves XML output. 

    Parameters: 
     target_network → Network range to scan (CIDR) 
     output_dir → Directory where scan results are stored
     
     Returns: Path to generated XML file """ 
     
     
     # Ensure scans directory exists 
    out_path = Path(output_dir) 
    out_path.mkdir(parents=True, exist_ok=True) 
     
     # Create timestamped filename 
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S") 
    xml_file = out_path / f"scan_{timestamp}.xml" 
     
     # Construct Nmap command 
    command = [ 
        "nmap", 
        "-sS", # SYN scan (efficient, realistic scanning)
        "-sV", # Service/version detection 
        "-oX", # XML output format 
        str(xml_file), target_network 
        ] 
        
        # Run Nmap 
    result = subprocess.run(command, capture_output=True, text=True) 
        
        # Basic failure handling 
    if result.returncode != 0: 
            raise RuntimeError( 
                f"Nmap Scan Failed\n" 
                f"STDOUT:\n{result.stdout}\n" 
                f"STDERR:\n{result.stderr}" 
                )
    return str(xml_file)