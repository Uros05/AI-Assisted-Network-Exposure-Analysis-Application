AI-Assisted Network Exposure Analyser

Setup Instructions:


1. Install Nmap (If not already installed on device)

   * Run "nmap-7.98-setup.exe" as Administrator
   * Ensure Npcap is installed
   * Allow adding Nmap to PATH

2. Run the Application

   * Run "FINAL_APP.exe" as Administrator
   * Administrator privileges are required for network scanning to function correctly


Notes:

* Ensure that FINAL_APP.exe, FINAL_AI.exe, and the "models" folder are all located in the same directory
* FINAL_AI.exe is the AI runner used by the application and DOES NOT need to be opened manually
* All other supporting Python files or folders DO NOT need to be executed
* If the AI model is not present, the application will still run, but AI-based explanations will not be available
* The application performs network scanning and AI-based explanation of exposed services
* No data is sent externally. All analysis is performed locally
