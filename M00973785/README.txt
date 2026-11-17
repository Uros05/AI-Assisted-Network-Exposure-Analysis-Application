AI-Assisted Network Exposure Analyser

Setup Instructions:

1. Download the AI Model

   * Download the required model file from:
     https://drive.google.com/file/d/1sHRi6ogs6fsM82sxc5j4bVJF44RyRr1P/view?usp=sharing

   * Click "Download" in the top right corner of the page
   * If a warning appears (file too large), select "Download anyway"

   * NOTE: If the google drive link for some reason does not work you can also download it from here:
     https://huggingface.co/microsoft/Phi-3-mini-4k-instruct-gguf/blob/main/Phi-3-mini-4k-instruct-q4.gguf

   * Ensure the file is named exactly:
     Phi-3-mini-4k-instruct-q4.gguf

   * If the file name changes after download, rename it back to the correct name before placing it in the folder

2. Place the Model File

   * Create a folder named "models" in the same directory as the application (if it does not already exist)
   * Place the downloaded model file inside the "models" folder

   Example folder structure:

   /Application Folder/
       nmap-7.98-setup.exe
       FINAL_APP.exe
       FINAL_AI.exe
       models/
           Phi-3-mini-4k-instruct-q4.gguf

3. Install Nmap

   * Run "nmap-7.98-setup.exe" as Administrator
   * Ensure Npcap is installed
   * Allow adding Nmap to PATH

4. Run the Application

   * Run "FINAL_APP.exe" as Administrator
   * Administrator privileges are required for network scanning to function correctly


Notes:

* Ensure that FINAL_APP.exe, FINAL_AI.exe, and the "models" folder are all located in the same directory
* FINAL_AI.exe is the AI runner used by the application and DOES NOT need to be opened manually
* All other supporting Python files or folders DO NOT need to be executed
* If the AI model is not present, the application will still run, but AI-based explanations will not be available
* The application performs network scanning and AI-based explanation of exposed services
* No data is sent externally. All analysis is performed locally