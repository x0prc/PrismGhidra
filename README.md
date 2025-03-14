
![A](https://github.com/user-attachments/assets/4ddcfc8f-96ca-4b7d-a35a-692bdb115b85)
# Prism - Ghidra Plugin Suite
A toolkit of five plugins designed to work in Ghidra providing support for Debugging, Config Extraction, API Mapping, Visualisation and Taint Analysis.

## Features

1. **Debugger**
   - Enables debugging within Ghidra using external or integrated debugging tools.
   - Supports setting breakpoints, stepping through code, and inspecting registers and memory.
   - Works with common debugging backends like GDB and WinDbg.

2. **Configuration Extractor**
   - Automates the extraction of embedded configurations from binaries.
   - Identifies hardcoded credentials, URLs, IPs, and other artifacts.
   - Supports pattern matching and heuristics to detect configuration structures.
   - Works with C2_Server, Base64, PE_Header Malware Signatures.

3. **API Mapping**
   - Maps detected API calls to well-known libraries and functions.
   - Helps identify the purpose of obfuscated or unknown binaries.
   - Supports cross-referencing APIs with known malware behaviors.

4. **Visualization**
   - Provides graphical representations of control flow, call graphs, and data dependencies.
   - Enhances understanding of program structure and function relationships.
   - Supports export to common visualization formats.

5. **Taint Analysis**
   - Tracks data flow through a binary to identify potential vulnerabilities.
   - Highlights tainted variables and their propagation paths.
   - Supports both static and dynamic analysis modes.

## Installation

1. Ensure you have [Ghidra](https://github.com/NationalSecurityAgency/ghidra) installed.
2. Clone this repository:
   ```sh
   git clone https://github.com/x0prc/PrismGhidra.git
   ```
3. Navigate to the repository:
   ```sh
   cd PrismGhidra
   ```
4. Build the plugins using Gradle:
   ```sh
   ./gradlew build
   ```
5. Copy the built extensions (`.zip` files) to Ghidra's **Extensions** directory.
6. Open Ghidra, go to **File → Install Extensions**, and enable the plugins.

## Usage

### Debugger 
- Open a binary in Ghidra.
- Navigate to **Debugger** from the toolbar.
- Attach to a process or start debugging.

### Configuration Extractor 
- Analyze a binary using **Auto-Analysis**.
- Open the **Configuration Extractor** tool.
- View extracted data in the results pane.
- Add preffered Malware Patterns under `MalwareConfigExtractor/src/main/resources/`

### API Mapping 
- Load a binary and run **API Analysis**.
- View the API mapping results in the **Function Call Explorer**.

### Visualization 
- Open **Visualization** from the tools menu.
- Generate control flow or call graphs for functions.

### Taint Analysis 
- Select a function or variable.
- Run **Taint Analysis** to track its flow.
- View results in the **Taint Propagation Window**.

## Dependencies
- Ghidra version **10.x or later**
- Java **11+**
- Gradle **7+**

## Contributing
Contributions are welcome! Follow these steps:
1. Fork the repository.
2. Create a new branch for your feature/fix.
3. Commit your changes.
4. Submit a pull request.

## License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
