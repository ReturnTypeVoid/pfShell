# pfShell  
_A PowerShell module for parsing and analysing pfSense configurations. Not sure how much use it will be for everyone, but I needed something quick and accurate so I created this._

---

## Overview

`pfShell` is a PowerShell module designed to help you parse and analyse configurations from **pfSense** firewall XML exports. The project is in its early stages, and mileage may vary, but the goal is to provide a tool to provide a baseline audit of **pfSense** firewalls.

---

## Features

- Parse firewall rules directly from pfSense XML exports.
- Categorise rules by severity (High, Medium, Low).
- Identify potentially risky configurations, such as overly permissive traffic and weak SNMP community strings.
- Generate Excel outputs of the rules, split by severity (optional).

---

## Features Planned

- Parsing and analysing NAT rules.
- Extended SNMP analysis.
- Further analysis of baseline configuration.
- Improved reporting options.

---

## Severity Criteria

| **Severity** | **Description**                                                                  |
|--------------|----------------------------------------------------------------------------------|
| High         | Rule allows packets to any destination on any service/port.                     |
| High         | Rule allows any source, any destination, and multiple service/ports.            |
| Medium       | Rule allows packets from any source to a specific destination and port.         |
| Medium       | Rule allows packets to any destination from a specific source and port.         |
| Medium       | Rule allows packets to any service/port from a specific source and destination. |
| Medium       | Rule allows packets to a large range of service/ports (range ≥ 1000 ports).     |
| Medium       | Alias has excessive ports in a port/service group.                              |
| Low          | Reject rule identified in the configuration.                                     |

---

### Note on Severity

The severity levels assigned to each check are intended to serve as a **baseline assessment**. They are not definitive and should be interpreted in the context of your specific environment and security policies. Factors such as the purpose of the rule, the overall network design, and the organisational risk tolerance may influence whether a rule is acceptable or requires attention.

It is recommended that results from `pfShell` are reviewed by a network security professional to ensure alignment with your security objectives.

---

## Installation

Clone this repository to your local machine:

```bash
git clone https://github.com/returntypevoid/pfShell.git
```

Import the module into your PowerShell session:

```powershell
Import-Module .\pfShell\pfShell.psm1
```

**Note**: The script will automatically install the `ImportExcel` module if it is not already installed.

---

## Usage

### Analyse pfSense Configuration

To analyse a pfSense configuration file, use the `Invoke-PfShell` function:

```powershell
Invoke-PfShell -XmlPath "C:\Path\To\pfSenseExport.xml"
```

### Generate Reports

To generate Excel reports from the analysis, add the `-Report` switch:

```powershell
Invoke-PfShell -XmlPath "C:\Path\To\pfSenseExport.xml" -Report
```

The reports will be saved in a folder named `pfShell - <hostname>` in the current directory.

---

## Contributing

Contributions are welcome! If you’d like to help improve `pfShell`, please fork the repository and submit a pull request. Feel free to open issues for bug reports or feature suggestions.

---

## License

This project is licensed under the [Creative Commons Attribution-NonCommercial 4.0 International License](LICENSE).

### Summary:

- You are free to fork, edit, and share this work, provided credit is given to the author.
- The work cannot be integrated into commercial products or sold as part of any product.
- The work may be used in commercial services, such as penetration testing, provided that:
    - It is properly referenced in reports or documentation.
    - The work is not resold or directly monetised as a standalone offering.
- Non-commercial services and personal projects are fully permitted.

---

## Author

Created by **Reece Alqotaibi** (a.k.a. `ReturnTypeVoid`).

- GitHub: [returntypevoid](https://github.com/returntypevoid)

---

## Disclaimer

This project is in its early stages, and whilst I plan to update, **mileage may vary**. Please report any issues or suggestions.
