Overview
This repository contains my ongoing research and analysis of the "BlueShade" ransomware, a new .NET-based malware family first observed in January 2025. BlueShade is notable for its use of sophisticated AMSI bypass techniques, custom encryption implementation, and anti-analysis features.

⚠️ WARNING: This repository contains decompiled code, analysis tools, and technical writeups related to malware. The code is provided for educational purposes only. Do not use these techniques or tools for malicious purposes.

Repository Contents

TO DO STILL!

Key Findings

BlueShade uses a multi-stage execution flow with heavy obfuscation
Custom implementation of AES-256 with unusual key derivation function
At least 3 different AMSI bypass techniques included in the loader
.NET reflection used extensively for dynamic loading of encrypted payloads
File markers and extensions consistent across all observed samples: .blueshade
Embedded PowerShell scripts for credential theft and lateral movement
