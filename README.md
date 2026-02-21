# IHP - Imagine Hacking People

[![Download IHP](https://img.shields.io/github/v/release/KnechtUnrecht/IHP?label=Download&style=for-the-badge)](https://github.com/KnechtUnrecht/IHP/releases/latest/download/IHP.exe)

A Minecraft JAR antivirus scanner built for the community. Scans `.jar` mod/plugin files for malware, stealers, RATs, and other threats targeting Minecraft players.

## What It Does

IHP statically analyzes Java `.class` files inside JAR archives to detect:

- **Known malware** - Fractureiser, Skyrage, Stargazers, zEus, and 40+ known malicious hashes
- **Remote Access Trojans (RATs)** - Command execution, screen capture, keyloggers, socket backdoors
- **Info stealers** - Browser data theft (Chrome, Firefox, Edge, Brave), Discord token grabbers, crypto wallet theft, Steam/Telegram/Roblox session theft
- **Trojan behavior** - Self-replication, mod infection, persistence mechanisms, script droppers
- **Obfuscation** - Encrypted strings, dynamic class loading, custom classloaders, anti-analysis techniques
- **Exfiltration** - Discord webhooks, Telegram bots, file hosting uploads, data packaging
- **Evasion techniques** - Runtime string building, reflection call chains, network polling loops
- **Cross-class attack chains** - Correlates detections across the entire JAR to identify coordinated attacks

## Features

- **70+ detection rules** across RAT, Trojan, and Obfuscation categories
- **Java decompiler** - Reconstructs readable pseudo-Java source from bytecode
- **Bytecode disassembler** - Full JVM instruction display with suspicious line highlighting
- **Intelligence extraction** - Finds URLs, webhooks, C2 servers, commands, and IP addresses embedded in code
- **JAR metadata viewer** - MANIFEST.MF parsing, Minecraft plugin/mod info (Bukkit, Fabric, Forge)
- **Mod comparison** - Side-by-side diff of two JAR files (classes, detections, file entries)
- **Code search (Ctrl+F)** - Search within decompiled source and bytecode views
- **Export** - Copy scan reports to clipboard or save as JSON
- **Drag & drop** - Drop JARs directly onto the window to scan
- **Batch scanning** - Scan entire folders of mods at once
- **Auto-updates** - Checks for new versions automatically

## Screenshot
- **Result Screen**
![Scanned/Result Screen](/Screenshots/Results.png?raw=true "Result")
- **Detection Details**
![Detection Details](/Screenshots/DetectionDetails.png?raw=true "DetectionDetails")
- **Code Viewer**
![Code Viewer](/Screenshots/CodeViewer.png?raw=true "CodeViewer")


## Download

Check the [Releases](../../releases) page for the latest build.

**Requirements:** Windows 10/11 (64-bit)

> **Note:** Windows SmartScreen may show a "Windows protected your PC" warning when you first run IHP. This happens because the exe is not code-signed (signing certificates cost money lol). Click **More info** → **Run anyway** to continue. The source code is fully available here if you want to verify it yourself.

## How To Use

1. Download `IHP.exe` from Releases
2. Run the app (no install needed)
3. Drop your `.jar` files onto the window, or click "Select JAR File(s)" / "Select Folder"
4. Click **SCAN**
5. Review results - click any file to see detailed detections
6. Click **View Code** to inspect decompiled source, bytecode, and extracted intelligence

## Threat Levels

| Level | Score | Meaning |
|-------|-------|---------|
| CLEAN | 0-4 | No significant threats found |
| SUSPICIOUS | 5-14 | Some concerning behaviors detected |
| MALICIOUS | 15+ | High confidence this file is harmful |

## Known Malware Families Detected

- **Fractureiser** - CurseForge/Bukkit supply chain attack (stages 0-3)
- **Skyrage** - Minecraft-targeting RAT
- **Stargazers** - Multi-stage stealer campaign
- **zEus** - Info stealer targeting gaming platforms
- Various Discord token stealers, crypto wallet drainers, and session hijackers

## Built With

- **C++17** - Core language
- **[Dear ImGui](https://github.com/ocornut/imgui)** - Immediate mode GUI framework
- **[miniz](https://github.com/richgel999/miniz)** - ZIP/JAR archive extraction
- **[nlohmann/json](https://github.com/nlohmann/json)** - JSON parsing (for signature database)
- **DirectX 11** - GPU rendering backend
- **Win32 API** - Window management, file dialogs, clipboard, hashing (BCrypt)

## Inspiration & References

- **[Fractureiser investigation](https://github.com/fractureiser-investigation/fractureiser)** - The CurseForge malware incident that showed why Minecraft needs better mod scanning
- **[MCsniperPY](https://github.com/MCsniperPY)** - Minecraft security community
- **JD-GUI / CFR / Fernflower / Procyon** - Java decompiler projects that informed the bytecode analysis approach
- **VirusTotal / YARA** - Signature-based detection concepts

## Disclaimer

IHP is a static analysis tool. It cannot detect all malware, especially highly obfuscated or polymorphic threats. Always download mods from trusted sources (Modrinth, CurseForge) and keep your antivirus software active. This tool is meant to supplement, not replace, standard security practices.

![IHPLOGO](/Screenshots/IHP.png?raw=true "IHP")

## License

This project is licensed under the [MIT License](LICENSE).


