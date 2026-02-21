#pragma once
#include <string>
#include <unordered_map>

namespace ihp {

struct RuleInfo {
    std::string what_it_does;       // What the rule detects
    std::string why_its_bad;        // Why this is a security concern
    std::string how_it_works;       // Technical explanation of the detection
    std::string recommendation;     // What the user should do
};

// Returns detailed info about a detection rule by its rule_name.
// Returns nullptr if the rule is not found.
inline const RuleInfo* get_rule_info(const std::string& rule_name) {
    static const std::unordered_map<std::string, RuleInfo> info = {

        // --- RAT detector rules ---

        {"NET_SOCKET", {
            "Detects raw TCP socket usage (java.net.Socket / ServerSocket).",
            "Minecraft mods don't normally open raw network sockets. RATs use sockets to create backdoor connections to attacker-controlled servers, allowing remote command execution.",
            "Checks if the class references java/net/Socket or java/net/ServerSocket in its constant pool. These classes enable direct TCP communication.",
            "If this mod is from an untrusted source, avoid using it. Legitimate mods use Minecraft's built-in networking, not raw sockets."
        }},

        {"CMD_EXEC", {
            "Detects system command execution (Runtime.exec / ProcessBuilder).",
            "This allows the mod to run ANY program on your computer. Malware uses this to run PowerShell scripts, download more malware, disable security software, or steal data.",
            "Checks for Runtime.exec() method calls and ProcessBuilder class references. These Java APIs can spawn operating system processes with full user privileges.",
            "This is a critical finding. No legitimate Minecraft mod needs to execute system commands. Do NOT use this mod."
        }},

        {"SCREEN_CONTROL", {
            "Detects use of java.awt.Robot for screen capture or simulating mouse/keyboard input.",
            "Robot can take screenshots of your entire screen and simulate keyboard and mouse input. Attackers use this to spy on you or control your computer.",
            "Checks for java/awt/Robot in the class constant pool. This class provides methods like createScreenCapture(), mouseMove(), mousePress(), and keyPress().",
            "A Minecraft mod should never need screen capture or input simulation. This is highly suspicious."
        }},

        {"SUSPICIOUS_URL", {
            "Detects HTTP connections to external servers that are not known Minecraft services.",
            "The mod connects to a server outside the trusted Minecraft ecosystem. This could be a C2 (command & control) server used to send commands to the malware or receive stolen data.",
            "Checks URL/HttpURLConnection usage and scans string literals for URLs or IP addresses. Whitelists: mojang.com, minecraft.net, fabricmc.net, curseforge.com, modrinth.com, github.com.",
            "Check the detected URL. If it points to an unknown server, this mod may be communicating with an attacker."
        }},

        {"CREDENTIAL_ACCESS", {
            "Detects file access to browser and application data directories.",
            "The mod is reading files from directories where browsers like Chrome, Firefox, and apps like Discord store your passwords, cookies, and tokens.",
            "Scans string literals for paths containing 'AppData' combined with browser/app names (Chrome, Firefox, Discord, etc.).",
            "This is a clear indicator of data theft. The mod is trying to steal your saved passwords or session tokens."
        }},

        {"CREDENTIAL_THEFT", {
            "Detects reading of specific browser database files (Login Data, Cookies, Web Data, .sqlite).",
            "These files contain your actual saved passwords, cookies, and autofill data. The mod is directly targeting credential storage files.",
            "Looks for references to known browser database filenames combined with java.io.File or java.nio.file access. Chrome stores passwords in 'Login Data' (SQLite), Firefox in 'logins.json'.",
            "Critical theft indicator. This mod is specifically designed to steal your browser credentials. Delete it immediately."
        }},

        {"SCREENSHOT_EXFIL", {
            "Detects screenshot capture combined with network capability.",
            "The mod can capture your screen AND send images over the network. This combination means the attacker can see everything on your screen in real time.",
            "Triggers when both javax/imageio/ImageIO (or java.awt.Robot) AND network classes (Socket/URL) are found in the same class.",
            "This is surveillance malware. It captures screenshots and sends them to the attacker. Remove immediately."
        }},

        {"KEYLOGGER", {
            "Detects keyboard event listeners outside of GUI context.",
            "A KeyListener that isn't part of a GUI screen is likely capturing every keystroke you type, including passwords, chat messages, and private information.",
            "Detects java/awt/event/KeyListener or KeyAdapter usage. Excludes classes with 'gui' or 'screen' in their name (legitimate UI components).",
            "If the mod is not a GUI/screen component but listens to key events, it's likely a keylogger. Do not use this mod."
        }},

        {"CLIPBOARD_ACCESS", {
            "Detects system clipboard access.",
            "The mod can read or modify your clipboard contents. Crypto stealers replace copied wallet addresses, and data thieves read copied passwords.",
            "Checks for java/awt/datatransfer/Clipboard, StringSelection, and Toolkit.getSystemClipboard() references.",
            "Moderate risk alone, but dangerous combined with network access. Check if the mod has a legitimate reason to use the clipboard."
        }},

        {"HEAVY_REFLECTION", {
            "Detects heavy use of Java Reflection API to call methods dynamically.",
            "Reflection allows calling any Java method by name at runtime, bypassing normal access controls. Malware uses this to hide what it's actually doing from static analysis.",
            "Counts references to java/lang/reflect, Class.forName(), and Method.invoke(). Triggers when the combined count is 5 or more.",
            "Heavy reflection isn't always malicious (some frameworks use it), but in a Minecraft mod it can indicate evasion techniques. Check other findings."
        }},

        {"ENCRYPTED_C2", {
            "Detects encryption combined with network communication.",
            "The mod encrypts data before sending it over the network. While encryption is normal for HTTPS, using javax.crypto with raw sockets suggests a custom encrypted C2 channel.",
            "Triggers when both javax/crypto (or java/security) AND network classes are found in the same class.",
            "The mod may be communicating with an attacker through an encrypted channel that can't be easily monitored. Suspicious in a Minecraft mod."
        }},

        {"REGISTRY_PERSISTENCE", {
            "Detects Windows Registry access, specifically the Run key for auto-start.",
            "Adding entries to the Windows Run registry key makes programs start automatically when you log in. Malware uses this to survive reboots.",
            "Checks for WindowsPreferences class or string literals containing 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'.",
            "A Minecraft mod should never modify your Windows Registry. This is a persistence mechanism used by malware."
        }},

        {"STARTUP_WRITE", {
            "Detects file writes to Windows Startup or AppData directories.",
            "Writing files to the Startup folder or AppData (outside .minecraft) is a persistence technique. The malware ensures it runs every time you start your computer.",
            "Scans for string literals containing 'startup', 'start menu', or 'appdata' (excluding .minecraft) combined with FileOutputStream/FileWriter/Files classes.",
            "Legitimate mods only write to the .minecraft directory. Writing elsewhere is a red flag for persistence."
        }},

        {"DROPPER", {
            "Detects downloading and creating executable files.",
            "The mod downloads files from the internet AND creates executable files (.exe, .dll, .bat, .ps1). This is classic dropper behavior - downloading and running additional malware.",
            "Triggers when URL connection classes are found AND string literals end with executable extensions (.exe, .dll, .bat, .ps1, .vbs, .scr).",
            "This is critical malware behavior. The mod downloads and deploys additional malicious programs on your system. Delete immediately."
        }},

        {"NATIVE_METHODS", {
            "Detects JNI (Java Native Interface) method declarations.",
            "Native methods run compiled machine code directly on your CPU, bypassing Java's safety sandbox completely. This gives the mod the same power as a .exe file.",
            "Checks for the native method flag (0x0100) in class access_flags. JNI allows Java to call C/C++ code through shared libraries.",
            "Some mods use JNI for performance (e.g., audio/graphics). But native code from untrusted sources can do anything on your system."
        }},

        {"EMBEDDED_EXECUTABLE", {
            "Detects executable files (.exe, .dll, .bat, .ps1, .vbs, .scr) embedded inside the JAR.",
            "A Minecraft mod JAR should only contain .class files, resources, and configs. Having executables inside means the mod will extract and run programs on your system.",
            "Scans all file entries in the JAR archive for executable file extensions.",
            "This is a clear red flag. The mod is carrying a payload. Do not run this mod."
        }},

        {"EMBEDDED_NATIVE_LIB", {
            "Detects native libraries (.so, .dylib) embedded inside the JAR.",
            "Native libraries contain compiled machine code that runs outside Java's security sandbox. While some mods bundle native libs for performance, it's unusual and worth checking.",
            "Scans JAR file entries for .so (Linux) and .dylib (macOS) extensions.",
            "Check if this is a known mod that legitimately uses native code (e.g., LWJGL). Unknown mods with native libs are suspicious."
        }},

        // --- Obfuscation detector rules ---

        {"OBFUSCATED_CLASS_NAME", {
            "Detects class names that appear obfuscated (very short or random characters).",
            "While many legitimate mods use ProGuard or similar obfuscation tools to protect their code, obfuscation is also used by malware to hide its true purpose from analysis.",
            "Checks if class names are 1-2 characters long or contain long consonant clusters (5+) that don't form real words.",
            "Obfuscation alone is not malicious (most production mods are obfuscated). Only concerning when combined with other suspicious findings."
        }},

        {"OBFUSCATED_METHODS", {
            "Detects classes where most methods have very short (1-2 char) names.",
            "A high ratio of single-character method names suggests automated obfuscation. This is normal for ProGuard-processed mods but can also indicate attempts to hide malicious logic.",
            "Counts methods with names <= 2 characters (excluding <init>/<clinit>) and triggers when >70% of 5+ methods are short.",
            "Normal for obfuscated mods. Only suspicious when combined with other detection rules."
        }},

        {"BASE64_STRINGS", {
            "Detects multiple Base64-encoded strings in the class constant pool.",
            "Base64 encoding is commonly used to hide suspicious strings like URLs, commands, or encryption keys. However, it's also used legitimately for texture data, configs, etc.",
            "Identifies strings that match Base64 character set (A-Z, a-z, 0-9, +, /, =) with >95% valid characters and length >= 32 bytes. Triggers at 3+ matches.",
            "Low risk alone. Check if the mod has a legitimate reason for encoded data (resource packs, embedded configs)."
        }},

        {"ENCRYPTED_STRINGS", {
            "Detects strings with high non-printable character content (possibly XOR/encrypted data).",
            "Strings with mostly non-printable characters suggest encrypted or encoded payloads. Malware often XOR-encrypts its command strings, URLs, or API keys to avoid detection.",
            "Scans string literals for those where >33% of characters are non-printable (outside ASCII 32-126). Triggers at 3+ such strings.",
            "More suspicious than simple obfuscation. Encrypted strings are less common in legitimate mods."
        }},

        {"DYNAMIC_LOADING", {
            "Detects frequent use of Class.forName() to load classes dynamically.",
            "Class.forName() loads Java classes by name at runtime. While used by many frameworks (Forge, Fabric), excessive use can indicate a mod is trying to hide which classes it actually loads.",
            "Counts Class.forName() calls and triggers when 3 or more are found in a single class.",
            "Common in plugin systems and mod loaders. Only concerning with other suspicious findings."
        }},

        {"CUSTOM_CLASSLOADER", {
            "Detects a custom ClassLoader subclass.",
            "Custom ClassLoaders can load and execute Java bytecode from anywhere - files, network, encrypted payloads. Malware uses this to load additional code that isn't visible in the JAR.",
            "Checks if the class extends java.lang.ClassLoader, SecureClassLoader, or URLClassLoader.",
            "Some mods legitimately need custom ClassLoaders. But combined with network access, this is a strong malware indicator."
        }},

        {"LARGE_CONSTANT_POOL", {
            "Detects classes with unusually large numbers of string constants (500+).",
            "An extremely large constant pool can indicate packed or concatenated code, though it can also just be a large mod class with lots of string resources.",
            "Simply counts the number of string literals in the class constant pool and triggers above 500.",
            "Usually harmless - big mods just have lots of strings. Low priority unless combined with other findings."
        }},

        {"DYNAMIC_CLASS_CONSTRUCTION", {
            "Detects building class names with StringBuilder then loading them with Class.forName().",
            "Constructing class names dynamically makes it impossible to know which classes will be loaded just by reading the code. This is a common anti-analysis technique used by malware.",
            "Looks for StringBuilder/StringBuffer usage combined with Class.forName() or loadClass() calls in the same class.",
            "More suspicious than simple Class.forName(). The mod is deliberately hiding which classes it loads."
        }},

        // --- Trojan detector rules ---

        {"SELF_REPLICATION", {
            "Detects writing to JAR files - potential self-replicating virus.",
            "This is exactly how the fractureiser malware worked: it infected other .jar files in your mods folder, spreading to every mod. Once triggered, ALL your mods become infected.",
            "Detects JarOutputStream usage or string literals ending in '.jar' combined with FileOutputStream/Files classes.",
            "CRITICAL: This is the signature behavior of fractureiser. Quarantine this file and check all other mods for infection."
        }},

        {"MOD_INFECTION", {
            "Detects file operations targeting the Minecraft mods folder.",
            "The mod modifies, renames, or deletes files in your mods/ directory. This could be replacing legitimate mods with infected versions or deleting security mods.",
            "Looks for 'mods/' or 'mods\\' string literals combined with FileOutputStream, Files, File.renameTo(), or File.delete().",
            "A mod should never modify other mods. This is a clear sign of infection behavior."
        }},

        {"SCRIPT_DROPPER", {
            "Detects creation of script files (.bat, .ps1, .vbs, .cmd).",
            "The mod creates Windows script files that can execute system commands. These scripts often disable security, create persistence, or download additional malware.",
            "Finds string literals ending with .bat/.ps1/.vbs/.cmd combined with FileWriter/FileOutputStream/PrintWriter classes.",
            "CRITICAL: Script creation is a direct attack vector. The mod is deploying malicious scripts. Delete immediately."
        }},

        {"PERSISTENCE", {
            "Detects scheduled task creation or startup registry modification via command execution.",
            "The mod uses Runtime.exec or ProcessBuilder to run schtasks.exe or modify the Windows registry Run key, ensuring malware survives system reboots.",
            "Looks for string literals containing 'schtasks', 'CurrentVersion\\Run', or 'Startup' combined with Runtime.exec/ProcessBuilder.",
            "CRITICAL: The malware is installing itself to run permanently. Even removing the mod won't stop it - manual cleanup is required."
        }},

        {"SECURITY_BYPASS", {
            "Detects attempts to disable Windows Defender or the firewall.",
            "The mod tries to turn off your antivirus protection and firewall so other malware components can operate undetected.",
            "Scans for strings like 'Windows Defender', 'DisableAntiSpyware', 'Set-MpPreference', 'netsh advfirewall', 'DisableRealtimeMonitoring'.",
            "CRITICAL: The mod is actively disabling your security. This is a guaranteed malware indicator."
        }},

        {"CHROME_DATA_THEFT", {
            "Detects access to Chrome browser profile data (passwords, cookies, autofill).",
            "The mod targets Chrome's exact data storage paths to steal your saved passwords (Login Data), session cookies, credit card info (Web Data), and browsing history.",
            "Scans for string literals containing Chrome's profile path ('Google/Chrome/User Data/Default') combined with specific database filenames.",
            "CRITICAL: Your Chrome passwords and cookies are being stolen. Change all saved passwords immediately if you've run this mod."
        }},

        {"FIREFOX_DATA_THEFT", {
            "Detects access to Firefox browser data (passwords, cookies, history).",
            "Targets Firefox profile files to steal encrypted passwords (logins.json), key database (key4.db), cookies, and browsing history.",
            "Scans for paths containing 'Mozilla/Firefox' combined with known database filenames (logins.json, key4.db, cookies.sqlite, etc.).",
            "CRITICAL: Firefox data is being targeted. Change passwords and clear sessions if you've used this mod."
        }},

        {"BROWSER_DATA_THEFT", {
            "Detects access to Chromium-based browser data (Edge, Brave, Opera, Vivaldi).",
            "Targets browser data directories for browsers built on Chromium. These browsers store passwords and cookies in the same format as Chrome.",
            "Checks for browser-specific path keywords (microsoft/edge, bravesoftware, opera software, vivaldi) combined with data file references.",
            "CRITICAL: Multiple browsers are being targeted. Change passwords for any browser installed on your system."
        }},

        {"BROWSER_LOCALSTORAGE_THEFT", {
            "Detects access to browser Local Storage (LevelDB) files.",
            "Browser Local Storage contains website tokens, session data, and authentication information. Stealers read these LevelDB files to hijack your logged-in sessions.",
            "Looks for 'local storage' + 'leveldb' in string literals, which is the exact path where Chromium stores Local Storage data.",
            "CRITICAL: Session tokens are being stolen. Log out and back into important websites to invalidate stolen tokens."
        }},

        {"BROWSER_EXTENSION_THEFT", {
            "Detects access to browser extension data directories.",
            "Targets browser extension storage, particularly crypto wallet extensions like MetaMask that store private keys and wallet data in the browser.",
            "Scans for 'extensions' combined with browser names (Chrome, Brave, Edge) and file access classes.",
            "If you use browser-based crypto wallets, transfer your assets to a different wallet immediately."
        }},

        {"DISCORD_TOKEN_STEALER", {
            "Detects access to Discord local storage to steal authentication tokens.",
            "Discord stores your authentication token in LevelDB files. With your token, an attacker can fully access your Discord account - send messages, join servers, and steal personal data.",
            "Checks for Discord-specific paths (discord/local storage, discord/leveldb) and .ldb/.log file access patterns.",
            "CRITICAL: Your Discord token may be compromised. Change your Discord password (this invalidates the old token)."
        }},

        {"DISCORD_WEBHOOK_EXFIL", {
            "Detects Discord webhook URLs used to exfiltrate stolen data.",
            "Discord webhooks allow posting messages to a channel via URL. Malware sends your stolen passwords, tokens, and system info to an attacker's private Discord channel.",
            "Scans string literals for 'discord.com/api/webhooks' or 'discordapp.com/api/webhooks'.",
            "CRITICAL: The webhook URL reveals where stolen data is being sent. The mod is actively exfiltrating data."
        }},

        {"STEAM_SESSION_THEFT", {
            "Detects access to Steam session and configuration files.",
            "Targets Steam files like SSFN (session tokens), config.vdf (settings), and loginusers.vdf (account info). With these, an attacker can hijack your Steam account.",
            "Checks for 'steam' combined with known file names: ssfn, config.vdf, loginusers.vdf.",
            "Change your Steam password and enable Steam Guard. Deauthorize all devices from Steam settings."
        }},

        {"TELEGRAM_SESSION_THEFT", {
            "Detects access to Telegram session data (tdata folder).",
            "Telegram stores session data in the 'tdata' folder. Stealing these files allows an attacker to clone your Telegram session and read all your messages.",
            "Scans for 'telegram' combined with 'tdata' or Telegram's internal folder hash 'D877F783D5D3EF8C'.",
            "CRITICAL: Terminate all other Telegram sessions from Settings > Devices. Enable 2FA if not already set."
        }},

        {"CRYPTO_WALLET_THEFT", {
            "Detects access to cryptocurrency wallet files.",
            "Targets wallet files for Bitcoin Core (wallet.dat), Exodus, Electrum, Atomic Wallet, Ethereum (keystore), and Monero. Stealing wallet files gives access to your crypto funds.",
            "Checks for known wallet paths: bitcoin/wallet.dat, exodus/exodus.wallet, electrum/wallets, ethereum/keystore, etc.",
            "CRITICAL: If you've run this mod, transfer all crypto assets to new wallets immediately. Old wallets may be compromised."
        }},

        {"BROWSER_WALLET_THEFT", {
            "Detects targeting of browser-based crypto wallet extensions (MetaMask, TronLink, Binance).",
            "The mod targets specific browser extension IDs for popular crypto wallets. It reads extension storage to steal private keys and seed phrases.",
            "Matches known extension IDs: MetaMask Chrome (nkbihfbeog...), MetaMask Edge (ejbalbako...), TronLink (ibnejdfjmm...), BinanceChain (fhbohimaelb...).",
            "CRITICAL: Move all crypto assets from targeted wallets to new wallets on a clean device."
        }},

        {"WINDOWS_CREDENTIAL_THEFT", {
            "Detects access to Windows Credential Manager and DPAPI.",
            "Windows stores credentials (WiFi passwords, website logins, RDP credentials) in the Credential Manager, encrypted with DPAPI. This mod attempts to access or decrypt them.",
            "Scans for 'vaultcmd', 'Windows\\Credentials', 'dpapi', 'DPAPI', or 'CryptUnprotectData' strings.",
            "CRITICAL: System-level credentials are being targeted. All Windows-saved credentials may be compromised."
        }},

        {"SSH_KEY_THEFT", {
            "Detects access to SSH private key files.",
            "SSH keys provide passwordless access to servers. Stealing private keys (id_rsa, id_ed25519) gives the attacker access to any server that trusts those keys.",
            "Looks for '.ssh' path combined with key filenames (id_rsa, id_ed25519, id_ecdsa, known_hosts, config) and file access classes.",
            "CRITICAL: Regenerate all SSH keys and update authorized_keys on all servers you have access to."
        }},

        {"DATA_EXFILTRATION", {
            "Detects file enumeration combined with network upload capability.",
            "The mod lists files on your system AND has the ability to upload data over the network. This pattern indicates bulk data theft - scanning your files and sending interesting ones to an attacker.",
            "Triggers when file listing methods (File.listFiles, Files.walk, DirectoryStream) are found with HTTP/Socket network classes.",
            "The mod can browse and upload your files. Any sensitive documents on your system may be at risk."
        }},

        {"JAVA_AGENT", {
            "Detects Java Agent registration in the JAR manifest.",
            "A Java Agent can intercept and modify ANY class loaded by the JVM. This gives it total control - it can patch Minecraft, inject code into other mods, or intercept method calls.",
            "Checks the MANIFEST.MF for 'Premain-Class' or 'Agent-Class' attributes, which register the JAR as a Java instrumentation agent.",
            "Java Agents have legitimate uses (profiling, debugging), but a Minecraft mod registering as an agent is very suspicious."
        }},

        // --- Bundled library rules ---

        {"BUNDLED_SQLITE", {
            "Detects SQLite JDBC driver bundled inside the mod JAR.",
            "Minecraft mods don't need their own SQLite driver. Stealers bundle it to read browser password databases (Chrome's 'Login Data', Firefox's 'cookies.sqlite').",
            "Scans JAR file entries for org/sqlite/ or org/xerial/ package paths, which are the standard Java SQLite drivers.",
            "Highly suspicious when combined with browser path detections. The mod can directly query your password databases."
        }},

        {"BUNDLED_OKHTTP", {
            "Detects OkHttp HTTP client library bundled inside the mod JAR.",
            "Minecraft already provides HTTP capabilities. Bundling a separate HTTP client suggests the mod needs to make network requests outside of Minecraft's framework - often for data exfiltration.",
            "Scans JAR file entries for okhttp3/ or okhttp/ package paths.",
            "Moderately suspicious. Check if the mod has a legitimate reason to make HTTP requests (update checking, API integration)."
        }},

        {"BUNDLED_APACHE_HTTP", {
            "Detects Apache HttpClient library bundled inside the mod JAR.",
            "Similar to OkHttp - the mod bundles its own HTTP client. Minecraft/Forge already provide HTTP capabilities.",
            "Scans JAR file entries for org/apache/http/ or org/apache/hc/ package paths.",
            "Moderately suspicious. Older mods sometimes legitimately use Apache HttpClient."
        }},

        {"BUNDLED_JAVAMAIL", {
            "Detects JavaMail API bundled inside the mod JAR.",
            "A Minecraft mod should never need to send emails. JavaMail is used by malware to email stolen credentials to the attacker.",
            "Scans JAR file entries for javax/mail/ or com/sun/mail/ package paths.",
            "Highly suspicious. There is no legitimate reason for a Minecraft mod to include email functionality."
        }},

        {"BUNDLED_JNA", {
            "Detects JNA (Java Native Access) library bundled inside the mod JAR.",
            "JNA allows Java code to call OS functions directly - reading memory, accessing the Windows API, injecting into processes. It bypasses Java's security sandbox.",
            "Scans JAR file entries for com/sun/jna/ package paths.",
            "Highly suspicious. JNA gives the mod native-level access to your operating system."
        }},

        {"BUNDLED_GSON", {
            "Detects Google GSON library bundled inside the mod JAR.",
            "Minecraft already includes GSON for JSON parsing. Re-bundling it is unusual but not always malicious - some mods target multiple versions and include their own copy.",
            "Scans JAR file entries for com/google/gson/ package paths.",
            "Low risk alone. Only concerning when combined with browser data theft or network exfiltration detections."
        }},

        {"BUNDLED_JSOUP", {
            "Detects Jsoup HTML parser library bundled inside the mod JAR.",
            "Jsoup parses HTML documents. While it could be used for update checking, malware uses it to parse web pages containing stolen data or to scrape websites.",
            "Scans JAR file entries for org/jsoup/ package paths.",
            "Moderately suspicious. Check what the mod claims to do - HTML parsing is unusual for a game mod."
        }},

        {"BUNDLED_WEBCAM", {
            "Detects webcam capture library bundled inside the mod JAR.",
            "A Minecraft mod should NEVER access your camera. This library allows capturing photos and video from your webcam without your knowledge.",
            "Scans JAR file entries for com/github/sarxos/webcam/ or org/bytedeco/javacv/ package paths.",
            "CRITICAL: This is not a Minecraft mod - it's surveillance malware. Delete immediately and check if your webcam was accessed."
        }},

        // --- Composite rules ---

        {"JSON_CREDENTIAL_PARSER", {
            "Detects JSON parsing library usage combined with browser credential file access.",
            "The mod uses GSON or org.json to parse JSON AND accesses browser data files. This combination means it's parsing stolen browser data (Chrome's Local State, Firefox's logins.json).",
            "Triggers when JSON parsing classes (com/google/gson, org/json, fromJson method) are found alongside browser-specific path strings (cookies, login data, local state).",
            "CRITICAL: This is purpose-built credential parsing code. The mod is specifically designed to extract and process your stolen browser data."
        }},

        {"SQLITE_CREDENTIAL_THEFT", {
            "Detects SQL/SQLite usage combined with browser database file paths.",
            "The mod uses SQLite to directly query browser password databases. Chrome stores passwords in 'Login Data' and Firefox in 'cookies.sqlite' - both are SQLite databases.",
            "Triggers when SQL/SQLite classes (java.sql.*, org/sqlite/, jdbc:sqlite) are found alongside browser database filenames (Login Data, cookies.sqlite, etc.).",
            "CRITICAL: The mod is running SQL queries against your browser's password database. All saved passwords should be considered compromised."
        }},

        {"CRYPTO_CREDENTIAL_DECRYPT", {
            "Detects encryption APIs combined with browser encryption key access.",
            "Chrome encrypts saved passwords with AES-GCM using a key stored in 'Local State', which is itself encrypted with Windows DPAPI. This mod uses javax.crypto to decrypt your passwords.",
            "Triggers when javax/crypto/Cipher, SecretKeySpec, or GCMParameterSpec are found alongside Chrome 'Local State' paths or DPAPI/CryptUnprotectData references.",
            "CRITICAL: The mod implements the exact password decryption chain used by Chrome stealers. Your browser passwords are being decrypted and stolen."
        }},

        {"LEVELDB_TOKEN_THEFT", {
            "Detects LevelDB file reading combined with token extraction patterns.",
            "Discord and browser tokens are stored in LevelDB Local Storage files. The mod reads these files and uses regex patterns to extract authentication tokens.",
            "Triggers when LevelDB-related strings (leveldb, .ldb) are found alongside Discord/browser Local Storage paths or known token regex patterns.",
            "CRITICAL: The mod extracts tokens from Local Storage to hijack your Discord and browser sessions."
        }},

        // --- Signature DB rules ---

        {"KNOWN_MALWARE_HASH", {
            "This file's SHA-256 hash matches a known malware sample in the signature database.",
            "The exact file has been previously identified and cataloged as malware. This is a 100% positive identification - there is no ambiguity.",
            "Computes the SHA-256 hash of the entire JAR file and checks it against a database of known malicious hashes.",
            "CRITICAL: This is confirmed malware. Delete it immediately, scan all other mods, and check your system for signs of compromise."
        }},

        {"INVALID_JAR", {
            "The file could not be read as a valid JAR/ZIP archive.",
            "The file may be corrupted, not actually a JAR file, or use an unsupported compression method.",
            "Attempts to open the file as a ZIP archive using miniz. If extraction fails, this detection is created.",
            "Try re-downloading the file. If it still fails, it may not be a valid JAR file."
        }},

        // --- Additional RAT rules ---

        {"SYSTEM_FINGERPRINT", {
            "Detects collection of system information (OS name, version, username, etc.).",
            "The mod queries multiple system properties to build a profile of your computer. Malware uses this for victim identification, VM/sandbox detection, and reconnaissance.",
            "Counts System.getProperty() calls for os.name, os.version, os.arch, user.name, user.home, user.dir, java.version, java.home. Triggers when 4+ are queried.",
            "Moderate risk. Some mods legitimately check OS for compatibility, but querying 4+ properties suggests profiling."
        }},

        {"C2_BEACONING", {
            "Detects Thread.sleep combined with network connections - periodic check-in pattern.",
            "RATs and botnets use periodic sleep+connect cycles to 'beacon' back to a C2 server. The malware sleeps for a while, wakes up, contacts the attacker, gets commands, executes them, then sleeps again.",
            "Triggers when Thread.sleep() is found in the same class as Socket, URL, or HttpURLConnection references.",
            "Suspicious pattern. Legitimate mods rarely need to combine sleep with network calls in the same class."
        }},

        {"DATA_PACKAGING", {
            "Detects data compression combined with network upload capability.",
            "The mod compresses data into ZIP/GZIP format AND sends it over the network. This is a common data exfiltration pattern - stolen files are compressed then uploaded.",
            "Triggers when ZipOutputStream, GZIPOutputStream, or DeflaterOutputStream are found with network classes (Socket, URL, HttpURLConnection).",
            "High risk. A Minecraft mod should not need to compress and upload arbitrary data."
        }},

        {"AUDIO_CAPTURE", {
            "Detects audio recording API usage outside of audio/sound classes.",
            "The mod uses Java's audio capture API (microphone input) in a class that isn't a sound-related component. This indicates covert microphone recording.",
            "Checks for javax/sound/sampled/AudioSystem, TargetDataLine, and AudioInputStream. Excludes classes with 'sound' or 'audio' in their name.",
            "A Minecraft mod should never record from your microphone. This is surveillance functionality."
        }},

        {"DNS_LOOKUP", {
            "Detects direct DNS lookups via InetAddress.",
            "While DNS lookups can be innocent, malware uses them for domain generation algorithms (DGA), DNS tunneling (hiding data in DNS queries), or checking if a C2 domain is active.",
            "Checks for InetAddress.getByName() or getAllByName() method references.",
            "Low risk alone. Only concerning when combined with other network-related findings."
        }},

        {"RUNTIME_CODE_INJECTION", {
            "Detects ClassLoader.defineClass or sun.misc.Unsafe usage for runtime code injection.",
            "defineClass can load arbitrary bytecode at runtime, and Unsafe provides direct memory access bypassing all Java safety. Both allow executing code that isn't visible in the JAR file.",
            "Checks for ClassLoader.defineClass() method calls and sun/misc/Unsafe or jdk/internal/misc/Unsafe class references.",
            "CRITICAL: The mod can execute arbitrary code that isn't visible to static analysis. This is a serious evasion technique."
        }},

        {"ENV_CREDENTIAL_THEFT", {
            "Detects reading environment variables looking for tokens and credentials.",
            "Developers often store API tokens, database passwords, and secret keys in environment variables. This mod reads System.getenv() and searches for sensitive variable names.",
            "Triggers when System.getenv() is combined with string literals like 'token', 'discord_token', 'api_key', 'secret', 'password', etc.",
            "The mod is harvesting credentials from your environment variables. Check what sensitive data you have stored in env vars."
        }},

        {"ANTI_ANALYSIS", {
            "Detects checks for debuggers, decompilers, and analysis tools.",
            "The mod checks if it's being analyzed by looking for debugging flags (JDWP), common decompilers (Recaf, Bytecode Viewer, CFR, Fernflower, JADX, Procyon), or the Java compiler.",
            "Scans string literals for known analysis tool names and debugging-related terms.",
            "Legitimate mods don't need to detect decompilers. This is anti-reverse-engineering behavior typical of malware."
        }},

        // --- Additional Trojan rules ---

        {"WORLD_DATA_TAMPERING", {
            "Detects direct manipulation of Minecraft world/save files.",
            "The mod directly accesses level.dat, session.lock, playerdata, or advancements files using raw file I/O instead of Minecraft's API. This could corrupt worlds or inject malicious data.",
            "Looks for save-related path strings (saves/, world/, level.dat, playerdata) combined with FileOutputStream or Files classes.",
            "Legitimate mods use Minecraft's API for world data. Direct file access suggests tampering or data corruption intent."
        }},

        {"CRYPTO_CLIPJACKER", {
            "Detects clipboard monitoring for cryptocurrency address replacement.",
            "A clipjacker watches your clipboard for crypto wallet addresses and silently replaces them with the attacker's address. When you paste to send crypto, it goes to the attacker instead.",
            "Triggers when clipboard access is combined with crypto address regex patterns (Bitcoin ^1/^3/^bc1, Ethereum ^0x, etc.) or wallet replacement keywords.",
            "CRITICAL: If you've used this mod while sending crypto, verify all recent transaction destinations immediately."
        }},

        {"TELEGRAM_BOT_EXFIL", {
            "Detects Telegram Bot API usage for data exfiltration.",
            "The mod sends stolen data to a Telegram bot via the Bot API (api.telegram.org/bot). This is an increasingly common exfiltration method - harder to block than Discord webhooks.",
            "Scans for 'api.telegram.org/bot', 'sendMessage', or 'sendDocument' combined with HTTP connection classes.",
            "CRITICAL: Your data is being sent to the attacker's Telegram bot. The bot token in the string can identify the attacker."
        }},

        {"FILEHOST_EXFIL", {
            "Detects references to anonymous file hosting services used for data exfiltration.",
            "The mod uploads stolen data to anonymous file hosting services (gofile.io, anonfiles.com, transfer.sh, file.io, 0x0.st, catbox.moe). These services allow anonymous uploads.",
            "Scans string literals for known anonymous file hosting domains.",
            "CRITICAL: The mod uploads your data to public file hosting. The attacker downloads it anonymously."
        }},

        {"MC_SESSION_THEFT", {
            "Detects theft of Minecraft session and access tokens.",
            "Targets Minecraft launcher files (launcher_profiles.json, launcher_accounts.json) and Microsoft/Xbox authentication tokens. With these, an attacker can hijack your Minecraft account.",
            "Checks for launcher file references, access/client token strings, and Microsoft/Xbox auth endpoints combined with file access classes.",
            "CRITICAL: Change your Microsoft account password and re-authenticate the Minecraft launcher. Enable 2FA on your Microsoft account."
        }},

        {"PROCESS_MANIPULATION", {
            "Detects system process listing or killing via command execution.",
            "The mod runs tasklist.exe or taskkill.exe to enumerate or terminate processes. Malware uses this to kill antivirus, detect analysis tools, or check for running applications.",
            "Looks for 'tasklist', 'taskkill', or 'wmic process' strings combined with Runtime.exec().",
            "The mod is interacting with system processes. This is not normal Minecraft mod behavior."
        }},

        {"POWERSHELL_HIDDEN", {
            "Detects hidden or encoded PowerShell command execution.",
            "The mod runs PowerShell with flags to hide the window (-WindowStyle Hidden) or encode commands (-EncodedCommand). This is a classic evasion technique to run malicious scripts invisibly.",
            "Scans for 'powershell' or 'pwsh' combined with flags like -EncodedCommand, -enc, -nop, -WindowStyle Hidden, -w hidden.",
            "CRITICAL: Hidden/encoded PowerShell is a guaranteed malware indicator. The encoded command likely downloads or executes additional malware."
        }},

        {"HOSTS_FILE_MODIFY", {
            "Detects access to the Windows hosts file.",
            "The hosts file (System32/drivers/etc/hosts) maps domain names to IP addresses. Malware modifies it to redirect security update sites, banking websites, or other services to attacker-controlled servers.",
            "Checks for string literals containing 'system32', 'drivers', and 'hosts' together.",
            "CRITICAL: Hosts file modification can redirect your web traffic. Check your hosts file for unauthorized entries."
        }},

        {"WMI_RECON", {
            "Detects WMI hardware queries for system fingerprinting.",
            "The mod uses WMIC to query hardware details (BIOS, CPU, motherboard, disks, RAM). Malware uses this to fingerprint systems, detect virtual machines, and uniquely identify victims.",
            "Scans for 'wmic' combined with hardware categories (bios, cpu, baseboard, diskdrive, memorychip, csproduct).",
            "System fingerprinting is suspicious. The mod is gathering detailed hardware information about your computer."
        }},

        {"ROBLOX_TOKEN_THEFT", {
            "Detects theft of Roblox authentication cookies.",
            "Targets the .ROBLOSECURITY cookie which provides full access to a Roblox account. Many Minecraft malware variants also steal gaming credentials from other platforms.",
            "Scans for '.ROBLOSECURITY' or 'roblox' combined with 'cookie' or 'token' in string literals.",
            "CRITICAL: If you play Roblox and ran this mod, change your Roblox password immediately and enable 2FA."
        }},

        {"EPIC_SESSION_THEFT", {
            "Detects theft of Epic Games session data.",
            "Targets Epic Games launcher files to steal session tokens. With these, an attacker can access your Epic Games account and any linked payment methods.",
            "Checks for 'epicgames' or 'epic games' combined with session-related keywords (loginusers, remember, cookies, token).",
            "Change your Epic Games password and enable 2FA. Check for unauthorized purchases."
        }},

        // --- More signature rules ---

        {"KNOWN_MALWARE_URL", {
            "A string matches a known malware payload or C2 communication URL.",
            "The mod references an exact URL that has been identified in previous malware campaigns (fractureiser, Skyrage, Stargazers). These URLs serve payloads, receive stolen data, or relay C2 commands.",
            "Checks all string literals against a database of known malicious URLs collected from analyzed malware samples.",
            "CRITICAL: This is a direct link to malware infrastructure. Delete the mod immediately and check your system for compromise."
        }},

        {"WEBHOOK_EXFILTRATION", {
            "The mod contains a Discord webhook or Telegram bot URL pattern used for data exfiltration.",
            "Discord webhooks and Telegram bots are the #1 exfiltration method for Minecraft malware. Stolen passwords, tokens, and system info are sent to the attacker's private channel/chat.",
            "Scans string literals for 'discord.com/api/webhooks', 'discordapp.com/api/webhooks', or 'api.telegram.org/bot' patterns.",
            "CRITICAL: The mod is actively sending stolen data to the attacker. The webhook/bot URL can be reported to Discord/Telegram for takedown."
        }},

        {"EXFIL_SERVICE", {
            "The mod references an anonymous file hosting service commonly used for data exfiltration.",
            "Services like gofile.io, anonfiles.com, transfer.sh, file.io, 0x0.st, and catbox.moe allow anonymous file uploads. Malware uploads stolen data archives to these services for the attacker to retrieve.",
            "Checks string literals against a database of known anonymous file hosting domains.",
            "High risk. A Minecraft mod has no legitimate reason to upload files to anonymous hosting services."
        }},

        {"PASTE_SERVICE_C2", {
            "The mod references a paste service commonly used for malware C2 configuration.",
            "Paste services (pastebin.com, hastebin.com, paste.ee, rentry.co) are used as dead-drop C2 - the attacker posts commands or config data to a paste, and the malware reads it. This avoids running a visible C2 server.",
            "Scans string literals for known paste service raw content URLs (pastebin.com/raw, hastebin.com/raw, etc.).",
            "High risk. The mod likely reads attack configuration or download URLs from a paste service."
        }},

        {"MALWARE_SYSTEM_PROPERTY", {
            "The mod references a Java system property used by known malware.",
            "Known malware families set specific system properties as execution guards. For example, fractureiser Stage 3 sets 'neko.run' to prevent re-execution.",
            "Checks string literals for exact matches against known malware system property names.",
            "CRITICAL: This is a signature of a known malware family. The mod is confirmed malware."
        }},

        {"KNOWN_MALWARE_METHOD", {
            "The mod contains a method name from known malware (e.g., fractureiser obfuscated injection).",
            "Fractureiser's Stage 0 injected methods with specific obfuscated names into infected mods. These method names are unique fingerprints of the infection.",
            "Matches string literals against known malicious method names like '_d385bd3c36f464882460aa4f0484c53' and 'retrieveMSACredentials'.",
            "CRITICAL: The mod contains fractureiser infection signatures. It has been infected and should be deleted. Check all other mods."
        }},

        {"KNOWN_MALWARE_ARTIFACT", {
            "The JAR contains a file that is a known artifact of specific malware.",
            "Certain malware families include distinctive files: Skyrage uses 'plugin-config.bin', fractureiser drops 'hook.dll', and others use uniquely named configuration or payload files.",
            "Checks JAR file entries against a database of known malware artifact filenames.",
            "CRITICAL: The presence of a known malware artifact confirms infection. Delete this file immediately."
        }},

        {"KNOWN_MALWARE_CLASS", {
            "A class reference matches a known malicious class name in the signature database.",
            "The mod contains or references a class that is cataloged as malware (e.g., fractureiser classes, known RAT packages, known stealer packages).",
            "Compares all class references against a database of known malicious class/package names.",
            "CRITICAL: This mod contains known malware components. Delete immediately."
        }},

        {"KNOWN_C2_DOMAIN", {
            "A string in the code matches a known malware command-and-control domain.",
            "The mod references a domain that has been identified as a malware C2 server. It will attempt to communicate with this server to receive commands or exfiltrate data.",
            "Checks all string literals against a database of known C2 domains.",
            "CRITICAL: The mod communicates with a known malware server. Block this domain in your firewall and delete the mod."
        }},

        {"KNOWN_C2_IP", {
            "A string matches a known malware command-and-control IP address.",
            "The mod connects to an IP address known to be associated with malware operations.",
            "Checks all string literals against a database of known malicious IP addresses.",
            "CRITICAL: Block this IP address in your firewall and check network logs for past connections."
        }},

        {"SUSPICIOUS_FILE_IN_JAR", {
            "The JAR contains a file with a suspicious extension that shouldn't be in a Minecraft mod.",
            "Files like .exe, .dll, .bat, .ps1 have no place inside a Minecraft mod JAR. Their presence indicates the mod will extract and execute these files on your system.",
            "Checks all file entries in the JAR against a list of suspicious extensions (.exe, .dll, .bat, .cmd, .ps1, .vbs, .scr, .com, .pif, .msi, .hta, .wsf).",
            "CRITICAL: The JAR contains executable payload files. Do not run this mod."
        }},
    };

    auto it = info.find(rule_name);
    if (it != info.end()) return &it->second;
    return nullptr;
}

} // namespace ihp
