#include "trojan_detector.h"
#include "../../utils/string_utils.h"

namespace ihp {

std::vector<Detection> TrojanDetector::scan_class(const ClassInfo& cls, const std::string& filename) {
    std::vector<Detection> detections;

    // Helper lambda
    auto has_class = [&](const std::string& ref) {
        for (const auto& cr : cls.class_references)
            if (contains(cr, ref)) return true;
        return false;
    };
    auto has_method = [&](const std::string& cls_name, const std::string& meth) {
        for (const auto& mr : cls.method_references)
            if (contains(mr.class_name, cls_name) && contains(mr.method_name, meth)) return true;
        return false;
    };
    auto has_string = [&](const std::string& substr) {
        for (const auto& s : cls.string_literals)
            if (contains(to_lower(s), to_lower(substr))) return true;
        return false;
    };
    // Returns the matching string literal or "" if not found
    auto find_string = [&](const std::string& substr) -> std::string {
        for (const auto& s : cls.string_literals)
            if (contains(to_lower(s), to_lower(substr))) return s;
        return "";
    };

    // --- self-replication & mod infection ---

    // Rule 1: Writing to other .jar files (self-replication / fractureiser-style)
    {
        bool writes_jar = false;
        for (const auto& s : cls.string_literals) {
            if (ends_with(to_lower(s), ".jar")) {
                if (has_class("java/io/FileOutputStream") || has_class("java/nio/file/Files") ||
                    has_class("java/util/jar/JarOutputStream")) {
                    writes_jar = true;
                    break;
                }
            }
        }
        if (writes_jar || has_class("java/util/jar/JarOutputStream")) {
            detections.push_back({Severity::CRITICAL, "SELF_REPLICATION",
                "Writes to JAR files - potential self-replicating virus (fractureiser-style)",
                filename, "JarOutputStream or writes to .jar files"});
        }
    }

    // Rule 2: Modifying mods folder
    if (has_string("mods/") || has_string("mods\\")) {
        if (has_class("java/io/FileOutputStream") || has_class("java/nio/file/Files") ||
            has_method("java/io/File", "renameTo") || has_method("java/io/File", "delete")) {
            detections.push_back({Severity::CRITICAL, "MOD_INFECTION",
                "Modifies Minecraft mods folder - potential mod infection",
                filename, "writes/deletes in mods/ directory"});
        }
    }

    // Rule 3: Creating .bat/.ps1/.vbs files (script dropper)
    for (const auto& s : cls.string_literals) {
        std::string lower = to_lower(s);
        if ((ends_with(lower, ".bat") || ends_with(lower, ".ps1") ||
             ends_with(lower, ".vbs") || ends_with(lower, ".cmd")) &&
            (has_class("java/io/FileWriter") || has_class("java/io/FileOutputStream") ||
             has_class("java/io/PrintWriter"))) {
            detections.push_back({Severity::CRITICAL, "SCRIPT_DROPPER",
                "Creates script files (.bat/.ps1/.vbs) - drops malicious scripts",
                filename, s});
            break;
        }
    }

    // --- persistence ---

    // Rule 4: Scheduled task / startup registry (persistence)
    if (has_string("schtasks") || has_string("SchTasks") ||
        has_string("CurrentVersion\\Run") || has_string("CurrentVersion\\RunOnce") ||
        has_string("Startup") || has_string("at.exe")) {
        if (has_method("java/lang/Runtime", "exec") || has_class("java/lang/ProcessBuilder")) {
            detections.push_back({Severity::CRITICAL, "PERSISTENCE",
                "Creates scheduled tasks or startup entries - persistence mechanism",
                filename, "schtasks/registry run key"});
        }
    }

    // Rule 5: Disabling security software
    if (has_string("Windows Defender") || has_string("DisableAntiSpyware") ||
        has_string("Set-MpPreference") || has_string("netsh advfirewall") ||
        has_string("DisableRealtimeMonitoring")) {
        detections.push_back({Severity::CRITICAL, "SECURITY_BYPASS",
            "Attempts to disable Windows Defender or firewall",
            filename, "security software manipulation"});
    }

    // --- browser data theft ---

    // Rule 6: Chrome credential/cookie databases
    // Chrome stores data in: %LOCALAPPDATA%/Google/Chrome/User Data/Default/
    {
        bool chrome_theft = false;
        std::string evidence;
        // Exact database filenames Chrome uses
        const std::vector<std::string> chrome_db_files = {
            "Login Data",       // saved passwords (SQLite)
            "Cookies",          // session cookies (SQLite)
            "Web Data",         // autofill, credit cards (SQLite)
            "History",          // browsing history
            "Local State",      // encryption key for decrypting passwords
            "Bookmarks",        // bookmarks JSON
        };
        for (const auto& s : cls.string_literals) {
            std::string lower = to_lower(s);
            // Must reference Chrome's actual profile path + a database file
            if (contains(lower, "google") && contains(lower, "chrome") && contains(lower, "user data")) {
                for (const auto& db : chrome_db_files) {
                    if (contains(to_lower(s), to_lower(db))) {
                        chrome_theft = true;
                        evidence = s + " [targets: " + db + "]";
                        break;
                    }
                }
                if (!chrome_theft) {
                    // Even just accessing User Data\Default is suspicious
                    if (contains(lower, "default")) {
                        chrome_theft = true;
                        evidence = s + " [accesses Chrome profile directory]";
                    }
                }
            }
            if (chrome_theft) break;
        }
        if (chrome_theft) {
            detections.push_back({Severity::CRITICAL, "CHROME_DATA_THEFT",
                "Accesses Chrome browser profile data (passwords, cookies, autofill)",
                filename, evidence});
        }
    }

    // Rule 7: Firefox credential theft
    // Firefox: %APPDATA%/Mozilla/Firefox/Profiles/*.default/
    {
        bool firefox_theft = false;
        std::string evidence;
        const std::vector<std::string> firefox_db_files = {
            "logins.json",      // saved passwords
            "key4.db",          // master password key database
            "key3.db",          // legacy key database
            "cookies.sqlite",   // cookies
            "places.sqlite",    // history + bookmarks
            "formhistory.sqlite", // autofill data
            "cert9.db",         // certificates
        };
        for (const auto& s : cls.string_literals) {
            std::string lower = to_lower(s);
            if (contains(lower, "mozilla") && contains(lower, "firefox")) {
                for (const auto& db : firefox_db_files) {
                    if (contains(lower, to_lower(db))) {
                        firefox_theft = true;
                        evidence = s + " [targets: " + db + "]";
                        break;
                    }
                }
                if (!firefox_theft && contains(lower, "profiles")) {
                    firefox_theft = true;
                    evidence = s + " [accesses Firefox profiles directory]";
                }
            }
            if (firefox_theft) break;
        }
        if (firefox_theft) {
            detections.push_back({Severity::CRITICAL, "FIREFOX_DATA_THEFT",
                "Accesses Firefox browser data (passwords, cookies, history)",
                filename, evidence});
        }
    }

    // Rule 8: Edge / Brave / Opera / Vivaldi (Chromium-based browsers)
    // All use similar paths under %LOCALAPPDATA%
    {
        struct BrowserInfo { std::string name; std::string path_keyword; };
        std::vector<BrowserInfo> chromium_browsers = {
            {"Microsoft Edge",  "microsoft\\edge"},
            {"Microsoft Edge",  "microsoft/edge"},
            {"Brave",           "bravesoftware\\brave"},
            {"Brave",           "bravesoftware/brave"},
            {"Opera",           "opera software\\opera"},
            {"Opera",           "opera software/opera"},
            {"Vivaldi",         "vivaldi\\user data"},
            {"Vivaldi",         "vivaldi/user data"},
        };
        for (const auto& s : cls.string_literals) {
            std::string lower = to_lower(s);
            for (const auto& browser : chromium_browsers) {
                if (contains(lower, browser.path_keyword) &&
                    (contains(lower, "login data") || contains(lower, "cookies") ||
                     contains(lower, "web data") || contains(lower, "local state") ||
                     contains(lower, "user data") || contains(lower, "default"))) {
                    detections.push_back({Severity::CRITICAL, "BROWSER_DATA_THEFT",
                        "Accesses " + browser.name + " browser data (passwords, cookies)",
                        filename, s});
                    goto done_browser_check; // only report once
                }
            }
        }
        done_browser_check:;
    }

    // Rule 9: Browser Local Storage / IndexedDB theft
    // Chromium Local Storage: User Data/Default/Local Storage/leveldb/
    // This is where websites store tokens, session data, etc.
    {
        for (const auto& s : cls.string_literals) {
            std::string lower = to_lower(s);
            if (contains(lower, "local storage") && contains(lower, "leveldb")) {
                detections.push_back({Severity::CRITICAL, "BROWSER_LOCALSTORAGE_THEFT",
                    "Accesses browser Local Storage (LevelDB) - steals website tokens and session data",
                    filename, s});
                break;
            }
        }
    }

    // Rule 10: Browser extension data theft
    {
        for (const auto& s : cls.string_literals) {
            std::string lower = to_lower(s);
            if (contains(lower, "extensions") &&
                (contains(lower, "chrome") || contains(lower, "brave") || contains(lower, "edge")) &&
                (has_class("java/io/File") || has_class("java/nio/file"))) {
                detections.push_back({Severity::HIGH, "BROWSER_EXTENSION_THEFT",
                    "Accesses browser extension data (may target crypto wallet extensions like MetaMask)",
                    filename, s});
                break;
            }
        }
    }

    // --- application data theft ---

    // Rule 11: Discord token extraction (precise paths)
    {
        bool discord_theft = false;
        std::string evidence;
        // Discord stores tokens in Local Storage LevelDB files
        const std::vector<std::string> discord_paths = {
            "discord\\local storage",
            "discord/local storage",
            "discordcanary\\local storage",
            "discordcanary/local storage",
            "discordptb\\local storage",
            "discordptb/local storage",
            "discord\\leveldb",
            "discord/leveldb",
        };
        for (const auto& s : cls.string_literals) {
            std::string lower = to_lower(s);
            for (const auto& dp : discord_paths) {
                if (contains(lower, dp)) {
                    discord_theft = true;
                    evidence = s;
                    break;
                }
            }
            if (discord_theft) break;
        }
        // Also match the .ldb/.log file reading pattern in Discord dirs
        if (!discord_theft) {
            if (has_string("discord") && (has_string(".ldb") || has_string(".log"))) {
                if (has_class("java/io/File") || has_class("java/nio/file")) {
                    discord_theft = true;
                    evidence = "reads .ldb/.log files from Discord directory";
                }
            }
        }
        if (discord_theft) {
            detections.push_back({Severity::CRITICAL, "DISCORD_TOKEN_STEALER",
                "Accesses Discord local storage to steal authentication tokens",
                filename, evidence});
        }
    }

    // Rule 12: Discord webhook exfiltration
    for (const auto& s : cls.string_literals) {
        if (contains(s, "discord.com/api/webhooks") || contains(s, "discordapp.com/api/webhooks")) {
            detections.push_back({Severity::CRITICAL, "DISCORD_WEBHOOK_EXFIL",
                "Sends stolen data to Discord webhook (common exfiltration method)",
                filename, s});
            break;
        }
    }

    // Rule 13: Steam session theft
    {
        for (const auto& s : cls.string_literals) {
            std::string lower = to_lower(s);
            if ((contains(lower, "steam") && (contains(lower, "ssfn") || contains(lower, "config\\config.vdf") ||
                 contains(lower, "config/config.vdf") || contains(lower, "loginusers.vdf")))) {
                detections.push_back({Severity::CRITICAL, "STEAM_SESSION_THEFT",
                    "Accesses Steam session/config files - Steam account theft",
                    filename, s});
                break;
            }
        }
    }

    // Rule 14: Telegram session theft
    {
        for (const auto& s : cls.string_literals) {
            std::string lower = to_lower(s);
            if (contains(lower, "telegram") && (contains(lower, "tdata") || contains(lower, "D877F783D5D3EF8C"))) {
                detections.push_back({Severity::CRITICAL, "TELEGRAM_SESSION_THEFT",
                    "Accesses Telegram session data (tdata) - Telegram account theft",
                    filename, s});
                break;
            }
        }
    }

    // --- cryptocurrency theft ---

    // Rule 15: Cryptocurrency wallet files (precise paths)
    {
        struct WalletInfo { std::string name; std::string path; };
        std::vector<WalletInfo> wallets = {
            {"Bitcoin Core",  "bitcoin\\wallet.dat"},
            {"Bitcoin Core",  "bitcoin/wallet.dat"},
            {"Exodus",        "exodus\\exodus.wallet"},
            {"Exodus",        "exodus/exodus.wallet"},
            {"Electrum",      "electrum\\wallets"},
            {"Electrum",      "electrum/wallets"},
            {"Atomic Wallet", "atomic\\local storage"},
            {"Atomic Wallet", "atomic/local storage"},
            {"Ethereum",      "ethereum\\keystore"},
            {"Ethereum",      "ethereum/keystore"},
            {"Monero",        "monero\\wallets"},
            {"Monero",        "monero/wallets"},
        };
        for (const auto& s : cls.string_literals) {
            std::string lower = to_lower(s);
            for (const auto& w : wallets) {
                if (contains(lower, w.path)) {
                    detections.push_back({Severity::CRITICAL, "CRYPTO_WALLET_THEFT",
                        "Accesses " + w.name + " wallet files - cryptocurrency theft",
                        filename, s});
                    goto done_wallet_check;
                }
            }
        }
        done_wallet_check:;
    }

    // Rule 16: MetaMask / browser extension wallets
    {
        // MetaMask extension ID in Chrome: nkbihfbeogaeaoehlefnkodbefgpgknn
        for (const auto& s : cls.string_literals) {
            std::string lower = to_lower(s);
            if (contains(lower, "nkbihfbeogaeaoehlefnkodbefgpgknn") || // MetaMask Chrome
                contains(lower, "ejbalbakoplchlghecdalmeeeajnimhm") || // MetaMask Edge
                contains(lower, "ibnejdfjmmkpcnlpebklmnkoeoihofec") || // TronLink
                contains(lower, "fhbohimaelbohpjbbldcngcnapndodjp"))   // BinanceChain
            {
                detections.push_back({Severity::CRITICAL, "BROWSER_WALLET_THEFT",
                    "Targets browser crypto wallet extension data (MetaMask/TronLink/Binance)",
                    filename, s});
                break;
            }
        }
    }

    // --- system data theft ---

    // Rule 17: Windows credential store / vault
    {
        if (has_string("vaultcmd") || has_string("VaultCmd") ||
            has_string("Windows\\Credentials") || has_string("windows/credentials") ||
            has_string("dpapi") || has_string("DPAPI")) {
            detections.push_back({Severity::CRITICAL, "WINDOWS_CREDENTIAL_THEFT",
                "Accesses Windows Credential Manager / DPAPI - system credential theft",
                filename, "Windows credential store access"});
        }
    }

    // Rule 18: SSH key theft
    {
        for (const auto& s : cls.string_literals) {
            std::string lower = to_lower(s);
            if ((contains(lower, ".ssh") && (contains(lower, "id_rsa") || contains(lower, "id_ed25519") ||
                 contains(lower, "id_ecdsa") || contains(lower, "known_hosts") || contains(lower, "config")))) {
                if (has_class("java/io/File") || has_class("java/nio/file")) {
                    detections.push_back({Severity::CRITICAL, "SSH_KEY_THEFT",
                        "Accesses SSH private keys (.ssh directory) - server access theft",
                        filename, s});
                    break;
                }
            }
        }
    }

    // Rule 19: File enumeration + upload (data exfiltration)
    {
        bool enumerates_files = has_method("java/io/File", "listFiles") ||
                                has_method("java/io/File", "list") ||
                                has_class("java/nio/file/DirectoryStream") ||
                                has_method("java/nio/file/Files", "walk");
        bool has_upload = has_class("java/net/HttpURLConnection") ||
                          has_class("java/net/URL") ||
                          has_class("java/net/Socket");
        if (enumerates_files && has_upload) {
            detections.push_back({Severity::HIGH, "DATA_EXFILTRATION",
                "Enumerates local files AND has network upload capability",
                filename, "File listing + network connection"});
        }
    }

    // --- composite: library usage + browser data access ---
    // A class that USES parsing/database libraries AND references
    // browser data paths is almost certainly stealing credentials.

    // Rule 20: GSON/JSON parsing + browser credential paths
    // If a class uses GSON to parse JSON AND touches browser data paths,
    // it's parsing stolen cookies/passwords/tokens
    {
        bool uses_json_parsing = has_class("com/google/gson") ||
                                 has_class("org/json/") ||
                                 has_method("", "fromJson") ||
                                 has_method("", "parseJSON") ||
                                 has_method("", "parse");
        bool touches_browser_data = false;
        std::string browser_evidence;
        for (const auto& s : cls.string_literals) {
            std::string lower = to_lower(s);
            if ((contains(lower, "cookies") || contains(lower, "login data") ||
                 contains(lower, "local state") || contains(lower, "web data") ||
                 contains(lower, "logins.json") || contains(lower, "key4.db") ||
                 contains(lower, "cookies.sqlite")) &&
                (contains(lower, "chrome") || contains(lower, "firefox") ||
                 contains(lower, "mozilla") || contains(lower, "google") ||
                 contains(lower, "brave") || contains(lower, "edge") ||
                 contains(lower, "opera") || contains(lower, "appdata") ||
                 contains(lower, "user data"))) {
                touches_browser_data = true;
                browser_evidence = s;
                break;
            }
        }
        if (uses_json_parsing && touches_browser_data) {
            detections.push_back({Severity::CRITICAL, "JSON_CREDENTIAL_PARSER",
                "Parses JSON/GSON AND accesses browser credential files - parsing stolen passwords/cookies",
                filename, "JSON library + " + browser_evidence});
        }
    }

    // Rule 21: SQLite usage + browser database paths
    // SQLite + Chrome "Login Data" or Firefox "cookies.sqlite" = reading encrypted passwords
    {
        bool uses_sqlite = has_class("java/sql/DriverManager") ||
                           has_class("java/sql/Connection") ||
                           has_class("java/sql/Statement") ||
                           has_class("java/sql/ResultSet") ||
                           has_class("org/sqlite/") ||
                           has_class("org/xerial/") ||
                           has_string("jdbc:sqlite");
        bool targets_browser_db = false;
        std::string db_evidence;
        for (const auto& s : cls.string_literals) {
            std::string lower = to_lower(s);
            // Chrome/Chromium SQLite databases
            if (contains(lower, "login data") || contains(lower, "web data") ||
                contains(lower, "cookies") || contains(lower, "history")) {
                if (contains(lower, "chrome") || contains(lower, "google") ||
                    contains(lower, "user data") || contains(lower, "default") ||
                    contains(lower, "brave") || contains(lower, "edge") ||
                    contains(lower, "opera") || contains(lower, "vivaldi")) {
                    targets_browser_db = true;
                    db_evidence = s;
                    break;
                }
            }
            // Firefox SQLite databases
            if (contains(lower, "cookies.sqlite") || contains(lower, "places.sqlite") ||
                contains(lower, "formhistory.sqlite") || contains(lower, "key4.db") ||
                contains(lower, "key3.db") || contains(lower, "logins.json")) {
                if (contains(lower, "mozilla") || contains(lower, "firefox") ||
                    contains(lower, "profiles")) {
                    targets_browser_db = true;
                    db_evidence = s;
                    break;
                }
            }
        }
        if (uses_sqlite && targets_browser_db) {
            detections.push_back({Severity::CRITICAL, "SQLITE_CREDENTIAL_THEFT",
                "Uses SQL/SQLite AND accesses browser database files - reading stored passwords and cookies",
                filename, "SQL library + " + db_evidence});
        }
    }

    // Rule 22: Crypto decryption + browser "Local State" or credential paths
    // Chrome encrypts passwords with DPAPI; stealers use javax.crypto to decrypt them
    {
        bool uses_crypto = has_class("javax/crypto/Cipher") ||
                           has_class("javax/crypto/spec/SecretKeySpec") ||
                           has_class("javax/crypto/spec/GCMParameterSpec") ||
                           has_class("javax/crypto/spec/IvParameterSpec") ||
                           has_method("javax/crypto/Cipher", "getInstance") ||
                           has_string("AES/GCM") || has_string("AES/CBC");
        bool targets_encrypted_creds = false;
        std::string crypto_evidence;
        for (const auto& s : cls.string_literals) {
            std::string lower = to_lower(s);
            // "Local State" contains Chrome's AES encryption key
            if (contains(lower, "local state") && (contains(lower, "chrome") ||
                contains(lower, "user data") || contains(lower, "google"))) {
                targets_encrypted_creds = true;
                crypto_evidence = s + " [Chrome encryption key file]";
                break;
            }
            // DPAPI decryption
            if (contains(lower, "dpapi") || contains(lower, "crypt32") ||
                contains(lower, "cryptunprotectdata")) {
                targets_encrypted_creds = true;
                crypto_evidence = s + " [Windows DPAPI decryption]";
                break;
            }
            // Encrypted cookie value (v10/v11 prefix is Chrome's encrypted cookie marker)
            if (contains(s, "v10") || contains(s, "v11")) {
                if (has_string("cookies") || has_string("Cookies") || has_string("encrypted_value")) {
                    targets_encrypted_creds = true;
                    crypto_evidence = "Chrome encrypted cookie decryption (v10/v11 prefix)";
                    break;
                }
            }
        }
        if (uses_crypto && targets_encrypted_creds) {
            detections.push_back({Severity::CRITICAL, "CRYPTO_CREDENTIAL_DECRYPT",
                "Uses encryption API AND accesses browser encryption keys - decrypting stolen passwords/cookies",
                filename, crypto_evidence});
        }
    }

    // Rule 23: Local Storage / LevelDB reading + token patterns
    // Discord/browser tokens are stored in LevelDB Local Storage files
    {
        bool reads_leveldb = has_string("leveldb") || has_string(".ldb") || has_string(".log");
        bool targets_tokens = false;
        std::string token_evidence;
        for (const auto& s : cls.string_literals) {
            std::string lower = to_lower(s);
            if (contains(lower, "local storage") &&
                (contains(lower, "discord") || contains(lower, "chrome") ||
                 contains(lower, "brave") || contains(lower, "opera") ||
                 contains(lower, "edge"))) {
                targets_tokens = true;
                token_evidence = s;
                break;
            }
        }
        // Also check for token regex patterns stealers use
        if (!targets_tokens) {
            for (const auto& s : cls.string_literals) {
                // Common Discord token regex patterns
                if (contains(s, "dQw4w9WgXcQ") || // known token regex bait
                    contains(s, "[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}") ||
                    contains(s, "mfa\\.") || contains(s, "NDc") ||
                    (contains(s, "token") && (contains(s, "discord") || contains(s, "Discord")))) {
                    targets_tokens = true;
                    token_evidence = s;
                    break;
                }
            }
        }
        if (reads_leveldb && targets_tokens) {
            detections.push_back({Severity::CRITICAL, "LEVELDB_TOKEN_THEFT",
                "Reads LevelDB files AND searches for tokens - stealing browser/Discord tokens from Local Storage",
                filename, token_evidence});
        }
    }

    // --- minecraft-specific threats ---

    // Rule 24: Minecraft config/world manipulation outside normal API
    {
        bool modifies_world = false;
        std::string world_evidence;
        for (const auto& s : cls.string_literals) {
            std::string lower = to_lower(s);
            if ((contains(lower, "saves") || contains(lower, "world")) &&
                (contains(lower, "level.dat") || contains(lower, "session.lock") ||
                 contains(lower, "playerdata") || contains(lower, "advancements"))) {
                modifies_world = true;
                world_evidence = s;
                break;
            }
        }
        if (modifies_world &&
            (has_class("java/io/FileOutputStream") || has_class("java/nio/file/Files"))) {
            detections.push_back({Severity::HIGH, "WORLD_DATA_TAMPERING",
                "Directly manipulates Minecraft world/save files outside normal API",
                filename, world_evidence});
        }
    }

    // Rule 25: Clipboard crypto address replacement (clipper/clipjacker)
    {
        bool has_clipboard = has_class("java/awt/datatransfer/Clipboard") ||
                             has_method("java/awt/Toolkit", "getSystemClipboard");
        bool has_crypto_regex = false;
        std::string crypto_evidence;
        for (const auto& s : cls.string_literals) {
            // Bitcoin address patterns (1..., 3..., bc1...)
            if (contains(s, "^[13][a-km-zA-HJ-NP-Z1-9]") || contains(s, "^bc1") ||
                // Ethereum address pattern (0x...)
                contains(s, "^0x[0-9a-fA-F]{40}") ||
                // Monero pattern
                contains(s, "^4[0-9AB]") ||
                // Litecoin
                contains(s, "^[LM3]") ||
                // Generic wallet address replacement keywords
                (contains(to_lower(s), "wallet") && contains(to_lower(s), "replace"))) {
                has_crypto_regex = true;
                crypto_evidence = s;
                break;
            }
        }
        if (has_clipboard && has_crypto_regex) {
            detections.push_back({Severity::CRITICAL, "CRYPTO_CLIPJACKER",
                "Monitors clipboard for crypto addresses and replaces them with attacker's address",
                filename, "Clipboard access + " + crypto_evidence});
        }
    }

    // Rule 26: Telegram bot API exfiltration
    for (const auto& s : cls.string_literals) {
        if (contains(s, "api.telegram.org/bot") || contains(s, "sendMessage") ||
            contains(s, "sendDocument")) {
            if (has_class("java/net/URL") || has_class("java/net/HttpURLConnection")) {
                detections.push_back({Severity::CRITICAL, "TELEGRAM_BOT_EXFIL",
                    "Sends stolen data to a Telegram bot (common exfiltration method)",
                    filename, s});
                break;
            }
        }
    }

    // Rule 27: Gofile / Anonfiles / temp file hosting for exfil
    for (const auto& s : cls.string_literals) {
        std::string lower = to_lower(s);
        if (contains(lower, "gofile.io") || contains(lower, "anonfiles.com") ||
            contains(lower, "transfer.sh") || contains(lower, "file.io") ||
            contains(lower, "0x0.st") || contains(lower, "catbox.moe")) {
            detections.push_back({Severity::CRITICAL, "FILEHOST_EXFIL",
                "References file hosting service commonly used for data exfiltration",
                filename, s});
            break;
        }
    }

    // Rule 28: Minecraft session/access token theft
    {
        bool steals_mc_session = false;
        std::string mc_evidence;
        for (const auto& s : cls.string_literals) {
            std::string lower = to_lower(s);
            // Minecraft launcher stores access tokens in launcher_profiles.json
            if (contains(lower, "launcher_profiles") || contains(lower, "launcher_accounts") ||
                contains(lower, "accesstoken") || contains(lower, "clienttoken")) {
                if (has_class("java/io/File") || has_class("java/nio/file")) {
                    steals_mc_session = true;
                    mc_evidence = s;
                    break;
                }
            }
            // Microsoft auth token theft
            if (contains(lower, "xbl_token") || contains(lower, "xsts_token") ||
                contains(lower, "minecraftservices.com") || contains(lower, "xbox.com/auth")) {
                steals_mc_session = true;
                mc_evidence = s;
                break;
            }
        }
        if (steals_mc_session) {
            detections.push_back({Severity::CRITICAL, "MC_SESSION_THEFT",
                "Steals Minecraft session/access tokens - account takeover",
                filename, mc_evidence});
        }
    }

    // Rule 29: Process listing / killing (to check for analysis tools or kill AV)
    {
        bool lists_processes = false;
        for (const auto& s : cls.string_literals) {
            std::string lower = to_lower(s);
            if (lower == "tasklist" || lower == "tasklist.exe" ||
                lower == "wmic process" || lower == "taskkill" ||
                lower == "taskkill.exe" || contains(lower, "process list")) {
                lists_processes = true;
                break;
            }
        }
        if (lists_processes && has_method("java/lang/Runtime", "exec")) {
            detections.push_back({Severity::HIGH, "PROCESS_MANIPULATION",
                "Lists or kills system processes - may target security software or detect analysis",
                filename, "tasklist/taskkill via Runtime.exec"});
        }
    }

    // Rule 30: PowerShell encoded command execution
    for (const auto& s : cls.string_literals) {
        std::string lower = to_lower(s);
        if ((contains(lower, "powershell") || contains(lower, "pwsh")) &&
            (contains(lower, "-encodedcommand") || contains(lower, "-enc ") ||
             contains(lower, "-e ") || contains(lower, "-nop") ||
             contains(lower, "-windowstyle hidden") || contains(lower, "-w hidden"))) {
            detections.push_back({Severity::CRITICAL, "POWERSHELL_HIDDEN",
                "Executes hidden or encoded PowerShell commands - evasion technique",
                filename, s});
            break;
        }
    }

    // Rule 31: Hosts file modification (redirect URLs, block security sites)
    for (const auto& s : cls.string_literals) {
        std::string lower = to_lower(s);
        if (contains(lower, "system32") && contains(lower, "drivers") &&
            contains(lower, "hosts")) {
            detections.push_back({Severity::CRITICAL, "HOSTS_FILE_MODIFY",
                "Accesses Windows hosts file - can redirect websites or block security updates",
                filename, s});
            break;
        }
    }

    // Rule 32: WMI queries (system reconnaissance)
    for (const auto& s : cls.string_literals) {
        std::string lower = to_lower(s);
        if (contains(lower, "wmic") && (contains(lower, "bios") || contains(lower, "cpu") ||
            contains(lower, "baseboard") || contains(lower, "diskdrive") ||
            contains(lower, "memorychip") || contains(lower, "csproduct"))) {
            detections.push_back({Severity::MEDIUM, "WMI_RECON",
                "Uses WMI to query hardware info - system fingerprinting/VM detection",
                filename, s});
            break;
        }
    }

    // Rule 33: Roblox cookie theft
    for (const auto& s : cls.string_literals) {
        std::string lower = to_lower(s);
        if (contains(lower, ".roblosecurity") || contains(lower, "roblox") &&
            (contains(lower, "cookie") || contains(lower, "token"))) {
            detections.push_back({Severity::CRITICAL, "ROBLOX_TOKEN_THEFT",
                "Targets Roblox authentication cookies/tokens - gaming account theft",
                filename, s});
            break;
        }
    }

    // Rule 34: Epic Games / other game platform theft
    {
        for (const auto& s : cls.string_literals) {
            std::string lower = to_lower(s);
            if ((contains(lower, "epicgames") || contains(lower, "epic games")) &&
                (contains(lower, "loginusers") || contains(lower, "remember") ||
                 contains(lower, "cookies") || contains(lower, "token"))) {
                detections.push_back({Severity::CRITICAL, "EPIC_SESSION_THEFT",
                    "Targets Epic Games session data - gaming account theft",
                    filename, s});
                break;
            }
        }
    }

    return detections;
}

std::vector<Detection> TrojanDetector::scan_jar(const JarContents& jar) {
    std::vector<Detection> detections;

    // Check manifest for suspicious main class
    if (!jar.manifest.empty()) {
        if (contains(jar.manifest, "Premain-Class") || contains(jar.manifest, "Agent-Class")) {
            detections.push_back({Severity::HIGH, "JAVA_AGENT",
                "JAR registers as a Java agent - can modify any loaded class",
                jar.jar_path, "Premain-Class or Agent-Class in manifest"});
        }
    }

    // --- suspicious bundled libraries ---
    // Minecraft mods shouldn't need to bundle certain libraries.
    // Minecraft already provides GSON, Apache commons, etc.
    // Finding these bundled inside a mod JAR is a red flag.

    // Track which suspicious packages are found
    bool has_sqlite = false;
    bool has_okhttp = false;
    bool has_apache_http = false;
    bool has_javamail = false;
    bool has_jna = false;
    bool has_gson_bundled = false;
    bool has_jsoup = false;
    bool has_webcam = false;

    for (const auto& filename : jar.all_filenames) {
        std::string lower = to_lower(filename);

        // SQLite JDBC driver bundled in a mod — used by stealers to read browser DBs
        if (starts_with(lower, "org/sqlite/") || starts_with(lower, "org/xerial/")) {
            has_sqlite = true;
        }
        // OkHttp bundled — mod has its own HTTP stack (suspicious for data exfil)
        if (starts_with(lower, "okhttp3/") || starts_with(lower, "okhttp/")) {
            has_okhttp = true;
        }
        // Apache HttpClient bundled
        if (starts_with(lower, "org/apache/http/") || starts_with(lower, "org/apache/hc/")) {
            has_apache_http = true;
        }
        // JavaMail API — why would a mod send emails?
        if (starts_with(lower, "javax/mail/") || starts_with(lower, "com/sun/mail/")) {
            has_javamail = true;
        }
        // JNA (Java Native Access) — direct native calls from a mod
        if (starts_with(lower, "com/sun/jna/")) {
            has_jna = true;
        }
        // GSON bundled inside mod (Minecraft already has it; bundling your own is suspicious)
        if (starts_with(lower, "com/google/gson/")) {
            has_gson_bundled = true;
        }
        // Jsoup HTML parser — could be used for scraping or parsing stolen data
        if (starts_with(lower, "org/jsoup/")) {
            has_jsoup = true;
        }
        // Webcam capture libraries
        if (starts_with(lower, "com/github/sarxos/webcam/") || starts_with(lower, "org/bytedeco/javacv/")) {
            has_webcam = true;
        }
    }

    if (has_sqlite) {
        detections.push_back({Severity::HIGH, "BUNDLED_SQLITE",
            "Bundles SQLite JDBC driver - commonly used by stealers to read browser databases",
            jar.jar_path, "org/sqlite/ or org/xerial/ classes found inside JAR"});
    }
    if (has_okhttp) {
        detections.push_back({Severity::MEDIUM, "BUNDLED_OKHTTP",
            "Bundles OkHttp library - mod has its own HTTP client (Minecraft already provides HTTP)",
            jar.jar_path, "okhttp3/ classes found inside JAR"});
    }
    if (has_apache_http) {
        detections.push_back({Severity::MEDIUM, "BUNDLED_APACHE_HTTP",
            "Bundles Apache HttpClient - mod has its own HTTP client (unusual for mods)",
            jar.jar_path, "org/apache/http/ classes found inside JAR"});
    }
    if (has_javamail) {
        detections.push_back({Severity::HIGH, "BUNDLED_JAVAMAIL",
            "Bundles JavaMail API - a Minecraft mod should not need to send emails",
            jar.jar_path, "javax/mail/ classes found inside JAR"});
    }
    if (has_jna) {
        detections.push_back({Severity::HIGH, "BUNDLED_JNA",
            "Bundles JNA (Java Native Access) - enables direct OS-level access from Java",
            jar.jar_path, "com/sun/jna/ classes found inside JAR"});
    }
    if (has_gson_bundled) {
        detections.push_back({Severity::LOW, "BUNDLED_GSON",
            "Bundles Google GSON library - Minecraft already includes GSON (unusual to re-bundle)",
            jar.jar_path, "com/google/gson/ classes found inside JAR"});
    }
    if (has_jsoup) {
        detections.push_back({Severity::MEDIUM, "BUNDLED_JSOUP",
            "Bundles Jsoup HTML parser - unusual for a Minecraft mod",
            jar.jar_path, "org/jsoup/ classes found inside JAR"});
    }
    if (has_webcam) {
        detections.push_back({Severity::CRITICAL, "BUNDLED_WEBCAM",
            "Bundles webcam capture library - a Minecraft mod should NEVER access your camera",
            jar.jar_path, "webcam capture library classes found inside JAR"});
    }

    return detections;
}

} // namespace ihp
