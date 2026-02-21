#include "rat_detector.h"
#include "../../utils/string_utils.h"
#include <algorithm>

namespace ihp {

bool RATDetector::has_class_ref(const ClassInfo& cls, const std::string& ref) {
    for (const auto& cr : cls.class_references) {
        if (contains(cr, ref)) return true;
    }
    return false;
}

bool RATDetector::has_method_ref(const ClassInfo& cls, const std::string& class_name, const std::string& method_name) {
    for (const auto& mr : cls.method_references) {
        if (contains(mr.class_name, class_name) && contains(mr.method_name, method_name)) return true;
    }
    return false;
}

bool RATDetector::has_string_containing(const ClassInfo& cls, const std::string& substr) {
    for (const auto& s : cls.string_literals) {
        if (contains(s, substr)) return true;
    }
    return false;
}

int RATDetector::count_class_refs(const ClassInfo& cls, const std::string& ref) {
    int count = 0;
    for (const auto& cr : cls.class_references) {
        if (contains(cr, ref)) count++;
    }
    return count;
}

std::vector<Detection> RATDetector::scan_class(const ClassInfo& cls, const std::string& filename) {
    std::vector<Detection> detections;

    // Rule 1: Socket / ServerSocket usage (network backdoor)
    if (has_class_ref(cls, "java/net/Socket") || has_class_ref(cls, "java/net/ServerSocket")) {
        detections.push_back({Severity::HIGH, "NET_SOCKET",
            "Uses raw Socket/ServerSocket - potential network backdoor",
            filename, "java/net/Socket or java/net/ServerSocket"});
    }

    // Rule 2: Runtime.exec / ProcessBuilder (command execution)
    if (has_method_ref(cls, "java/lang/Runtime", "exec") ||
        has_class_ref(cls, "java/lang/ProcessBuilder")) {
        detections.push_back({Severity::CRITICAL, "CMD_EXEC",
            "Can execute system commands - common RAT behavior",
            filename, "Runtime.exec() or ProcessBuilder"});
    }

    // Rule 3: java.awt.Robot (screen capture / input control)
    if (has_class_ref(cls, "java/awt/Robot")) {
        detections.push_back({Severity::HIGH, "SCREEN_CONTROL",
            "Uses java.awt.Robot for screen capture or input simulation",
            filename, "java/awt/Robot"});
    }

    // Rule 4: check if its connecting to sketchy domains (sorry for my english lol)
    bool has_url_conn = has_class_ref(cls, "java/net/URL") ||
                        has_class_ref(cls, "java/net/HttpURLConnection") ||
                        has_class_ref(cls, "javax/net/ssl/HttpsURLConnection");
    if (has_url_conn) {
        // Check if connecting to non-Mojang/non-Minecraft domains
        bool suspicious_url = false;
        std::string evidence;
        for (const auto& s : cls.string_literals) {
            if (looks_like_url(s)) {
                if (!contains(s, "mojang.com") && !contains(s, "minecraft.net") &&
                    !contains(s, "minecraftforge.net") && !contains(s, "fabricmc.net") &&
                    !contains(s, "curseforge.com") && !contains(s, "modrinth.com") &&
                    !contains(s, "github.com") && !contains(s, "githubusercontent.com")) {
                    suspicious_url = true;
                    evidence = s;
                    break;
                }
            }
            if (looks_like_ip(s)) {
                suspicious_url = true;
                evidence = s;
                break;
            }
        }
        if (suspicious_url) {
            detections.push_back({Severity::HIGH, "SUSPICIOUS_URL",
                "Makes HTTP connections to suspicious external host",
                filename, evidence});
        }
    }

    // Rule 5: File operations on browser/credential paths
    for (const auto& s : cls.string_literals) {
        std::string lower = to_lower(s);
        if (contains(lower, "appdata") && (contains(lower, "discord") || contains(lower, "chrome") ||
            contains(lower, "firefox") || contains(lower, "opera") || contains(lower, "brave") ||
            contains(lower, "edge"))) {
            detections.push_back({Severity::CRITICAL, "CREDENTIAL_ACCESS",
                "Accesses browser/app data directories - likely credential theft",
                filename, s});
            break;
        }
        if (contains(lower, "login data") || contains(lower, "cookies") ||
            contains(lower, "web data") || contains(lower, ".sqlite")) {
            if (has_class_ref(cls, "java/io/File") || has_class_ref(cls, "java/nio/file")) {
                detections.push_back({Severity::CRITICAL, "CREDENTIAL_THEFT",
                    "Reads browser database files (credentials/cookies)",
                    filename, s});
                break;
            }
        }
    }

    // Rule 6: Screenshot + network = exfiltration
    bool has_screenshot = has_class_ref(cls, "javax/imageio/ImageIO") || has_class_ref(cls, "java/awt/Robot");
    bool has_network = has_class_ref(cls, "java/net/Socket") || has_class_ref(cls, "java/net/URL");
    if (has_screenshot && has_network) {
        detections.push_back({Severity::CRITICAL, "SCREENSHOT_EXFIL",
            "Captures screenshots AND has network capability - screenshot exfiltration",
            filename, "javax/imageio + network API"});
    }

    // Rule 7: KeyListener (keylogger potential)
    if (has_class_ref(cls, "java/awt/event/KeyListener") ||
        has_class_ref(cls, "java/awt/event/KeyAdapter") ||
        has_method_ref(cls, "", "keyPressed") || has_method_ref(cls, "", "keyReleased")) {
        // Only suspicious if not a typical GUI mod
        if (!contains(cls.this_class, "gui") && !contains(cls.this_class, "screen") &&
            !contains(cls.this_class, "Gui") && !contains(cls.this_class, "Screen")) {
            detections.push_back({Severity::HIGH, "KEYLOGGER",
                "Implements KeyListener outside GUI context - potential keylogger",
                filename, "java/awt/event/KeyListener"});
        }
    }

    // Rule 8: Clipboard access
    if (has_class_ref(cls, "java/awt/datatransfer/Clipboard") ||
        has_class_ref(cls, "java/awt/datatransfer/StringSelection") ||
        has_method_ref(cls, "java/awt/Toolkit", "getSystemClipboard")) {
        detections.push_back({Severity::MEDIUM, "CLIPBOARD_ACCESS",
            "Accesses system clipboard - could steal copied data",
            filename, "java/awt/datatransfer/Clipboard"});
    }

    // Rule 9: Heavy reflection usage (evasion)
    int reflect_count = count_class_refs(cls, "java/lang/reflect");
    if (has_method_ref(cls, "java/lang/Class", "forName")) reflect_count += 3;
    if (has_method_ref(cls, "java/lang/reflect/Method", "invoke")) reflect_count += 3;
    if (reflect_count >= 5) {
        detections.push_back({Severity::MEDIUM, "HEAVY_REFLECTION",
            "Heavy use of Java Reflection - may be hiding malicious calls",
            filename, "java/lang/reflect (count: " + std::to_string(reflect_count) + ")"});
    }

    // Rule 10: Crypto + network = encrypted C2
    bool has_crypto = has_class_ref(cls, "javax/crypto") || has_class_ref(cls, "java/security");
    if (has_crypto && has_network) {
        detections.push_back({Severity::HIGH, "ENCRYPTED_C2",
            "Uses encryption AND network - potential encrypted C2 channel",
            filename, "javax/crypto + network API"});
    }

    // Rule 11: Windows Registry / Preferences (persistence)
    if (has_class_ref(cls, "java/util/prefs/WindowsPreferences") ||
        has_string_containing(cls, "Software\\Microsoft\\Windows\\CurrentVersion\\Run")) {
        detections.push_back({Severity::HIGH, "REGISTRY_PERSISTENCE",
            "Accesses Windows Registry - potential persistence mechanism",
            filename, "WindowsPreferences or Run key"});
    }

    // Rule 12: File writes to startup/appdata
    for (const auto& s : cls.string_literals) {
        std::string lower = to_lower(s);
        if (contains(lower, "startup") || contains(lower, "start menu") ||
            (contains(lower, "appdata") && !contains(lower, ".minecraft"))) {
            if (has_class_ref(cls, "java/io/FileOutputStream") ||
                has_class_ref(cls, "java/io/FileWriter") ||
                has_class_ref(cls, "java/nio/file/Files")) {
                detections.push_back({Severity::HIGH, "STARTUP_WRITE",
                    "Writes files to startup/AppData directories - persistence mechanism",
                    filename, s});
                break;
            }
        }
    }

    // Rule 13: Downloads and writes executable files (dropper)
    bool writes_exec = false;
    for (const auto& s : cls.string_literals) {
        std::string lower = to_lower(s);
        if (ends_with(lower, ".exe") || ends_with(lower, ".dll") ||
            ends_with(lower, ".bat") || ends_with(lower, ".ps1") ||
            ends_with(lower, ".vbs") || ends_with(lower, ".scr")) {
            writes_exec = true;
            break;
        }
    }
    if (writes_exec && has_url_conn) {
        detections.push_back({Severity::CRITICAL, "DROPPER",
            "Downloads and creates executable files - dropper behavior",
            filename, "URL connection + executable file extension"});
    }

    // Rule 14: Desktop.browse is normal for mods (wiki links, donate buttons, Discord invites)
    // Only flag if it's combined with OTHER malicious behavior (handled by composite scoring)

    // Rule 15: JNI native methods
    if (cls.has_native_methods) {
        detections.push_back({Severity::HIGH, "NATIVE_METHODS",
            "Declares native (JNI) methods - could load native malware payloads",
            filename, "native method declaration"});
    }

    // Rule 16: System property / environment info gathering (fingerprinting)
    {
        int fingerprint_count = 0;
        std::vector<std::string> fp_strings = {"os.name", "os.version", "os.arch",
            "user.name", "user.home", "user.dir", "java.version", "java.home"};
        for (const auto& s : cls.string_literals) {
            for (const auto& fp : fp_strings) {
                if (s == fp) { fingerprint_count++; break; }
            }
        }
        if (fingerprint_count >= 4) {
            detections.push_back({Severity::MEDIUM, "SYSTEM_FINGERPRINT",
                "Collects extensive system info (OS, user, Java version) - fingerprinting behavior",
                filename, std::to_string(fingerprint_count) + " system properties queried"});
        }
    }

    // Rule 17: Thread.sleep + network = beaconing pattern (checks in periodically with C2)
    if (has_method_ref(cls, "java/lang/Thread", "sleep")) {
        bool has_net = has_class_ref(cls, "java/net/Socket") ||
                       has_class_ref(cls, "java/net/URL") ||
                       has_class_ref(cls, "java/net/HttpURLConnection");
        if (has_net) {
            detections.push_back({Severity::MEDIUM, "C2_BEACONING",
                "Uses Thread.sleep with network connections - periodic C2 beaconing pattern",
                filename, "Thread.sleep() + network API"});
        }
    }

    // Rule 18: Zip/compression of data + network = data packaging for exfiltration
    {
        bool uses_zip = has_class_ref(cls, "java/util/zip/ZipOutputStream") ||
                        has_class_ref(cls, "java/util/zip/GZIPOutputStream") ||
                        has_class_ref(cls, "java/util/zip/DeflaterOutputStream");
        bool has_net = has_class_ref(cls, "java/net/Socket") ||
                       has_class_ref(cls, "java/net/URL") ||
                       has_class_ref(cls, "java/net/HttpURLConnection");
        if (uses_zip && has_net) {
            detections.push_back({Severity::HIGH, "DATA_PACKAGING",
                "Compresses data AND sends over network - data packaging for exfiltration",
                filename, "ZipOutputStream/GZIPOutputStream + network API"});
        }
    }

    // Rule 19: Microphone / audio capture
    if (has_class_ref(cls, "javax/sound/sampled/AudioSystem") ||
        has_class_ref(cls, "javax/sound/sampled/TargetDataLine") ||
        has_class_ref(cls, "javax/sound/sampled/AudioInputStream")) {
        // Minecraft mods don't need to record audio from the mic
        if (!contains(cls.this_class, "sound") && !contains(cls.this_class, "audio") &&
            !contains(cls.this_class, "Sound") && !contains(cls.this_class, "Audio")) {
            detections.push_back({Severity::HIGH, "AUDIO_CAPTURE",
                "Uses audio capture API outside audio context - potential microphone recording",
                filename, "javax/sound/sampled audio capture"});
        }
    }

    // Rule 20: DNS lookup (can be used for C2 via DNS tunneling or domain generation)
    if (has_class_ref(cls, "java/net/InetAddress") &&
        (has_method_ref(cls, "java/net/InetAddress", "getByName") ||
         has_method_ref(cls, "java/net/InetAddress", "getAllByName"))) {
        detections.push_back({Severity::LOW, "DNS_LOOKUP",
            "Performs DNS lookups - can be used for domain generation or DNS tunneling",
            filename, "InetAddress.getByName/getAllByName"});
    }

    // Rule 21: ClassLoader.defineClass / Unsafe - runtime code injection
    if (has_method_ref(cls, "java/lang/ClassLoader", "defineClass") ||
        has_class_ref(cls, "sun/misc/Unsafe") ||
        has_class_ref(cls, "jdk/internal/misc/Unsafe")) {
        detections.push_back({Severity::CRITICAL, "RUNTIME_CODE_INJECTION",
            "Uses ClassLoader.defineClass or Unsafe to inject code at runtime",
            filename, "ClassLoader.defineClass or sun.misc.Unsafe"});
    }

    // Rule 22: Accessing environment variables (may look for tokens, credentials in env)
    {
        bool reads_env = has_method_ref(cls, "java/lang/System", "getenv");
        bool suspicious_env = false;
        std::string env_evidence;
        for (const auto& s : cls.string_literals) {
            std::string lower = to_lower(s);
            if (lower == "token" || lower == "discord_token" || lower == "api_key" ||
                lower == "secret" || lower == "password" || lower == "aws_secret_access_key" ||
                lower == "github_token" || lower == "npm_token") {
                suspicious_env = true;
                env_evidence = s;
                break;
            }
        }
        if (reads_env && suspicious_env) {
            detections.push_back({Severity::HIGH, "ENV_CREDENTIAL_THEFT",
                "Reads environment variables looking for tokens/credentials",
                filename, "System.getenv() + \"" + env_evidence + "\""});
        }
    }

    // Rule 23: Minecraft-specific anti-analysis (checks for debuggers, decompilers)
    {
        bool anti_debug = false;
        for (const auto& s : cls.string_literals) {
            std::string lower = to_lower(s);
            if (contains(lower, "java.compiler") || contains(lower, "jdwp") ||
                contains(lower, "debugger") || contains(lower, "recaf") ||
                contains(lower, "bytecodeviewer") || contains(lower, "procyon") ||
                contains(lower, "cfr") || contains(lower, "fernflower") ||
                contains(lower, "jadx")) {
                anti_debug = true;
                break;
            }
        }
        if (anti_debug) {
            detections.push_back({Severity::MEDIUM, "ANTI_ANALYSIS",
                "Checks for debuggers or decompilers - anti-analysis/anti-reverse-engineering",
                filename, "Detects analysis tools (debuggers, decompilers)"});
        }
    }

    // --- instruction-level detection ---

    // Rule 24: Reflection call chain (forName → getDeclaredMethod → invoke)
    for (const auto& seq : cls.method_call_sequences) {
        int stage = 0; // 0=waiting forName, 1=got forName, 2=got getMethod, 3=got invoke
        for (const auto& call : seq.calls) {
            if (stage == 0 && call == "java/lang/Class.forName") stage = 1;
            else if (stage == 1 && (call == "java/lang/Class.getDeclaredMethod" ||
                                    call == "java/lang/Class.getMethod")) stage = 2;
            else if (stage == 2 && call == "java/lang/reflect/Method.invoke") { stage = 3; break; }
        }
        if (stage >= 3) {
            detections.push_back({Severity::HIGH, "REFLECTION_CHAIN",
                "Uses reflection chain (forName->getMethod->invoke) to call methods indirectly",
                filename, "In method: " + seq.method_name});
            break; // one detection per class is enough
        }
    }

    // Rule 25: Runtime string building → suspicious sink
    // StringBuilder.append 5+ times followed by passing result to URL, Runtime.exec, etc.
    if (cls.string_builder_chain_count > 0) {
        for (const auto& seq : cls.method_call_sequences) {
            int sb_count = 0;
            bool has_url_sink = false;
            bool has_exec_sink = false;
            bool has_classload_sink = false;

            for (const auto& call : seq.calls) {
                if (call == "java/lang/StringBuilder.append" ||
                    call == "java/lang/StringBuffer.append") {
                    sb_count++;
                }
                if (sb_count >= 5) {
                    if (call == "java/net/URL.<init>" || call == "java/net/URI.<init>" ||
                        call == "java/net/URL.openConnection")
                        has_url_sink = true;
                    if (call == "java/lang/Runtime.exec" ||
                        call == "java/lang/ProcessBuilder.<init>")
                        has_exec_sink = true;
                    if (call == "java/lang/Class.forName")
                        has_classload_sink = true;
                }
            }

            if (has_exec_sink) {
                detections.push_back({Severity::CRITICAL, "RUNTIME_STRING_CMD",
                    "Builds command string at runtime via StringBuilder then executes it",
                    filename, "In method: " + seq.method_name});
            } else if (has_url_sink) {
                detections.push_back({Severity::HIGH, "RUNTIME_STRING_URL",
                    "Builds URL string at runtime via StringBuilder - evades static string scanning",
                    filename, "In method: " + seq.method_name});
            } else if (has_classload_sink) {
                detections.push_back({Severity::MEDIUM, "RUNTIME_STRING_CLASSLOAD",
                    "Builds class name at runtime via StringBuilder then loads it",
                    filename, "In method: " + seq.method_name});
            }
        }
    }

    // Rule 26: Network calls inside loops (C2 polling / beaconing)
    for (const auto& seq : cls.method_call_sequences) {
        if (!seq.has_loop) continue;
        for (const auto& call : seq.calls) {
            if (call == "java/net/URL.openConnection" ||
                call == "java/net/Socket.<init>" ||
                call == "java/net/HttpURLConnection.connect" ||
                contains(call, "java/net/URL") ||
                contains(call, "okhttp3/")) {
                detections.push_back({Severity::MEDIUM, "NETWORK_LOOP",
                    "Network calls inside a loop - potential C2 polling or beaconing behavior",
                    filename, "In method: " + seq.method_name + ", call: " + call});
                break;
            }
        }
    }

    return detections;
}

std::vector<Detection> RATDetector::scan_jar(const JarContents& jar) {
    std::vector<Detection> detections;

    // Check for suspicious non-class files in the JAR
    for (const auto& filename : jar.all_filenames) {
        std::string lower = to_lower(filename);
        if (ends_with(lower, ".dll") || ends_with(lower, ".exe") ||
            ends_with(lower, ".bat") || ends_with(lower, ".ps1") ||
            ends_with(lower, ".vbs") || ends_with(lower, ".scr")) {
            detections.push_back({Severity::CRITICAL, "EMBEDDED_EXECUTABLE",
                "JAR contains embedded executable file",
                filename, filename});
        }
        if (ends_with(lower, ".so") || ends_with(lower, ".dylib")) {
            detections.push_back({Severity::HIGH, "EMBEDDED_NATIVE_LIB",
                "JAR contains native library - may load malicious native code",
                filename, filename});
        }
    }

    return detections;
}

} // namespace ihp
