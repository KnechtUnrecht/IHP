#include "signature_db.h"
#include "../utils/string_utils.h"
#include <fstream>

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4244 4267)
#endif
#include "../../third_party/json/json.hpp"
#ifdef _MSC_VER
#pragma warning(pop)
#endif

using json = nlohmann::json;

namespace ihp {

bool SignatureDB::load(const std::string& json_path) {
    std::ifstream file(json_path);
    if (!file.is_open()) {
        return load_default();
    }

    try {
        json j;
        file >> j;

        // known_hashes can be either a flat array or categorized object
        if (j.contains("known_hashes")) {
            if (j["known_hashes"].is_array()) {
                for (const auto& h : j["known_hashes"]) {
                    db_.known_hashes.insert(to_lower(h.get<std::string>()));
                }
            } else if (j["known_hashes"].is_object()) {
                // Categorized format: { "category": ["hash1", "hash2"], ... }
                for (auto& [key, val] : j["known_hashes"].items()) {
                    if (key == "_description") continue;
                    if (val.is_array()) {
                        for (const auto& h : val) {
                            db_.known_hashes.insert(to_lower(h.get<std::string>()));
                        }
                    }
                }
            }
        }
        if (j.contains("malicious_classes")) {
            for (const auto& c : j["malicious_classes"]) {
                db_.malicious_classes.push_back(c.get<std::string>());
            }
        }
        if (j.contains("malicious_domains")) {
            for (const auto& d : j["malicious_domains"]) {
                db_.malicious_domains.push_back(to_lower(d.get<std::string>()));
            }
        }
        if (j.contains("malicious_ips")) {
            for (const auto& ip : j["malicious_ips"]) {
                db_.malicious_ips.push_back(ip.get<std::string>());
            }
        }
        if (j.contains("suspicious_extensions")) {
            for (const auto& ext : j["suspicious_extensions"]) {
                db_.suspicious_extensions.insert(to_lower(ext.get<std::string>()));
            }
        }

        // Load new signature categories
        auto load_string_vec = [&](const std::string& key, std::vector<std::string>& target) {
            if (j.contains(key)) {
                for (const auto& item : j[key]) {
                    target.push_back(item.get<std::string>());
                }
            }
        };
        load_string_vec("suspicious_urls", db_.suspicious_urls);
        load_string_vec("suspicious_webhook_patterns", db_.suspicious_webhook_patterns);
        load_string_vec("suspicious_exfil_services", db_.suspicious_exfil_services);
        load_string_vec("suspicious_paste_services", db_.suspicious_paste_services);
        load_string_vec("suspicious_file_artifacts", db_.suspicious_file_artifacts);
        load_string_vec("suspicious_system_properties", db_.suspicious_system_properties);
        load_string_vec("suspicious_method_names", db_.suspicious_method_names);

        return true;
    } catch (...) {
        return load_default();
    }
}

bool SignatureDB::load_default() {
    // Built-in default signatures for known Minecraft malware
    // Compiled from fractureiser investigation, Skyrage analysis, Stargazers campaign,
    // zEus stealer research, MCAntiMalware database, and community reports.

    // Known malicious file hashes
    db_.known_hashes = {
        // fractureiser stage 0 (infected mod)
        "1d1aaccdc13244e980c0c024610ecc77ea2674a33a52129edf1bb4ce3b2cc2fc",
        // fractureiser stage 1 (dl.jar)
        "dc43c4685c3f47808ac207d1667cc1eb915b2d82",
        // fractureiser stage 2 (lib.jar)
        "52d08736543a240b0cbbbf2da03691ae525bb119",
        "6ec85c8112c25abe4a71998eb32480d266408863",
        // fractureiser stage 3 (client.jar)
        "c2d0c87a1fe99e3c44a52c48d8bcf65a67b3e9a5",
        "e299bf5a025f5c3fff45d017c3c2f467fa599915",
        // fractureiser infected CurseForge/Bukkit mods
        "33677ca0e4c565b1f34baa74a79c09a3b690bf41",
        "2db855a7f40c015f8c9ca7cbab69e1f1aafa210b",
        "284a4449e58868036b2bafdfb5a210fd0480ef4a",
        "0c6576bdc6d1b92d581c18f3a150905ad97fa080",
        "c55c3e9d6a4355f36b0710ab189d5131a290df26",
        "32536577d5bb074abd493ad98dc12ccc86f30172",
        "a4b6385d1140c111549d95eab25cb51922eefba2",
        "b0752dcf01d56f420cb084c84b641b9c132e8a73",
        "282adb0edc52ce955932de48ef06df36e1050ada",
        "e50eadd3293e35e60e89d1914bbc67ab597c8721",
        "2de8f42871213f17771be2943e5f9da3b0a94ad2",
        // Skyrage infected sample
        "c692b3d8777f799428e82479607911804286a80ea1769b49dcd12c6472d0e57d",
        // Stargazers campaign stage 1 JARs
        "05b143fd7061bdd317bd42c373c5352bec351a44fa849ded58236013126d2963",
        "9ca41431df9445535b96a45529fce9f9a8b7f26c08ac8989a57787462da3342f",
        "c5936514e05e8b1327f0df393f4d311afd080e5467062151951e94bbd7519703",
        "9a678140ce41bdd8c02065908ee85935e8d01e2530069df42856a1d6c902bae1",
        // Stargazers campaign stage 2 JARs
        "4c8a6ad89c4218507e27ad6ef4ddadb6b507020c74691d02b986a252fb5dc612",
        "51e423e8ab1eb49691d8500983f601989286f0552f444f342245197b74bc6fcf",
        "5d80105913e42efe58f4c325ac9b7c89857cc67e1dcab9d99f865a28ef084b37",
        "97df45c790994bbe7ac1a2cf83d42791c9d832fa21b99c867f5b329e0cc63f64",
        "4c944b07832d5c29e7b499d9dd17a3d71f0fd918ab68694d110cbb8523b8af49",
        "5590eaa4f11a6ed4351bc983e47d9dfd91245b89f3108bfd8b7f86e40d00b9fa",
        // Stargazers campaign stage 3 (.NET stealer)
        "7aefd6442b09e37aa287400825f81b2ff896b9733328814fb7233978b104127f",
        "886a694ee4be77242f501b20d37395e1a8a7a8f734f460cae269eb1309c5b196",
        "a1dc479898f0798e40f63b9c1a7ee4649357abdc757c53d4a81448a5eea9169f",
        "a427eeb8eed4585f2d51b62528b8b4920e72002ab62eb6fc19289ebc2fba5660",
        "f08086257c14b1de394bf150ad8aacc99ca5de57b4baa0974bc1b59bb973d355",
    };

    // Malicious class/package names
    db_.malicious_classes = {
        // fractureiser stage 2/3 (NekoClient)
        "dev/neko/nekoclient",
        "dev/neko/nekoclient/Client",
        "dev/neko/nekoclient/api/windows/WindowsHook",
        "dev/neko/nekoclient/api/stealer/msa/impl/MSAStealer",
        "dev/neko/nekoclient/api/stealer/discord/DiscordAccount",
        "dev/neko/nekoclient/api/stealer/browser/impl/BrowserDataStealer",
        "dev/neko/nekoinjector/template/impl/BungeecordPluginTemplate",
        "dev/neko/nekoinjector/template/impl/FabricModTemplate",
        "dev/neko/nekoinjector/template/impl/ForgeModTemplate",
        "dev/neko/nekoinjector/template/impl/MinecraftClientTemplate",
        "dev/neko/nekoinjector/template/impl/SpigotPluginTemplate",
        "dev/neko/e/e/e/A",
        "dev/neko/e/e/e/C",
        "dev/neko/e/e/e/i",
        "dev/neko/e/e/e/l",
        "dev/neko/e/e/e/c",
        "dev/sirlennox/nekoclient",
        // Stargazers campaign (Baikal)
        "me/baikal/club",
        // Minegrief worm
        "net/minecraft/bundler/Backdoor",
        "com/chebuya/minegriefserver/Main",
        // Common malicious class patterns
        "Autorun",
        "net/minecraftforge/init",
        "nekoclient",
        "skyrage",
        "C2Client",
        "RemoteShell",
        "RATClient",
        "StealerMain",
        "TokenGrabber",
        "WebhookSender",
        "ForceOPExploit",
        "BackdoorPlugin",
        "ServerBackdoor",
        "OpExploit",
        // Stealer class patterns
        "stealer/main",
        "stealer/browser",
        "stealer/discord",
        "grabber/token",
        "stealer/msa",
        "stealer/steam",
        "stealer/telegram",
        "stealer/crypto",
        "stealer/wallet",
        "stealer/cookie",
        "stealer/password",
        "InfoStealer",
        "SessionStealer",
        "CookieGrabber",
        "CredentialHarvester",
        "BrowserStealer",
        "DiscordStealer",
        "MinecraftStealer",
        // Loader/installer patterns
        "NekoInstaller",
        "NekoService",
        "MixinLoader",
    };

    // C2 domains
    db_.malicious_domains = {
        // fractureiser C2
        "files-8ie.pages.dev",
        // Skyrage C2
        "skyrage.de",
        "files.skyrage.de",
        "connect.skyrage.de",
        "t23e7v6uz8idz87ehugwq.skyrage.de",
        "qw3e1ee12e9hzheu9h1912hew1sh12uw9.skyrage.de",
        // Spigot malware
        "nasapaul.com",
        // zEus stealer C2
        "onlinecontroler.000webhostapp.com",
        "panel-controller.000webhostapp.com",
    };

    // C2 IP addresses
    db_.malicious_ips = {
        // fractureiser
        "85.217.144.130",
        "107.189.3.101",
        "95.214.27.172",
        // Stargazers campaign
        "147.45.79.104",
        "185.95.159.125",
    };

    // Suspicious URLs
    db_.suspicious_urls = {
        // fractureiser payload URLs
        "85.217.144.130:8080/dl",
        "files-8ie.pages.dev/ip",
        "files-8ie.pages.dev:8083/ip",
        "t23e7v6uz8idz87ehugwq.skyrage.de/qqqqqqqqq",
        "t23e7v6uz8idz87ehugwq.skyrage.de/version",
        // Skyrage payload URLs
        "files.skyrage.de/update",
        "files.skyrage.de/mvd",
        // Stargazers campaign URLs
        "147.45.79.104/download",
        "147.45.79.104/cookies",
        "147.45.79.104/upload",
    };

    // Webhook/exfil patterns
    db_.suspicious_webhook_patterns = {
        "discord.com/api/webhooks",
        "discordapp.com/api/webhooks",
        "api.telegram.org/bot",
    };

    db_.suspicious_exfil_services = {
        "gofile.io",
        "anonfiles.com",
        "transfer.sh",
        "file.io",
        "0x0.st",
        "catbox.moe",
    };

    db_.suspicious_paste_services = {
        "pastebin.com/raw",
        "hastebin.com/raw",
        "paste.ee/r/",
        "rentry.co/raw",
    };

    // File artifacts & system properties
    db_.suspicious_file_artifacts = {
        "plugin-config.bin",
        "kernel-certs-debug4917.log",
        "hook.dll",
        "libWebGL64.jar",
        "microsoft-vm-core",
        "vmd-gnu",
    };

    db_.suspicious_system_properties = {
        "neko.run",
    };

    db_.suspicious_method_names = {
        "_d385bd3c36f464882460aa4f0484c53",
        "_f7dba6a3a72049a78a308a774a847180",
        "retrieveClipboardFiles",
        "retrieveMSACredentials",
    };

    // Suspicious file extensions
    db_.suspicious_extensions = {
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs",
        ".scr", ".com", ".pif", ".msi", ".hta", ".wsf",
        ".so", ".dylib",
    };

    return true;
}

bool SignatureDB::is_known_malware_hash(const std::string& sha256) const {
    return db_.known_hashes.count(to_lower(sha256)) > 0;
}

std::vector<Detection> SignatureDB::check_classes(const std::vector<std::string>& class_refs, const std::string& filename) const {
    std::vector<Detection> detections;

    for (const auto& cls_ref : class_refs) {
        for (const auto& known_bad : db_.malicious_classes) {
            if (contains(cls_ref, known_bad)) {
                detections.push_back({Severity::CRITICAL, "KNOWN_MALWARE_CLASS",
                    "Contains known malicious class name",
                    filename, "class: " + cls_ref + " matches: " + known_bad});
            }
        }
    }

    return detections;
}

std::vector<Detection> SignatureDB::check_strings(const std::vector<std::string>& strings, const std::string& filename) const {
    std::vector<Detection> detections;

    for (const auto& s : strings) {
        std::string lower = to_lower(s);

        // Check against malicious domains
        for (const auto& domain : db_.malicious_domains) {
            if (contains(lower, domain)) {
                detections.push_back({Severity::CRITICAL, "KNOWN_C2_DOMAIN",
                    "References known malware command-and-control domain",
                    filename, "string: " + s + " matches: " + domain});
            }
        }

        // Check against malicious IPs
        for (const auto& ip : db_.malicious_ips) {
            if (contains(s, ip)) {
                detections.push_back({Severity::CRITICAL, "KNOWN_C2_IP",
                    "References known malware command-and-control IP address",
                    filename, "string: " + s + " matches: " + ip});
            }
        }

        // Check against known malicious URLs
        for (const auto& url : db_.suspicious_urls) {
            if (contains(lower, to_lower(url))) {
                detections.push_back({Severity::CRITICAL, "KNOWN_MALWARE_URL",
                    "References known malware payload/C2 URL",
                    filename, "string: " + s + " matches: " + url});
            }
        }

        // Check against webhook exfiltration patterns
        for (const auto& pattern : db_.suspicious_webhook_patterns) {
            if (contains(lower, to_lower(pattern))) {
                detections.push_back({Severity::CRITICAL, "WEBHOOK_EXFILTRATION",
                    "Contains webhook URL pattern used for data exfiltration",
                    filename, "string: " + s + " matches: " + pattern});
            }
        }

        // Check against file hosting exfiltration services
        for (const auto& service : db_.suspicious_exfil_services) {
            if (contains(lower, service)) {
                detections.push_back({Severity::HIGH, "EXFIL_SERVICE",
                    "References file hosting service commonly used for data exfiltration",
                    filename, "string: " + s + " matches: " + service});
            }
        }

        // Check against paste services used for C2 config
        for (const auto& paste : db_.suspicious_paste_services) {
            if (contains(lower, paste)) {
                detections.push_back({Severity::HIGH, "PASTE_SERVICE_C2",
                    "References paste service commonly used for malware C2 configuration",
                    filename, "string: " + s + " matches: " + paste});
            }
        }

        // Check against known malicious system properties
        for (const auto& prop : db_.suspicious_system_properties) {
            if (s == prop) {
                detections.push_back({Severity::CRITICAL, "MALWARE_SYSTEM_PROPERTY",
                    "References system property used by known malware",
                    filename, "string: " + s + " matches: " + prop});
            }
        }

        // Check against known malicious method names (fractureiser obfuscated methods)
        for (const auto& method : db_.suspicious_method_names) {
            if (contains(s, method)) {
                detections.push_back({Severity::CRITICAL, "KNOWN_MALWARE_METHOD",
                    "Contains method name from known malware (fractureiser obfuscated injection)",
                    filename, "string: " + s + " matches: " + method});
            }
        }
    }

    return detections;
}

std::vector<Detection> SignatureDB::check_filenames(const std::vector<std::string>& filenames) const {
    std::vector<Detection> detections;

    for (const auto& fname : filenames) {
        std::string lower = to_lower(fname);

        // Check suspicious extensions
        for (const auto& ext : db_.suspicious_extensions) {
            if (ends_with(lower, ext)) {
                detections.push_back({Severity::CRITICAL, "SUSPICIOUS_FILE_IN_JAR",
                    "JAR contains file with suspicious extension",
                    fname, "extension: " + ext});
                break;
            }
        }

        // Check for known malware file artifacts inside JARs
        for (const auto& artifact : db_.suspicious_file_artifacts) {
            if (contains(lower, to_lower(artifact))) {
                detections.push_back({Severity::CRITICAL, "KNOWN_MALWARE_ARTIFACT",
                    "JAR contains known malware file artifact",
                    fname, "artifact: " + artifact});
                break;
            }
        }
    }

    return detections;
}

} // namespace ihp
