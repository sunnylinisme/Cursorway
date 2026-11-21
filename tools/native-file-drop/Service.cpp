// SPDX-License-Identifier: GPL-2.0-or-later
// Barrier Share service (Windows). Keeps the keyboard/mouse core running in the console
// session and raises it only when needed, like Barrier's elevate-as-needed mode:
// - On the normal desktop the core runs as the signed-in user, so the clipboard (including
//   files copied in Explorer), file access and the cursor scheme are the user's own.
// - When the input desktop is a secure one (sign-in, lock screen, UAC prompt), or nobody is
//   signed in, it runs with the session's winlogon token (SYSTEM), which can reach those screens.
// A small watcher (this exe with --desk-watch, run with the winlogon token in the session)
// reports the input desktop; switching restarts the core, which reconnects within a second.
//
// Security model:
// - Only the user of the active console session may control it, over a local-only pipe.
// - The service never opens paths the user chose: the GUI sends the pairing identity,
//   trusted fingerprints and screen config as data, and the service writes them under
//   <install dir>\state\<user SID>\, which only SYSTEM and Administrators can modify
//   (the user may read it, so the log and received files are reachable).
// - Executables come from the service's own directory; the address must be IPv4.
// - The last command is kept, so after sign-out the core is started again in the new
//   console session and the sign-in screen can be controlled from the other computer.
//
// Pipe protocol (\\.\pipe\Cursorway.Service, one request per connection, UTF-8):
//   START \t host|receiver \t address \t base64(Barrier.pem) \t base64(trusted) \t base64(config) \t screen name \t user profile folder [\t wheel "percent,0|1", receiver only]
//   CONFIG \t base64(config)   (host: replace the running core's configuration; it reloads without reconnecting)
//   STOP
//   STATUS
//   DESKTOP \t <name>|auto   (tests: act as if the input desktop were <name>)
// The user profile folder is used only by the core that runs as that user, so it grants nothing.
// Reply: OK \t running(0|1) \t log path   or   ERROR \t message
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <userenv.h>
#include <wtsapi32.h>
#include <algorithm>
#include <tlhelp32.h>

#include <aclapi.h>
#include <atomic>
#include <cstdio>
#include <fstream>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {
const wchar_t* kServiceName = L"Cursorway";
const wchar_t* kPipeName = L"\\\\.\\pipe\\Cursorway.Service";
SERVICE_STATUS_HANDLE statusHandle = nullptr;
SERVICE_STATUS status{SERVICE_WIN32_OWN_PROCESS, SERVICE_START_PENDING, 0, NO_ERROR, 0, 0, 0};
HANDLE stopEvent = nullptr;
std::atomic<bool> stopping{false};

struct Command {
    bool host = true; std::wstring sid, address, directory, log, name, userProfile, userLog, wheel;
    std::string trusted; // receiver: the hosts the user's app asked for (only approved ones get raised rights)
};
std::mutex mutex;
bool wanted = false; Command command;
PROCESS_INFORMATION core{};
DWORD coreSession = 0xFFFFFFFF;
bool coreSystem = false;
unsigned failures = 0;
// Input desktop reported by the watcher, and a test override.
PROCESS_INFORMATION watcher{}; HANDLE watcherOutput = nullptr; DWORD watcherSession = 0xFFFFFFFF;
std::string watcherBuffer, inputDesktop, forcedDesktop;

std::wstring widen(const std::string& text) {
    if (text.empty()) return {};
    int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (length <= 0) throw std::runtime_error("Invalid text");
    std::wstring result(length, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), &result[0], length);
    return result;
}
std::string narrow(const std::wstring& text) {
    if (text.empty()) return {};
    int length = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string result(length, '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), &result[0], length, nullptr, nullptr);
    return result;
}
void logLine(const std::wstring& directory, const std::string& line) {
    // Service-side notes for the diagnostics window, next to the core log.
    std::ofstream out(directory + L"\\service.log", std::ios::app | std::ios::binary);
    SYSTEMTIME t; GetLocalTime(&t);
    char stamp[32]; std::snprintf(stamp, sizeof(stamp), "[%04u-%02u-%02uT%02u:%02u:%02u] ", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
    out << stamp << line << "\r\n";
}
std::string base64Decode(const std::string& input) {
    static const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (input.size() % 4) throw std::runtime_error("Invalid encoding");
    std::string out; unsigned value = 0; int bits = 0; size_t padding = 0;
    for (size_t i = 0; i < input.size(); ++i) {
        char c = input[i];
        if (c == '=') { if (i + 2 < input.size()) throw std::runtime_error("Invalid encoding"); ++padding; continue; }
        if (padding) throw std::runtime_error("Invalid encoding");
        auto index = alphabet.find(c);
        if (index == std::string::npos) throw std::runtime_error("Invalid encoding");
        value = (value << 6) | static_cast<unsigned>(index); bits += 6;
        if (bits >= 8) { bits -= 8; out.push_back(static_cast<char>((value >> bits) & 0xFF)); }
    }
    return out;
}
std::vector<std::string> fields(const std::string& line) {
    std::vector<std::string> result; size_t start = 0;
    for (;;) { auto end = line.find('\t', start); result.push_back(line.substr(start, end == std::string::npos ? end : end - start)); if (end == std::string::npos) break; start = end + 1; }
    return result;
}
bool validIPv4(const std::string& text) {
    int parts = 0; size_t start = 0;
    while (start <= text.size()) {
        auto end = text.find('.', start); auto part = text.substr(start, end == std::string::npos ? end : end - start);
        if (part.empty() || part.size() > 3 || part.find_first_not_of("0123456789") != std::string::npos || std::stoi(part) > 255) return false;
        ++parts; if (end == std::string::npos) break; start = end + 1;
    }
    return parts == 4;
}
std::wstring moduleDirectory() {
    wchar_t path[MAX_PATH * 4]; DWORD length = GetModuleFileNameW(nullptr, path, MAX_PATH * 4);
    std::wstring result(path, length); return result.substr(0, result.find_last_of(L'\\'));
}
std::wstring quote(const std::wstring& value) {
    std::wstring result = L"\""; int slashes = 0;
    for (wchar_t c : value) {
        if (c == L'\\') { ++slashes; continue; }
        result.append(c == L'"' ? slashes * 2 + 1 : slashes, L'\\'); result.push_back(c); slashes = 0;
    }
    result.append(slashes * 2, L'\\'); result.push_back(L'"'); return result;
}
// Directory only SYSTEM/Administrators can change; the user named by sid may read it.
void secureDirectory(const std::wstring& path, const std::wstring& sid) {
    std::wstring sddl = L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" + (sid.empty() ? std::wstring() : L"(A;OICI;0x1200a9;;;" + sid + L")");
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) throw std::runtime_error("Cannot build folder permissions");
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
    DWORD existing = GetFileAttributesW(path.c_str());
    if (existing != INVALID_FILE_ATTRIBUTES && (existing & FILE_ATTRIBUTE_REPARSE_POINT)) { LocalFree(descriptor); throw std::runtime_error("State folder is a link"); }
    if (existing == INVALID_FILE_ATTRIBUTES && !CreateDirectoryW(path.c_str(), &attributes)) { LocalFree(descriptor); throw std::runtime_error("Cannot create state folder"); }
    if (existing != INVALID_FILE_ATTRIBUTES) {
        BOOL present = FALSE, defaulted = FALSE; PACL dacl = nullptr; GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted);
        if (SetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl, nullptr) != ERROR_SUCCESS) {
            LocalFree(descriptor); throw std::runtime_error("Cannot secure state folder");
        }
    }
    LocalFree(descriptor);
}
void writeFile(const std::wstring& path, const std::string& data) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) throw std::runtime_error("Cannot write state file");
    DWORD written = 0; BOOL ok = data.empty() || WriteFile(file, data.data(), static_cast<DWORD>(data.size()), &written, nullptr);
    CloseHandle(file);
    if (!ok || written != data.size()) throw std::runtime_error("Cannot write state file");
}
// Approved hosts. Any program of the user can send START with its own trust list; a host on that
// list could then drive the sign-in, lock and UAC screens (SYSTEM core) and windows run as
// administrator (UI access core). So those two cores only trust hosts an administrator approved
// (cursorway-service.exe --approve, run elevated by the app after pairing). The plain user core
// trusts the user's own list, which grants nothing the user does not already have.
std::string readText(const std::wstring& path) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) return {};
    std::string text; char chunk[4096]; DWORD got = 0;
    while (text.size() < 1 << 20 && ReadFile(file, chunk, sizeof(chunk), &got, nullptr) && got) text.append(chunk, got);
    CloseHandle(file); return text;
}
bool validFingerprint(const std::string& line) {
    return !line.empty() && line.size() < 200 && line.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:") == std::string::npos;
}
std::vector<std::string> fingerprints(const std::string& text) {
    std::vector<std::string> result; size_t start = 0;
    while (start < text.size()) {
        auto end = text.find('\n', start); auto line = text.substr(start, end == std::string::npos ? std::string::npos : end - start);
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
        if (validFingerprint(line) && std::find(result.begin(), result.end(), line) == result.end()) result.push_back(line);
        if (end == std::string::npos) break; start = end + 1;
    }
    return result;
}
std::wstring approvedFile(const std::wstring& sid) { return moduleDirectory() + L"\\state\\" + sid + L"\\approved-servers.txt"; }
std::vector<std::string> approvedHosts(const std::wstring& sid) { return fingerprints(readText(approvedFile(sid))); }
// Requested hosts an administrator has not approved yet.
std::vector<std::string> pendingHosts(const Command& c) {
    std::vector<std::string> result; if (c.host) return result;
    auto approved = approvedHosts(c.sid);
    for (auto& fp : fingerprints(c.trusted)) if (std::find(approved.begin(), approved.end(), fp) == approved.end()) result.push_back(fp);
    return result;
}
// The trust file of the SYSTEM and UI access cores: requested and approved.
std::wstring approvedTrustFile(const Command& c) { return c.directory + L"\\SSL\\Fingerprints\\TrustedServers.txt"; }
void writeApprovedTrust(const Command& c) {
    auto approved = approvedHosts(c.sid); std::string text;
    for (auto& fp : fingerprints(c.trusted)) if (std::find(approved.begin(), approved.end(), fp) != approved.end()) text += fp + "\n";
    writeFile(approvedTrustFile(c), text);
}
// Only SYSTEM and Administrators may open the hardened core to change it; its owner (the user)
// may query and wait for it (the same as --harden sets inside; this closes the gap before that runs).
const wchar_t* kHardenedCore = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x101000;;;OW)";
bool hardenOff = false; std::string hardenOffReason; bool coreHardened = false;
// A quick exit waiting to be put down to the hardening or UI access (see apply()).
struct Blame { bool pending = false, hardened = false, uiAccess = false; ULONGLONG at = 0; std::string reason; } blame;
HANDLE winlogonToken(DWORD session) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); PROCESSENTRY32W entry{sizeof(entry)}; HANDLE result = nullptr;
    for (BOOL more = Process32FirstW(snapshot, &entry); more && !result; more = Process32NextW(snapshot, &entry)) {
        DWORD processSession = 0;
        if (_wcsicmp(entry.szExeFile, L"winlogon.exe") || !ProcessIdToSessionId(entry.th32ProcessID, &processSession) || processSession != session) continue;
        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, entry.th32ProcessID), token = nullptr;
        if (process && OpenProcessToken(process, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &token)) {
            DuplicateTokenEx(token, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenPrimary, &result); CloseHandle(token);
        }
        if (process) CloseHandle(process);
    }
    CloseHandle(snapshot);
    if (!result) throw std::runtime_error("No sign-in process in the console session");
    DWORD uiAccess = 1; SetTokenInformation(result, TokenUIAccess, &uiAccess, sizeof(uiAccess));
    return result;
}
// On some computers a user core started with UI access ends at once (before it writes its log).
// The core then runs without it, which keeps the connection working, and UI access is tried
// again after a growing pause; only after several quick exits in a row is it left off until
// the service restarts. uiAccessOff says why it is off, for the diagnostics.
constexpr unsigned uiAccessGiveUp = 5;
unsigned uiAccessFailures = 0; ULONGLONG uiAccessRetryAt = 0; std::string uiAccessOff;
bool uiAccessAllowed() { return uiAccessFailures == 0 || (uiAccessFailures < uiAccessGiveUp && GetTickCount64() >= uiAccessRetryAt); }
HANDLE userToken(DWORD session, bool uiAccess = false) {
    HANDLE token = nullptr, primary = nullptr;
    if (!WTSQueryUserToken(session, &token)) return nullptr;
    DuplicateTokenEx(token, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenPrimary, &primary);
    CloseHandle(token);
    // UI access lets the core move the mouse and type into windows running as administrator
    // (installers, regedit, an elevated terminal); without it Windows blocks that input (UIPI)
    // and the pointer freezes while such a window is in front. Only SYSTEM can set it.
    if (primary && uiAccess) { DWORD on = 1; SetTokenInformation(primary, TokenUIAccess, &on, sizeof(on)); }
    return primary;
}
bool running(const PROCESS_INFORMATION& p) { DWORD code = 0; return p.hProcess && GetExitCodeProcess(p.hProcess, &code) && code == STILL_ACTIVE; }
bool coreRunning() { return running(core); }
ULONGLONG coreStartedAt = 0; bool coreUiAccess = false;
void stopWatcher() {
    if (watcher.hProcess) { if (running(watcher)) TerminateProcess(watcher.hProcess, 0); CloseHandle(watcher.hProcess); CloseHandle(watcher.hThread); watcher = PROCESS_INFORMATION{}; }
    if (watcherOutput) { CloseHandle(watcherOutput); watcherOutput = nullptr; }
    watcherSession = 0xFFFFFFFF; watcherBuffer.clear(); inputDesktop.clear();
}
// Runs "cursorway-service.exe --desk-watch" with the winlogon token, which may read the input desktop.
void startWatcher(DWORD session) {
    stopWatcher();
    SECURITY_ATTRIBUTES inherit{sizeof(inherit), nullptr, TRUE}; HANDLE read = nullptr, write = nullptr;
    if (!CreatePipe(&read, &write, &inherit, 0)) throw std::runtime_error("Cannot create watcher pipe");
    SetHandleInformation(read, HANDLE_FLAG_INHERIT, 0);
    std::wstring line = quote(moduleDirectory() + L"\\cursorway-service.exe") + L" --desk-watch";
    std::vector<wchar_t> buffer(line.begin(), line.end()); buffer.push_back(0);
    STARTUPINFOW startup{sizeof(startup)}; startup.lpDesktop = const_cast<wchar_t*>(L"winsta0\\default");
    startup.dwFlags = STARTF_USESTDHANDLES; startup.hStdOutput = startup.hStdError = write;
    HANDLE token = winlogonToken(session);
    BOOL ok = CreateProcessAsUserW(token, nullptr, buffer.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, moduleDirectory().c_str(), &startup, &watcher);
    DWORD error = GetLastError(); CloseHandle(token); CloseHandle(write);
    if (!ok) { CloseHandle(read); throw std::runtime_error("Cannot start desktop watcher (error " + std::to_string(error) + ")"); }
    watcherOutput = read; watcherSession = session;
}
void readWatcher() {
    DWORD available = 0;
    while (watcherOutput && PeekNamedPipe(watcherOutput, nullptr, 0, nullptr, &available, nullptr) && available) {
        char chunk[256]; DWORD got = 0;
        if (!ReadFile(watcherOutput, chunk, (std::min)(available, static_cast<DWORD>(sizeof(chunk))), &got, nullptr) || !got) break;
        watcherBuffer.append(chunk, got);
        for (size_t end; (end = watcherBuffer.find('\n')) != std::string::npos; watcherBuffer.erase(0, end + 1)) {
            auto lineText = watcherBuffer.substr(0, end); if (!lineText.empty() && lineText.back() == '\r') lineText.pop_back();
            if (lineText.size() < 64) inputDesktop = lineText;
        }
    }
}
void stopCore() {
    if (core.hProcess) {
        if (coreRunning()) { TerminateProcess(core.hProcess, 0); WaitForSingleObject(core.hProcess, 5000); }
        CloseHandle(core.hProcess); CloseHandle(core.hThread); core = PROCESS_INFORMATION{};
    }
    coreSession = 0xFFFFFFFF;
}
// asSystem: the winlogon token and the service's protected state folder; otherwise the
// signed-in user's token and that user's own profile folder (what the app uses without the service).
void startCore(DWORD session, bool asSystem, const std::string& why) {
    stopCore();
    // Only the receiver types into other windows; the host reads input through its hook and needs no UI access.
    auto pending = pendingHosts(command);
    if (!command.host) writeApprovedTrust(command);
    bool uiAccess = !asSystem && !command.host && uiAccessAllowed() && pending.empty();
    bool harden = uiAccess && !hardenOff;
    HANDLE token = asSystem ? winlogonToken(session) : userToken(session, uiAccess);
    if (!token) throw std::runtime_error("No signed-in user in the console session");
    std::wstring bin = moduleDirectory(), profile = asSystem ? command.directory : command.userProfile, log = asSystem ? command.log : command.userLog;
    std::wstring line = quote(bin + (command.host ? L"\\cursorway-server.exe" : L"\\cursorway-client.exe")) + L" -f --no-tray --file-clipboard --profile-dir " + quote(profile) +
        L" --log " + quote(log) + L" --name " + command.name;
    // The host reads the configuration the service keeps (it arrives with START and CONFIG), never
    // the copy in the user's folder: on one computer the user's core could not open that file.
    // The UI access core trusts only approved hosts (a file the user cannot change), and is hardened
    // against other programs of the user unless that kept it from starting.
    if (uiAccess) line += L" --trusted-servers " + quote(approvedTrustFile(command)) + (harden ? L" --harden" : L"");
    line += command.host ? L" -c " + quote(command.directory + L"\\windows-windows.conf") : command.wheel + L" " + command.address;
    if (!asSystem) {
        // Note whether the signed-in user's core can open its profile folder (for the log only).
        if (ImpersonateLoggedOnUser(token)) {
            for (const std::wstring& path : { profile + L"\\SSL\\Barrier.pem", log, profile + L"\\windows-windows.conf", command.directory + L"\\windows-windows.conf" }) {
                HANDLE probe = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
                if (probe == INVALID_HANDLE_VALUE) logLine(command.directory, "as the user, cannot open " + narrow(path) + " (error " + std::to_string(GetLastError()) + ")");
                else CloseHandle(probe);
            }
            RevertToSelf();
        }
    }
    STARTUPINFOW startup{sizeof(startup)}; startup.lpDesktop = const_cast<wchar_t*>(L"winsta0\\default");
    // What the core prints before its log file is open (bad arguments, a missing file) goes to
    // core-output.txt in the service's folder, which the user can read.
    SECURITY_ATTRIBUTES inherit{sizeof(inherit), nullptr, TRUE};
    HANDLE output = CreateFileW((command.directory + L"\\core-output.txt").c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (output != INVALID_HANDLE_VALUE) { startup.dwFlags |= STARTF_USESTDHANDLES; startup.hStdOutput = output; startup.hStdError = output; startup.hStdInput = nullptr; }
    std::vector<wchar_t> buffer(line.begin(), line.end()); buffer.push_back(0);
    void* environment = nullptr; if (!asSystem) CreateEnvironmentBlock(&environment, token, FALSE);
    PSECURITY_DESCRIPTOR hardened = nullptr; SECURITY_ATTRIBUTES protect{sizeof(protect), nullptr, FALSE};
    if (harden && ConvertStringSecurityDescriptorToSecurityDescriptorW(kHardenedCore, SDDL_REVISION_1, &hardened, nullptr)) protect.lpSecurityDescriptor = hardened;
    BOOL ok = CreateProcessAsUserW(token, nullptr, buffer.data(), hardened ? &protect : nullptr, hardened ? &protect : nullptr, output != INVALID_HANDLE_VALUE, CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, environment, bin.c_str(), &startup, &core);
    DWORD error = GetLastError(); CloseHandle(token); if (environment) DestroyEnvironmentBlock(environment); if (hardened) LocalFree(hardened);
    if (output != INVALID_HANDLE_VALUE) CloseHandle(output);
    logLine(command.directory, "command: " + narrow(line));
    if (!ok) throw std::runtime_error("Cannot start core (error " + std::to_string(error) + ")");
    coreSession = session; coreSystem = asSystem; coreStartedAt = GetTickCount64(); coreUiAccess = uiAccess; coreHardened = harden;
    std::string accessOff = !pending.empty() ? std::to_string(pending.size()) + " paired computer(s) not yet allowed by an administrator" : uiAccessOff;
    logLine(command.directory, "core now runs as " + std::string(asSystem ? "SYSTEM" : "the signed-in user") + " (" + why + "), " + (command.host ? "host" : "receiver") + ", session " + std::to_string(session) + ", log " + narrow(log) +
        (asSystem || command.host ? std::string() : uiAccess ? std::string(", UI access: on") + (harden ? ", hardened" : ", not hardened (" + hardenOffReason + ")") : ", UI access: off (" + accessOff + ")"));
}
// Starts or switches the core to match the console session and its input desktop; mutex held.
void apply() {
    DWORD session = WTSGetActiveConsoleSessionId();
    if (session == 0xFFFFFFFF) return;
    if (!running(watcher) || watcherSession != session) {
        try { startWatcher(session); } catch (const std::exception& e) { if (wanted) logLine(command.directory, std::string("desktop watcher: ") + e.what()); }
    }
    readWatcher();
    if (!wanted) { if (core.hProcess) stopCore(); return; }
    std::string desktop = forcedDesktop.empty() ? inputDesktop : forcedDesktop;
    HANDLE user = userToken(session); bool signedIn = user != nullptr; if (user) CloseHandle(user);
    bool secure = !desktop.empty() && _stricmp(desktop.c_str(), "Default") != 0;
    bool asSystem = !signedIn || secure;
    static ULONGLONG retryAt = 0;
    static unsigned quickExits = 0;
    // Signing out, signing in or switching users changes the console session or whether a user is in
    // it. Cores die and fail to start for a moment around that; start the next one at once rather than
    // after the pause that a core that keeps ending would get.
    static DWORD lastSession = 0xFFFFFFFF; static bool lastSignedIn = false;
    if (session != lastSession || signedIn != lastSignedIn) {
        if (lastSession != 0xFFFFFFFF) logLine(command.directory, "console session " + std::to_string(session) + ": " + (signedIn ? "a user is signed in" : "nobody signed in"));
        lastSession = session; lastSignedIn = signedIn; quickExits = 0; failures = 0; retryAt = 0; blame.pending = false;
    }
    // A quick exit is put down to the hardening or to UI access only if nothing like that happened
    // within 5 s: while a user signs out, every core in the dying session ends at once.
    if (blame.pending && GetTickCount64() - blame.at >= 5000) {
        blame.pending = false;
        if (blame.hardened) {
            hardenOff = true; hardenOffReason = blame.reason;
            logLine(command.directory, "running the core without hardening from now on (" + hardenOffReason + ")");
        } else if (blame.uiAccess) {
            ++uiAccessFailures; unsigned wait = 30 * uiAccessFailures;
            uiAccessRetryAt = GetTickCount64() + 1000ull * wait;
            uiAccessOff = blame.reason + ", " + std::to_string(uiAccessFailures) + " in a row";
            if (uiAccessFailures >= uiAccessGiveUp) { uiAccessOff += "; left off until the service restarts"; logLine(command.directory, "UI access off until the service restarts (" + std::to_string(uiAccessFailures) + " quick exits in a row)"); }
            else { uiAccessOff += "; retrying in " + std::to_string(wait) + " s"; logLine(command.directory, "running the core without UI access for now; retrying it in " + std::to_string(wait) + " s"); }
        }
        // Started again without what it was blamed on.
        if (coreRunning() && (blame.hardened || blame.uiAccess)) stopCore();
    }
    if (coreRunning() && session == coreSession && asSystem == coreSystem) {
        failures = 0;
        // A core that keeps running with UI access clears the count of quick exits.
        if (coreUiAccess && uiAccessFailures > 0 && GetTickCount64() - coreStartedAt >= 3000) { uiAccessFailures = 0; uiAccessOff.clear(); logLine(command.directory, "UI access works again"); }
        // Time to try UI access again: restart the user core with it (the link reconnects in about a second).
        bool retry = !coreSystem && !command.host && !coreUiAccess && uiAccessFailures > 0 && uiAccessAllowed();
        if (!retry) return;
        logLine(command.directory, "trying UI access again (" + std::to_string(uiAccessFailures) + " quick exits so far)");
    }
    if (core.hProcess && !coreRunning()) {
        DWORD code = 0; GetExitCodeProcess(core.hProcess, &code);
        ULONGLONG ran = GetTickCount64() - coreStartedAt;
        char hex[16]; std::snprintf(hex, sizeof(hex), "0x%08lX", static_cast<unsigned long>(code));
        if (ran < 3000) {
            // A core that ends at once is started again after a growing pause (up to 10 s), not four times a second.
            ++quickExits; retryAt = GetTickCount64() + 1000ull * (quickExits < 10 ? quickExits : 10);
            if (quickExits <= 3 || quickExits % 20 == 0)
                logLine(command.directory, "core ended after " + std::to_string(ran) + " ms (exit " + std::to_string(code) + " / " + hex + ", " + std::to_string(quickExits) + " in a row)");
            if ((coreHardened || coreUiAccess) && !blame.pending) {
                blame.pending = true; blame.at = GetTickCount64(); blame.hardened = coreHardened; blame.uiAccess = coreUiAccess;
                blame.reason = std::string(coreHardened ? "a hardened core" : "a core with UI access") + " ended after " + std::to_string(ran) + " ms, exit " + hex;
            }
        } else {
            quickExits = 0;
            logLine(command.directory, "core ended after " + std::to_string(ran / 1000) + " s (exit " + std::to_string(code) + " / " + hex + ")");
        }
        CloseHandle(core.hProcess); CloseHandle(core.hThread); core = PROCESS_INFORMATION{};
    }
    if (coreRunning() || GetTickCount64() >= retryAt) {
        try { startCore(session, asSystem, !signedIn ? "nobody signed in" : secure ? "input desktop " + desktop : "input desktop " + (desktop.empty() ? std::string("Default") : desktop)); }
        catch (const std::exception& e) {
            ++failures; retryAt = GetTickCount64() + 1000ull * (failures < 5 ? failures * 2 : 10);
            logLine(command.directory, std::string("start failed: ") + e.what());
        }
    }
}
// Keeps the core running in the active console session, including the sign-in screen,
// and follows desktop switches four times a second.
void monitor() {
    while (WaitForSingleObject(stopEvent, 250) == WAIT_TIMEOUT) { std::lock_guard<std::mutex> lock(mutex); apply(); }
}
std::wstring clientSid(HANDLE pipe) {
    if (!ImpersonateNamedPipeClient(pipe)) throw std::runtime_error("Cannot identify caller");
    HANDLE token = nullptr; BOOL ok = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token);
    RevertToSelf();
    if (!ok) throw std::runtime_error("Cannot identify caller");
    std::vector<unsigned char> buffer(256); DWORD length = 0;
    if (!GetTokenInformation(token, TokenUser, buffer.data(), static_cast<DWORD>(buffer.size()), &length)) { buffer.resize(length); GetTokenInformation(token, TokenUser, buffer.data(), length, &length); }
    CloseHandle(token);
    wchar_t* text = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &text)) throw std::runtime_error("Cannot identify caller");
    std::wstring sid(text); LocalFree(text); return sid;
}
// Whether the caller runs elevated as an administrator (a filtered UAC token does not count).
bool callerIsAdministrator(HANDLE pipe) {
    if (!ImpersonateNamedPipeClient(pipe)) return false;
    BYTE sid[SECURITY_MAX_SID_SIZE]; DWORD size = sizeof(sid); BOOL member = FALSE;
    bool ok = CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, sid, &size) && CheckTokenMembership(nullptr, sid, &member) && member;
    RevertToSelf(); return ok;
}
std::string handle(HANDLE pipe, const std::string& request) {
    ULONG session = 0;
    if (!GetNamedPipeClientSessionId(pipe, &session) || session != WTSGetActiveConsoleSessionId()) throw std::runtime_error("Only the signed-in console user can control Barrier Share");
    auto f = fields(request);
    std::lock_guard<std::mutex> lock(mutex);
    auto reply = [&]() { return "OK\t" + std::string(wanted && coreRunning() ? "1" : "0") + '\t' + narrow(command.log); };
    if (f[0] == "STATUS") return reply();
    if (f[0] == "APPROVAL") {
        if (command.host || clientSid(pipe) != command.sid) return "OK\t0\t";
        auto pending = pendingHosts(command); std::string list;
        for (auto& fp : pending) list += (list.empty() ? "" : ",") + fp;
        return "OK\t" + std::to_string(pending.size()) + "\t" + list;
    }
    if (f[0] == "STOP") { wanted = false; stopCore(); return reply(); }
    // DESKTOP is a test hook: acting as if a secure desktop were shown starts the core with the
    // SYSTEM token on the user's desktop, so only an elevated administrator may use it.
    if (f[0] == "DESKTOP" && !callerIsAdministrator(pipe)) throw std::runtime_error("DESKTOP needs an administrator");
    if (f[0] == "DESKTOP" && f.size() == 2 && !f[1].empty() && f[1].size() < 32 && f[1].find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") == std::string::npos) {
        forcedDesktop = f[1] == "auto" ? "" : f[1]; apply(); return reply();
    }
    // CONFIG <base64 config>: new host settings for the running core, which re-reads its file
    // without dropping connections (0.3.17+ core). Only the user who started it may change it.
    if (f[0] == "CONFIG" && f.size() == 2) {
        if (!wanted || !command.host) throw std::runtime_error("No host core is running");
        auto config = base64Decode(f[1]);
        if (config.find("section: screens") == std::string::npos) throw std::runtime_error("Incomplete configuration");
        if (clientSid(pipe) != command.sid) throw std::runtime_error("The core was started by another user");
        writeFile(command.directory + L"\\windows-windows.conf", config);
        return reply();
    }
    if (f[0] != "START" || (f.size() != 8 && f.size() != 9) || (f[1] != "host" && f[1] != "receiver")) throw std::runtime_error("Invalid request");
    // The user profile folder is only handed to the core that runs as that same user.
    if (f[7].size() < 4 || f[7].size() > 1024 || f[7].find('"') != std::string::npos || !(f[7][1] == ':' || f[7].compare(0, 2, "\\\\") == 0)) throw std::runtime_error("Invalid profile folder");
    if (f[6].empty() || f[6].size() > 32 || f[6].find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-") != std::string::npos) throw std::runtime_error("Invalid screen name");
    bool host = f[1] == "host";
    // Receiver: the host's IPv4 address, optionally with :port (used by the tests).
    if (!host) {
        auto colon = f[2].find(':'); auto port = colon == std::string::npos ? std::string("24800") : f[2].substr(colon + 1);
        if (!validIPv4(f[2].substr(0, colon)) || port.empty() || port.size() > 5 || port.find_first_not_of("0123456789") != std::string::npos || std::stoi(port) == 0 || std::stoi(port) > 65535)
            throw std::runtime_error("Invalid host address");
    }
    auto pem = base64Decode(f[3]), trusted = base64Decode(f[4]), config = base64Decode(f[5]);
    if (pem.find("PRIVATE KEY") == std::string::npos || (host && config.find("section: screens") == std::string::npos)) throw std::runtime_error("Incomplete pairing data");
    Command next; next.host = host; next.address = widen(f[2]); next.name = widen(f[6]); next.sid = clientSid(pipe);
    // Optional receiver wheel settings: "<percent>,<0|1>".
    if (f.size() == 9 && !host) {
        auto comma = f[8].find(',');
        std::string scale = f[8].substr(0, comma), invert = comma == std::string::npos ? "0" : f[8].substr(comma + 1);
        if (scale.empty() || scale.size() > 3 || scale.find_first_not_of("0123456789") != std::string::npos || std::stoi(scale) < 10 || std::stoi(scale) > 500 || (invert != "0" && invert != "1")) throw std::runtime_error("Invalid wheel settings");
        if (scale != "100") next.wheel += L" --wheel-scale " + widen(scale);
        if (invert == "1") next.wheel += L" --wheel-invert";
    }
    next.userProfile = widen(f[7]); while (!next.userProfile.empty() && next.userProfile.back() == L'\\') next.userProfile.pop_back();
    next.userLog = next.userProfile + (host ? L"\\server.log" : L"\\windows.log");
    std::wstring state = moduleDirectory() + L"\\state";
    secureDirectory(state, L""); secureDirectory(state + L"\\" + next.sid, next.sid);
    next.directory = state + L"\\" + next.sid + (host ? L"\\profile-server" : L"\\profile");
    secureDirectory(next.directory, next.sid);
    for (auto sub : { L"\\SSL", L"\\SSL\\Fingerprints" }) secureDirectory(next.directory + sub, next.sid);
    writeFile(next.directory + L"\\SSL\\Barrier.pem", pem);
    if (host) writeFile(next.directory + L"\\SSL\\Fingerprints\\TrustedClients.txt", trusted);
    else {
        // Upgrading: the hosts the service already let onto the sign-in screen stay approved.
        if (GetFileAttributesW(approvedFile(next.sid).c_str()) == INVALID_FILE_ATTRIBUTES) writeFile(approvedFile(next.sid), readText(approvedTrustFile(next)));
        next.trusted = trusted; writeApprovedTrust(next);
    }
    if (host) writeFile(next.directory + L"\\windows-windows.conf", config);
    next.log = next.directory + (host ? L"\\server.log" : L"\\windows.log");
    stopCore(); command = next; wanted = true; failures = 0;
    apply();
    return reply();
}
void serve() {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    // Signed-in users may connect; requests are still limited to the console session.
    ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)", SDDL_REVISION_1, &descriptor, nullptr);
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
    while (!stopping) {
        HANDLE pipe = CreateNamedPipeW(kPipeName, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 65536, 4 * 1024 * 1024, 0, &attributes);
        if (pipe == INVALID_HANDLE_VALUE) { if (WaitForSingleObject(stopEvent, 1000) == WAIT_OBJECT_0) break; continue; }
        OVERLAPPED overlapped{}; overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        BOOL connected = ConnectNamedPipe(pipe, &overlapped);
        if (!connected && GetLastError() == ERROR_IO_PENDING) {
            HANDLE waits[2] = { overlapped.hEvent, stopEvent };
            DWORD which = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
            if (which != WAIT_OBJECT_0) { CancelIo(pipe); CloseHandle(overlapped.hEvent); CloseHandle(pipe); break; }
            DWORD ignored; connected = GetOverlappedResult(pipe, &overlapped, &ignored, FALSE);
        } else if (!connected && GetLastError() == ERROR_PIPE_CONNECTED) connected = TRUE;
        if (connected) {
            std::string request, reply; std::vector<char> chunk(65536); bool complete = false;
            while (request.size() < 4 * 1024 * 1024) {
                DWORD read = 0; ResetEvent(overlapped.hEvent);
                BOOL ok = ReadFile(pipe, chunk.data(), static_cast<DWORD>(chunk.size()), &read, &overlapped);
                if (!ok && GetLastError() == ERROR_IO_PENDING) {
                    if (WaitForSingleObject(overlapped.hEvent, 10000) != WAIT_OBJECT_0) { CancelIo(pipe); break; }
                    ok = GetOverlappedResult(pipe, &overlapped, &read, FALSE);
                }
                request.append(chunk.data(), read);
                if (ok) { complete = true; break; }
                if (GetLastError() != ERROR_MORE_DATA) break;
            }
            try { if (!complete) throw std::runtime_error("Incomplete request"); while (!request.empty() && (request.back() == '\n' || request.back() == '\r')) request.pop_back(); reply = handle(pipe, request); }
            catch (const std::exception& e) { reply = std::string("ERROR\t") + e.what(); }
            DWORD written = 0; ResetEvent(overlapped.hEvent);
            if (!WriteFile(pipe, reply.data(), static_cast<DWORD>(reply.size()), &written, &overlapped) && GetLastError() == ERROR_IO_PENDING)
                if (WaitForSingleObject(overlapped.hEvent, 5000) == WAIT_OBJECT_0) GetOverlappedResult(pipe, &overlapped, &written, FALSE);
            FlushFileBuffers(pipe); DisconnectNamedPipe(pipe);
        }
        CloseHandle(overlapped.hEvent); CloseHandle(pipe);
    }
    LocalFree(descriptor);
}
void report(DWORD state, DWORD exitCode = NO_ERROR) {
    status.dwCurrentState = state; status.dwWin32ExitCode = exitCode;
    status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    if (statusHandle) SetServiceStatus(statusHandle, &status);
}
DWORD WINAPI control(DWORD code, DWORD, LPVOID, LPVOID) {
    if (code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN) { report(SERVICE_STOP_PENDING); stopping = true; SetEvent(stopEvent); }
    return NO_ERROR;
}
// Ctrl+Alt+Del from the paired computer. The receiver core cannot send it itself: on that key it
// signals the named event below (MSWindowsKeyState::fakeCtrlAltDel), and this service, running as
// SYSTEM, asks Windows for the secure attention sequence. SendSAS works for a service only while the
// SoftwareSASGeneration policy allows services (set by the installer).
using SendSasFunction = void (WINAPI*)(BOOL);
void WINAPI realSendSas(BOOL asUser) {
    static SendSasFunction send = nullptr;
    if (!send) if (HMODULE sas = LoadLibraryW(L"sas.dll")) send = reinterpret_cast<SendSasFunction>(GetProcAddress(sas, "SendSAS"));
    if (send) send(asUser);
}
// Only the console user's cores may signal it: SYSTEM (the winlogon-token core) and interactive
// users get no more than EVENT_MODIFY_STATE (set the event), nobody else gets anything.
HANDLE createSasEvent(const wchar_t* name, const wchar_t* access = L"D:P(A;;GA;;;SY)(A;;0x0002;;;IU)") {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(access, SDDL_REVISION_1, &descriptor, nullptr)) return nullptr;
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
    HANDLE event = CreateEventW(&attributes, FALSE, FALSE, name);
    LocalFree(descriptor); return event;
}
// Waits for the event; calls send for a receiver core only (a host types nothing into this computer).
void watchSas(HANDLE event, SendSasFunction send, const std::function<bool()>& receiver) {
    HANDLE waits[2] = { event, stopEvent };
    ULONGLONG last = 0;
    while (WaitForMultipleObjects(2, waits, FALSE, INFINITE) == WAIT_OBJECT_0) {
        if (!receiver()) continue;
        // One press is one request: the core that takes over on the secure desktop may see the same
        // keys again; one press must not ask Windows twice.
        ULONGLONG now = GetTickCount64();
        if (last != 0 && now - last < 3000) { std::lock_guard<std::mutex> lock(mutex); logLine(command.directory, "Ctrl+Alt+Del again within 3 s: ignored"); continue; }
        last = now;
        send(FALSE);
        std::lock_guard<std::mutex> lock(mutex); logLine(command.directory, "Ctrl+Alt+Del from the paired computer: sent the secure attention sequence");
    }
}
void run() {
    stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE sas = createSasEvent(L"Global\\SendSAS");
    std::thread follower(monitor), server(serve);
    std::thread sasWatcher;
    if (sas) sasWatcher = std::thread(watchSas, sas, realSendSas, []() { std::lock_guard<std::mutex> lock(mutex); return wanted && !command.host; });
    if (statusHandle) report(SERVICE_RUNNING);
    server.join(); follower.join(); if (sasWatcher.joinable()) sasWatcher.join(); if (sas) CloseHandle(sas);
    { std::lock_guard<std::mutex> lock(mutex); stopCore(); stopWatcher(); }
}
void WINAPI serviceMain(DWORD, LPWSTR*) {
    statusHandle = RegisterServiceCtrlHandlerExW(kServiceName, control, nullptr);
    if (!statusHandle) return;
    run(); report(SERVICE_STOPPED);
}

// Watcher mode: print the input desktop's name whenever it changes (exits when the service goes away).
int watchDesktop() {
    std::string last;
    for (;;) {
        std::string name = "Winlogon";
        if (HDESK desk = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS)) {
            wchar_t buffer[64] = {};
            if (GetUserObjectInformationW(desk, UOI_NAME, buffer, sizeof(buffer) - sizeof(wchar_t), nullptr)) name = narrow(buffer);
            CloseDesktop(desk);
        }
        if (name != last) {
            auto line = name + "\n"; DWORD written = 0;
            if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), line.data(), static_cast<DWORD>(line.size()), &written, nullptr)) return 0;
            last = name;
        }
        Sleep(200);
    }
}
}

// --sas-test: the Ctrl+Alt+Del path with a stand-in for SendSAS, on an event of its own name.
int sasTest() {
    stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::wstring name = L"Global\\CursorwaySasTest-" + std::to_wstring(GetCurrentProcessId());
    // The test runs as an administrator, not as an interactive user: it gets the same narrow right.
    HANDLE event = createSasEvent(name.c_str(), L"D:P(A;;GA;;;SY)(A;;0x0002;;;IU)(A;;0x0002;;;BA)");
    if (!event) { std::printf("FAIL: cannot create the event (error %lu)\n", GetLastError()); return 1; }
    static std::atomic<int> calls{0}; static std::atomic<bool> receiver{true};
    command.directory = L"."; command.host = false;
    std::thread watcher(watchSas, event, [](BOOL asUser) { if (!asUser) ++calls; }, []() { return receiver.load(); });
    auto signal = [&]() {
        // Opened the way the core opens it: only the right to set it.
        HANDLE core = OpenEventW(EVENT_MODIFY_STATE, FALSE, name.c_str());
        if (!core) return false;
        BOOL ok = SetEvent(core); CloseHandle(core); return ok != FALSE;
    };
    auto waitFor = [&](int count) { for (int i = 0; i < 40 && calls < count; ++i) Sleep(50); return calls == count; };
    // A second press right away is ignored; one 3 s later counts again.
    bool ok = signal() && waitFor(1) && signal(); Sleep(300); ok = ok && calls == 1;
    Sleep(3000); ok = ok && signal() && waitFor(2);
    Sleep(3000); receiver = false; ok = ok && signal(); Sleep(300); ok = ok && calls == 2;
    // Nobody may take more than the right to set it (for example to wait on it and steal the signal).
    HANDLE wide = OpenEventW(EVENT_ALL_ACCESS, FALSE, name.c_str());
    bool narrow = true;
    if (wide) { CloseHandle(wide); narrow = false; }
    SetEvent(stopEvent); watcher.join(); CloseHandle(event);
    if (!ok || !narrow) { std::printf("FAIL: calls=%d narrow=%d\n", calls.load(), narrow ? 1 : 0); return 1; }
    std::printf("PASS: Ctrl+Alt+Del event reached SendSAS for a receiver (a repeat within 3 s ignored), not for a host, and only allows setting it\n");
    return 0;
}
// --approve <user SID> <fingerprint>[,<fingerprint>...]: run elevated by the app after pairing.
int approve(const std::wstring& sid, const std::wstring& list) {
    BYTE admins[SECURITY_MAX_SID_SIZE]; DWORD size = sizeof(admins); BOOL member = FALSE;
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admins, &size) || !CheckTokenMembership(nullptr, admins, &member) || !member) { std::printf("needs an administrator\n"); return 5; }
    if (sid.size() < 8 || sid.size() > 200 || sid.compare(0, 4, L"S-1-") || sid.find_first_not_of(L"S0123456789-") != std::wstring::npos) { std::printf("invalid user\n"); return 2; }
    std::string text = narrow(list); for (auto& c : text) if (c == ',') c = '\n';
    auto add = fingerprints(text);
    if (add.empty()) { std::printf("nothing to approve\n"); return 2; }
    std::wstring state = moduleDirectory() + L"\\state";
    try {
        secureDirectory(state, L""); secureDirectory(state + L"\\" + sid, sid);
        auto approved = approvedHosts(sid);
        for (auto& fp : add) if (std::find(approved.begin(), approved.end(), fp) == approved.end()) approved.push_back(fp);
        std::string out; for (auto& fp : approved) out += fp + "\n";
        writeFile(approvedFile(sid), out);
    } catch (const std::exception& e) { std::printf("%s\n", e.what()); return 1; }
    return 0;
}
int wmain(int argc, wchar_t** argv) {
    if (argc == 4 && std::wstring(argv[1]) == L"--approve") return approve(argv[2], argv[3]);
    if (argc == 2 && std::wstring(argv[1]) == L"--desk-watch") return watchDesktop();
    if (argc == 2 && std::wstring(argv[1]) == L"--sas-test") return sasTest();
    // --console runs the same loop in the foreground for testing as an administrator.
    if (argc == 2 && std::wstring(argv[1]) == L"--console") { SetConsoleCtrlHandler([](DWORD) -> BOOL { stopping = true; SetEvent(stopEvent); return TRUE; }, TRUE); run(); return 0; }
    SERVICE_TABLE_ENTRYW table[] = { { const_cast<wchar_t*>(kServiceName), serviceMain }, { nullptr, nullptr } };
    return StartServiceCtrlDispatcherW(table) ? 0 : 1;
}
