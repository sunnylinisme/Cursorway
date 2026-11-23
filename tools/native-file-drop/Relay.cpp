// SPDX-License-Identifier: GPL-2.0-or-later
// Cursorway relay (Windows receiver). Holds the one connection to the host while the receiver
// cores come and go, so switching between the user's desktop and the secure desktop (Ctrl+Alt+Del,
// UAC, lock screen) or a core restart never disconnects from the host.
//
//   host ──TLS── relay ──TLS (127.0.0.1)── user core   (the user's desktop; clipboard, files)
//                      └─TLS (127.0.0.1)── system core (sign-in / lock / UAC screens; no clipboard)
//
// Both cores stay connected; the relay sends the host's input only to the one on the active
// desktop (ROUTE from the service). Switching sends the old core the releases of what it holds and
// a leave, and the new one an enter at the current position. Clipboard and file messages only ever
// go between the host and the user core. The host sees one screen whose shape is the user core's.
//
// cursorway-relay --profile <dir> --host <ip:port> --listen <port> --user-core <fp> --system-core <fp>
//                 --name <screen> [--log <file>]
//   <dir>\SSL\Barrier.pem               the identity shown to the host and to the cores
//   <dir>\SSL\Fingerprints\TrustedServers.txt   hosts it may connect to (approved hosts only)
// stdin: "ROUTE user" / "ROUTE system" / "QUIT". stdout: one line per event (for the service log).
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace {
using Clock = std::chrono::steady_clock;
std::mutex outputMutex; std::ofstream logFile;
void emit(const std::string& line) {
    std::lock_guard<std::mutex> lock(outputMutex);
    std::cout << line << std::endl;
    if (logFile) { SYSTEMTIME t; GetLocalTime(&t); char stamp[32]; std::snprintf(stamp, sizeof(stamp), "[%02u:%02u:%02u.%03u] ", t.wHour, t.wMinute, t.wSecond, t.wMilliseconds); logFile << stamp << line << "\n"; logFile.flush(); }
}
std::string u16(unsigned v) { return std::string{char(v >> 8), char(v)}; }
std::string u32(uint32_t v) { return std::string{char(v >> 24), char(v >> 16), char(v >> 8), char(v)}; }
uint32_t get32(const std::string& s, size_t at) { return (uint32_t(uint8_t(s[at])) << 24) | (uint32_t(uint8_t(s[at + 1])) << 16) | (uint32_t(uint8_t(s[at + 2])) << 8) | uint8_t(s[at + 3]); }
unsigned get16(const std::string& s, size_t at) { return (unsigned(uint8_t(s[at])) << 8) | uint8_t(s[at + 1]); }
int16_t sget16(const std::string& s, size_t at) { return int16_t(get16(s, at)); }
std::string code(const std::string& m) { return m.substr(0, 4); }
const size_t kMaxFrame = 32 * 1024 * 1024;

std::string fingerprintOf(SSL* ssl) {
    X509* cert = SSL_get1_peer_certificate(ssl); if (!cert) return {};
    unsigned char digest[EVP_MAX_MD_SIZE]; unsigned length = 0; X509_digest(cert, EVP_sha256(), digest, &length); X509_free(cert);
    std::string result = "v2:sha256:"; for (unsigned i = 0; i < length; ++i) { result += "0123456789abcdef"[digest[i] >> 4]; result += "0123456789abcdef"[digest[i] & 15]; }
    return result;
}
std::set<std::string> readTrust(const std::string& path) {
    std::set<std::string> result; std::ifstream in(path); std::string line;
    while (std::getline(in, line)) { while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back(); if (!line.empty()) result.insert(line); }
    return result;
}

enum class Role { Pending, Host, User, System };
const char* name(Role r) { return r == Role::Host ? "host" : r == Role::User ? "user core" : r == Role::System ? "system core" : "core"; }

struct Conn {
    SOCKET fd = INVALID_SOCKET; SSL* ssl = nullptr; Role role = Role::Pending; bool server = false, secured = false, closed = false, connecting = false;
    int stage = 0; std::string in, out, dinf; Clock::time_point lastSeen = Clock::now(), lastAlive = Clock::now();
    ~Conn() { if (ssl) SSL_free(ssl); if (fd != INVALID_SOCKET) closesocket(fd); }
    void send(const std::string& message) { if (!closed) out += u32(uint32_t(message.size())) + message; }
};

struct Relay {
    SSL_CTX* context = nullptr; std::string hostAddress, screenName, userFp, systemFp; std::set<std::string> trustedHosts;
    unsigned short listenPort = 0; SOCKET listener = INVALID_SOCKET;
    std::vector<std::unique_ptr<Conn>> conns; Conn* host = nullptr; Conn* user = nullptr; Conn* system = nullptr;
    Role route = Role::User; Clock::time_point hostRetry{};
    // What the host told this screen, replayed to a core that connects or takes over.
    std::string options;                      // last DSOP (empty: none)
    bool hostWantsInfo = false, hostReady = false, entered = false;
    int16_t x = 0, y = 0; uint32_t seq = 0; unsigned mask = 0;
    std::map<unsigned, std::string> heldKeys; // button -> "DKDN..." message
    std::set<unsigned> heldButtons;
    std::map<unsigned, std::vector<std::string>> clipboard; // id -> the host's last complete DCLP messages
    std::map<unsigned, std::vector<std::string>> clipboardPartial;
    std::string sentInfo;                     // the DINF the host has
    std::mutex commandMutex; std::deque<std::string> commands; std::atomic<bool> quit{false};

    Conn* active() { return route == Role::System ? (system ? system : nullptr) : (user ? user : nullptr); }
    Conn* shapeSource() { return user && user->stage == 2 ? user : system && system->stage == 2 ? system : nullptr; }

    void close(Conn* c, const std::string& why) {
        if (c->closed) return; c->closed = true;
        emit(std::string(name(c->role)) + " disconnected: " + why);
        if (c == host) { host = nullptr; hostReady = false; hostWantsInfo = false; sentInfo.clear(); options.clear(); entered = false; heldKeys.clear(); heldButtons.clear(); clipboard.clear(); clipboardPartial.clear();
            // The cores belong to that host session: they reconnect and start over with the next one.
            // A host that never answered had no session: the cores stay and only the host is retried.
            if (c->stage == 2) for (auto& o : conns) if (o.get() != c && o->role != Role::Pending && !o->closed) close(o.get(), "the host connection ended");
            hostRetry = Clock::now() + std::chrono::milliseconds(500); }
        if (c == user) { user = nullptr; }
        if (c == system) { system = nullptr; }
    }

    // ---- host side -------------------------------------------------------------------------
    void connectHost() {
        auto colon = hostAddress.rfind(':'); std::string ip = hostAddress.substr(0, colon), port = colon == std::string::npos ? "24800" : hostAddress.substr(colon + 1);
        addrinfo hints{}, *result = nullptr; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(ip.c_str(), port.c_str(), &hints, &result) || !result) { hostRetry = Clock::now() + std::chrono::seconds(1); return; }
        SOCKET fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); BOOL on = TRUE; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char*>(&on), sizeof(on));
        u_long nb = 1; ioctlsocket(fd, FIONBIO, &nb);
        int ok = ::connect(fd, result->ai_addr, int(result->ai_addrlen)); freeaddrinfo(result);
        if (ok && WSAGetLastError() != WSAEWOULDBLOCK) { closesocket(fd); hostRetry = Clock::now() + std::chrono::milliseconds(500); return; }
        auto c = std::make_unique<Conn>(); c->fd = fd; c->role = Role::Host; c->connecting = ok != 0; c->ssl = SSL_new(context); SSL_set_fd(c->ssl, int(fd)); SSL_set_connect_state(c->ssl);
        host = c.get(); conns.push_back(std::move(c)); emit("connecting to the host " + hostAddress);
    }
    void fromHost(const std::string& m) {
        std::string k = code(m);
        if (host->stage == 0) {
            if (m.compare(0, 7, "Barrier") != 0) return close(host, "not a Barrier host");
            host->send("Barrier" + u16(1) + u16(6) + u32(uint32_t(screenName.size())) + screenName); host->stage = 2; emit("host connected"); return;
        }
        if (k == "CALV") { host->send("CALV"); return; }
        if (k == "QINF") { hostWantsInfo = true; sentInfo.clear(); sendInfo(); return; }
        if (k == "CIAK") { hostReady = true; return; }
        if (k == "CROP") { options.clear(); toCores(m, true); return; }
        if (k == "DSOP") { options = m; toCores(m, true); return; }
        if (k == "CBYE" || k == "EBSY" || k == "EUNK" || k == "EBAD" || k == "EICV") { emit("host said " + k); return close(host, "host said " + k); }
        if (k == "CINN" && m.size() >= 14) { entered = true; x = sget16(m, 4); y = sget16(m, 6); seq = get32(m, 8); mask = get16(m, 12); toActive(m); return; }
        if (k == "COUT") { entered = false; heldKeys.clear(); heldButtons.clear(); toActive(m); return; }
        if (k == "DMMV" && m.size() >= 8) { x = sget16(m, 4); y = sget16(m, 6); toActive(m); return; }
        if (k == "DMRM" && m.size() >= 8) { x = int16_t(x + sget16(m, 4)); y = int16_t(y + sget16(m, 6)); toActive(m); return; }
        if (k == "DKDN" && m.size() >= 10) { heldKeys[get16(m, 8)] = m; toActive(m); return; }
        if (k == "DKUP" && m.size() >= 10) { heldKeys.erase(get16(m, 8)); toActive(m); return; }
        if (k == "DMDN" && m.size() >= 5) { heldButtons.insert(uint8_t(m[4])); toActive(m); return; }
        if (k == "DMUP" && m.size() >= 5) { heldButtons.erase(uint8_t(m[4])); toActive(m); return; }
        if (k == "DCLP" && m.size() >= 10) {
            unsigned id = uint8_t(m[4]), mark = uint8_t(m[9]); auto& part = clipboardPartial[id];
            if (mark == 1) part.clear();
            part.push_back(m);
            if (mark == 3) { clipboard[id] = part; part.clear(); }
            toUser(m); return;
        }
        if (k == "CCLP" || k == "FCAP" || k.compare(0, 2, "FC") == 0 || k.compare(0, 3, "NDF") == 0) { toUser(m); return; }
        toActive(m);
    }
    static std::string describeInfo(const std::string& m) {
        if (m.size() < 18) return "(short)";
        return std::to_string(sget16(m, 4)) + "," + std::to_string(sget16(m, 6)) + " " + std::to_string(sget16(m, 8)) + "x" + std::to_string(sget16(m, 10))
            + " cursor " + std::to_string(sget16(m, 14)) + "," + std::to_string(sget16(m, 16));
    }
    void sendInfo() {
        Conn* source = shapeSource();
        if (!host || host->stage != 2 || !hostWantsInfo || !source || source->dinf.empty()) return;
        if (source->dinf == sentInfo) return;
        sentInfo = source->dinf; host->send(sentInfo); hostReady = false; emit("host given the " + std::string(name(source->role)) + " info " + describeInfo(sentInfo));
    }

    // ---- core side -------------------------------------------------------------------------
    // Options for a core: the system core never shares the clipboard or files.
    std::string optionsFor(Conn* c) {
        if (options.empty() || c->role != Role::System) return options;
        uint32_t count = get32(options, 4); std::string body;
        uint32_t kept = 0;
        for (uint32_t i = 0; i + 1 < count && 8 + 8 * (i / 2) + 8 <= options.size(); i += 2) {
            size_t at = 8 + 4 * i; std::string option = options.substr(at, 4); uint32_t value = get32(options, at + 4);
            if (option == "FRSM") continue;
            if (option == "CLPS") value = 0;
            body += option + u32(value); kept += 2;
        }
        return "DSOP" + u32(kept) + body;
    }
    void toCores(const std::string& m, bool options) {
        for (Conn* c : {user, system}) if (c && c->stage == 2) c->send(options && code(m) == "DSOP" ? optionsFor(c) : m);
    }
    void toActive(const std::string& m) { Conn* c = active(); if (c && c->stage == 2) c->send(m); }
    void toUser(const std::string& m) { if (user && user->stage == 2) user->send(m); }
    void coreReady(Conn* c) {
        c->stage = 2; emit(std::string(name(c->role)) + " ready");
        c->send("CIAK"); c->send("CROP"); if (!options.empty()) c->send(optionsFor(c));
        if (c->role == Role::User) for (auto& item : clipboard) for (auto& m : item.second) c->send(m);
        if (!host) { hostRetry = Clock::now(); }
        sendInfo();
        if (c == active() && entered) c->send("CINN" + u16(uint16_t(x)) + u16(uint16_t(y)) + u32(seq) + u16(mask));
    }
    void fromCore(Conn* c, const std::string& m) {
        std::string k = code(m);
        if (c->stage == 0) {
            if (m.compare(0, 7, "Barrier") != 0) return close(c, "not a Barrier core");
            c->send("QINF"); c->stage = 1; return;
        }
        // A core that sends new info ignores the mouse until it is acknowledged: the relay answers it
        // (the host's own CIAK goes to the relay, not to the core).
        if (k == "DINF") { c->dinf = m; if (c->stage == 1) coreReady(c); else { c->send("CIAK"); sendInfo(); } emit(std::string(name(c->role)) + " info " + describeInfo(m)); return; }
        if (c->stage != 2) return;
        if (k == "CALV" || k == "CNOP") return;
        bool userData = k == "CCLP" || k == "DCLP" || k == "FCAP" || k.compare(0, 2, "FC") == 0 || k.compare(0, 3, "NDF") == 0;
        if (userData) { if (c->role == Role::User && host && host->stage == 2) host->send(m); return; }
        if (c == active() && host && host->stage == 2) host->send(m);
    }
    void secured(Conn* c) {
        c->secured = true;
        std::string fp = fingerprintOf(c->ssl);
        if (c->role == Role::Host) {
            if (!trustedHosts.count(fp)) { emit("host certificate not approved: " + fp); hostRetry = Clock::now() + std::chrono::seconds(2); return close(c, "untrusted host"); }
            return;
        }
        Role role = fp == userFp ? Role::User : fp == systemFp ? Role::System : Role::Pending;
        if (role == Role::Pending) { emit("refused a local connection with an unknown certificate"); return close(c, "unknown core"); }
        // The same core again (it restarted): the new connection replaces the old one.
        Conn*& slot = role == Role::User ? user : system;
        if (slot) close(slot, "replaced by a new connection");
        c->role = role; slot = c; emit(std::string(name(role)) + " connected");
        c->send("Barrier" + u16(1) + u16(6));
    }

    // ---- routing ---------------------------------------------------------------------------
    void setRoute(Role to) {
        if (to == route) return;
        Conn* from = active(); route = to; Conn* next = active();
        emit(std::string("route: ") + (to == Role::System ? "system" : "user") + " desktop");
        if (!entered) return;
        if (from && from->stage == 2) {
            // Nothing stays pressed on the desktop being left.
            for (auto& key : heldKeys) from->send("DKUP" + key.second.substr(4, 6));
            for (unsigned b : heldButtons) from->send("DMUP" + std::string(1, char(b)));
            from->send("COUT");
        }
        if (next && next->stage == 2) next->send("CINN" + u16(uint16_t(x)) + u16(uint16_t(y)) + u32(seq) + u16(mask));
        // Keys still held on the host go up on the new core, which never saw them go down; nothing to send.
        heldKeys.clear(); heldButtons.clear();
    }

    // ---- I/O -------------------------------------------------------------------------------
    void pump(Conn* c, bool readable, bool writable, bool failed) {
        if (c->connecting) {
            if (failed) { hostRetry = Clock::now() + std::chrono::milliseconds(500); return close(c, "host not reachable"); }
            if (!writable) { if (Clock::now() - c->lastSeen > std::chrono::seconds(5)) { hostRetry = Clock::now(); close(c, "host did not answer"); } return; }
            c->connecting = false; c->lastSeen = Clock::now();
        }
        if (!c->secured) {
            int r = c->server ? SSL_accept(c->ssl) : SSL_connect(c->ssl);
            if (r == 1) secured(c);
            else { int e = SSL_get_error(c->ssl, r); if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) return close(c, "TLS handshake failed"); }
            if (c->closed || !c->secured) return;
        }
        if (readable || SSL_pending(c->ssl)) {
            char buffer[65536];
            for (;;) {
                int n = SSL_read(c->ssl, buffer, sizeof(buffer));
                if (n > 0) { c->in.append(buffer, n); c->lastSeen = Clock::now(); if (c->in.size() > kMaxFrame + 4) return close(c, "message too large"); continue; }
                int e = SSL_get_error(c->ssl, n); if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) break;
                return close(c, "connection closed");
            }
            while (c->in.size() >= 4) {
                uint32_t size = get32(c->in, 0); if (size > kMaxFrame) return close(c, "message too large");
                if (c->in.size() < size + 4) break;
                std::string m = c->in.substr(4, size); c->in.erase(0, size + 4);
                if (c->role == Role::Host) fromHost(m); else fromCore(c, m);
                if (c->closed) return;
            }
        }
        flush(c);
    }
    void flush(Conn* c) {
        while (!c->closed && c->secured && !c->out.empty()) {
            int n = SSL_write(c->ssl, c->out.data(), int(std::min<size_t>(c->out.size(), 1 << 20)));
            if (n > 0) { c->out.erase(0, n); continue; }
            int e = SSL_get_error(c->ssl, n); if (e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_WANT_READ) break;
            close(c, "write failed (" + std::to_string(e) + " " + std::to_string(ERR_get_error()) + ")");
        }
    }
    void run() {
        for (;;) {
            { std::lock_guard<std::mutex> lock(commandMutex);
              while (!commands.empty()) { std::string line = commands.front(); commands.pop_front();
                if (line == "ROUTE user") setRoute(Role::User); else if (line == "ROUTE system") setRoute(Role::System); else if (line == "QUIT") quit = true; } }
            if (quit) return;
            if (!host && (user || system) && Clock::now() >= hostRetry) connectHost();
            // Keep-alives to the cores (the host's are answered as they come).
            for (auto& c : conns) if (!c->closed && c->role != Role::Host && c->stage == 2 && Clock::now() - c->lastAlive > std::chrono::seconds(3)) { c->send("CALV"); c->lastAlive = Clock::now(); }
            for (auto& c : conns) if (!c->closed && !c->connecting && Clock::now() - c->lastSeen > std::chrono::seconds(c->role == Role::Host ? 15 : 12)) close(c.get(), "no keep-alive");
            fd_set reads, writes, errors; FD_ZERO(&reads); FD_ZERO(&writes); FD_ZERO(&errors); FD_SET(listener, &reads);
            for (auto& c : conns) if (!c->closed) { FD_SET(c->fd, &reads); FD_SET(c->fd, &errors); if (!c->out.empty() || !c->secured || c->connecting) FD_SET(c->fd, &writes); }
            timeval wait{0, 20000}; select(0, &reads, &writes, &errors, &wait);
            if (FD_ISSET(listener, &reads)) {
                sockaddr_in from{}; int length = sizeof(from); SOCKET fd = accept(listener, reinterpret_cast<sockaddr*>(&from), &length);
                if (fd != INVALID_SOCKET) {
                    u_long nb = 1; ioctlsocket(fd, FIONBIO, &nb); BOOL on = TRUE; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char*>(&on), sizeof(on));
                    auto c = std::make_unique<Conn>(); c->fd = fd; c->server = true; c->ssl = SSL_new(context); SSL_set_fd(c->ssl, int(fd)); SSL_set_accept_state(c->ssl);
                    conns.push_back(std::move(c));
                }
            }
            for (size_t i = 0; i < conns.size(); ++i) { Conn* c = conns[i].get(); if (!c->closed) pump(c, FD_ISSET(c->fd, &reads) != 0, FD_ISSET(c->fd, &writes) != 0, FD_ISSET(c->fd, &errors) != 0); }
            for (auto& c : conns) if (!c->closed && !c->connecting) flush(c.get());
            conns.erase(std::remove_if(conns.begin(), conns.end(), [](const std::unique_ptr<Conn>& c) { return c->closed; }), conns.end());
        }
    }
};
}

int main(int argc, char** argv) {
    Relay relay; std::string profile;
    for (int i = 1; i + 1 < argc; i += 2) {
        std::string a = argv[i], v = argv[i + 1];
        if (a == "--profile") profile = v; else if (a == "--host") relay.hostAddress = v; else if (a == "--listen") relay.listenPort = static_cast<unsigned short>(std::stoi(v));
        else if (a == "--user-core") relay.userFp = v; else if (a == "--system-core") relay.systemFp = v; else if (a == "--name") relay.screenName = v;
        else if (a == "--log") logFile.open(v, std::ios::app);
        else { std::fprintf(stderr, "unknown option %s\n", a.c_str()); return 2; }
    }
    if (profile.empty() || relay.hostAddress.empty() || relay.screenName.empty() || relay.userFp.empty()) { std::fprintf(stderr, "usage: see Relay.cpp\n"); return 2; }
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    relay.context = SSL_CTX_new(TLS_method());
    if (relay.context) SSL_CTX_set_min_proto_version(relay.context, TLS1_2_VERSION);
    // The outgoing buffer grows while a write waits (a file on the way): a retried SSL_write may see
    // it moved or longer. Without these modes OpenSSL fails the retry and the connection drops.
    SSL_CTX_set_mode(relay.context, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);
    std::string pem = profile + "\\SSL\\Barrier.pem";
    if (SSL_CTX_use_certificate_chain_file(relay.context, pem.c_str()) != 1 || SSL_CTX_use_PrivateKey_file(relay.context, pem.c_str(), SSL_FILETYPE_PEM) != 1) { emit("cannot load " + pem); return 1; }
    // Peers prove themselves with a certificate; the fingerprint is checked after the handshake.
    SSL_CTX_set_verify(relay.context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, [](int, X509_STORE_CTX*) { return 1; });
    relay.trustedHosts = readTrust(profile + "\\SSL\\Fingerprints\\TrustedServers.txt");
    if (relay.trustedHosts.empty()) { emit("no approved host"); return 1; }
    relay.listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in local{}; local.sin_family = AF_INET; local.sin_port = htons(relay.listenPort); local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    BOOL exclusive = TRUE; setsockopt(relay.listener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<char*>(&exclusive), sizeof(exclusive));
    if (bind(relay.listener, reinterpret_cast<sockaddr*>(&local), sizeof(local)) || listen(relay.listener, 4)) { emit("cannot listen on 127.0.0.1:" + std::to_string(relay.listenPort)); return 1; }
    int length = sizeof(local); getsockname(relay.listener, reinterpret_cast<sockaddr*>(&local), &length);
    u_long nb = 1; ioctlsocket(relay.listener, FIONBIO, &nb);
    emit("listening on 127.0.0.1:" + std::to_string(ntohs(local.sin_port)));
    std::thread([&relay] { std::string line; while (std::getline(std::cin, line)) { while (!line.empty() && line.back() == '\r') line.pop_back(); std::lock_guard<std::mutex> lock(relay.commandMutex); relay.commands.push_back(line); } std::lock_guard<std::mutex> lock(relay.commandMutex); relay.commands.push_back("QUIT"); }).detach();
    relay.run();
    return 0;
}
