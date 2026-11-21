// SPDX-License-Identifier: GPL-2.0-or-later
#include "FileClipboardTransfer.h"
#include "NativeFileTransfer.h"
#include "ProtocolUtil.h"
#include "common/DataDirectories.h"
#include "base/Log.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <deque>
#include <fstream>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>

namespace barrier {
namespace {
constexpr size_t chunkSize = 64 * 1024;
constexpr const char* begin = "FCBG%4i%1i%4i";
constexpr const char* entry = "FCEN%4i%1i%s%s";
constexpr const char* chunk = "FCHK%4i%s";
constexpr const char* fileEnd = "FCFE%4i%s";
constexpr const char* done = "FCDN%4i";
constexpr const char* ack = "FCAK%4i%4i";
constexpr const char* abort = "FCAB%4i";
constexpr const char* rejected = "FCNO%4i%s";
// Resumable offer: same fields as FCBG plus the 64-hex key of the selection (paths, sizes and
// modification times of every entry). The receiver answers FCRS instead of the first FCAK:
// entries it already holds (N), SHA-256 over their "relative\nsize\n" lines, and the bytes it
// holds of entry N+1 (decimal; 0 when none).
constexpr const char* beginResume = "FCBR%4i%1i%4i%s";
constexpr const char* resumeAt = "FCRS%4i%4i%s%s";
constexpr auto keepResume = std::chrono::hours(24);
std::atomic<bool> freshNextSend{false};
std::mutex registryMutex;
std::map<std::string, std::shared_ptr<const ClipboardFiles>> registry;
std::deque<std::string> history;
// Selection (paths, sizes, modification times) -> handle, so reading an unchanged
// clipboard again yields the same handle. Otherwise every screen switch looked like a
// new copy to the server, which cancelled and restarted a transfer still in progress.
std::map<std::string, std::string> handleBySelection;
std::string randomName() {
    unsigned char bytes[16];
    if (RAND_bytes(bytes, sizeof(bytes)) != 1) throw std::runtime_error("Cannot create transfer identity");
    const char* hex = "0123456789abcdef"; std::string result;
    for (auto b : bytes) { result += hex[b >> 4]; result += hex[b & 15]; }
    return result;
}
uint64_t number(const std::string& value) {
    if (value.empty() || value.size() > 20) throw std::runtime_error("Invalid file size");
    uint64_t result = 0;
    for (char c : value) {
        if (c < '0' || c > '9' || result > (UINT64_MAX - (c - '0')) / 10) throw std::runtime_error("Invalid file size");
        result = result * 10 + (c - '0');
    }
    return result;
}
void safeRelative(const std::string& path) {
    if (path.empty() || path.size() > 32768) throw std::runtime_error("Unsupported file path");
    size_t start = 0, depth = 0;
    while (start < path.size()) {
        auto slash = path.find('/', start);
        auto name = path.substr(start, slash == std::string::npos ? slash : slash - start);
        if (!nativeFilenameValid(name) || ++depth > 128) throw std::runtime_error("Unsupported file name or folder depth");
        if (slash == std::string::npos) return;
        start = slash + 1;
    }
    throw std::runtime_error("Invalid trailing path separator");
}
// Throttled progress line; the desktop apps read it from the log to show the transferred size and speed.
void progress(const char* verb, uint64_t total, std::chrono::steady_clock::time_point& last) {
    auto now = std::chrono::steady_clock::now();
    if (now - last < std::chrono::milliseconds(500)) return;
    last = now;
    LOG((CLOG_INFO "file clipboard: progress %s %s bytes", verb, std::to_string(total).c_str()));
}
bool validKey(const std::string& key) {
    if (key.size() != 64) return false;
    for (char c : key) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}
std::string hex(const std::string& bytes) {
    const char* digits = "0123456789abcdef"; std::string result;
    for (unsigned char b : bytes) { result += digits[b >> 4]; result += digits[b & 15]; }
    return result;
}
// Keeps at most the partial copy for `key` (none when empty), and none older than a day.
void pruneResume(const fs::path& folder, const std::string& key) {
    std::error_code ec;
    if (!fs::is_directory(folder, ec)) return;
    auto now = fs::file_time_type::clock::now();
    for (fs::directory_iterator i(folder, ec), end; !ec && i != end; i.increment(ec)) {
        auto name = i->path().filename().u8string();
        std::error_code age;
        auto stamp = fs::last_write_time(i->path() / "entries.txt", age);
        if (name == key && !age && now - stamp < keepResume) continue;
        std::error_code ignored; fs::remove_all(i->path(), ignored);
    }
}
struct Digest {
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    Digest() { if (!context || EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1) { EVP_MD_CTX_free(context); throw std::runtime_error("Cannot initialize SHA-256"); } }
    ~Digest() { EVP_MD_CTX_free(context); }
    void add(const std::string& bytes) { if (EVP_DigestUpdate(context, bytes.data(), bytes.size()) != 1) throw std::runtime_error("Cannot hash file"); }
    std::string finish() {
        unsigned char value[EVP_MAX_MD_SIZE]; unsigned length = 0;
        if (EVP_DigestFinal_ex(context, value, &length) != 1 || length != 32) throw std::runtime_error("Cannot finish SHA-256");
        return std::string(reinterpret_cast<char*>(value), length);
    }
};
}

std::string registerClipboardFiles(const std::vector<fs::path>& paths) {
    if (paths.empty() || paths.size() > 4096) throw std::runtime_error("Select between 1 and 4096 files or folders");
    auto files = std::make_shared<ClipboardFiles>(); std::set<std::string> names;
    for (const auto& path : paths) {
        auto absolute = fs::absolute(path).lexically_normal();
        auto name = absolute.filename().u8string(); safeRelative(name);
        // File type/existence is validated by the disk worker immediately before opening.
        std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return c < 128 ? std::tolower(c) : c; });
        if (!names.insert(name).second) throw std::runtime_error("Selected items have conflicting names");
        files->roots.push_back(absolute);
    }
    std::string selection;
    for (const auto& root : files->roots) {
        std::error_code ec;
        auto modified = fs::last_write_time(root, ec).time_since_epoch().count();
        auto size = fs::is_regular_file(root, ec) ? fs::file_size(root, ec) : 0;
        selection += root.u8string() + '\n' + std::to_string(modified) + ' ' + std::to_string(size) + '\n';
    }
    std::lock_guard<std::mutex> lock(registryMutex);
    auto known = handleBySelection.find(selection);
    if (known != handleBySelection.end() && registry.count(known->second)) return known->second;
    auto handle = "FLOCAL2:" + randomName();
    registry[handle] = files; history.push_back(handle); handleBySelection[selection] = handle;
    while (history.size() > 32) {
        registry.erase(history.front()); history.pop_front();
        for (auto i = handleBySelection.begin(); i != handleBySelection.end();) i = registry.count(i->second) ? std::next(i) : handleBySelection.erase(i);
    }
    return handle;
}
std::shared_ptr<const ClipboardFiles> clipboardFiles(const std::string& handle) {
    std::lock_guard<std::mutex> lock(registryMutex);
    auto found = registry.find(handle);
    if (found == registry.end()) throw std::runtime_error("File clipboard expired; copy the selection again");
    return found->second;
}

struct FileClipboardTransfer::Impl {
    IStream* stream; Completed completed; fs::path cache;
    struct Sender {
        uint32_t id; ClipboardID clipboard; uint32_t sequence, packet = 0;
        std::shared_ptr<const ClipboardFiles> files;
        size_t root = 0;
        std::unique_ptr<fs::recursive_directory_iterator> iterator;
        std::ifstream input; std::unique_ptr<Digest> digest;
        fs::path path; uint64_t size = 0, sent = 0, total = 0;
        fs::file_time_type modified;
        std::chrono::steady_clock::time_point reported = std::chrono::steady_clock::now();
        bool endingFile = false, endingTransfer = false, awaitingResume = false;
        bool next(fs::path& absolute, std::string& relative) {
            if (iterator) {
                if (*iterator != fs::recursive_directory_iterator{}) {
                    if (iterator->depth() > 126) throw std::runtime_error("Folder nesting is too deep");
                    absolute = (**iterator).path();
                    relative = (files->roots[root].filename() / absolute.lexically_relative(files->roots[root])).generic_u8string();
                    ++*iterator; return true;
                }
                iterator.reset(); ++root;
            }
            if (root == files->roots.size()) return false;
            absolute = files->roots[root]; relative = absolute.filename().u8string();
            if (fs::is_directory(fs::symlink_status(absolute))) iterator.reset(new fs::recursive_directory_iterator(absolute));
            else ++root;
            return true;
        }
    };
    // Key of a selection for resuming: every entry's path, kind, size and modification time.
    static std::string resumeKey(const std::shared_ptr<const ClipboardFiles>& files) {
        Sender walk; walk.files = files; Digest key; key.add("cursorway-resume-1\n");
        fs::path path; std::string relative; size_t count = 0;
        while (walk.next(path, relative)) {
            if (++count > 1000000) throw std::runtime_error("Too many entries");
            std::error_code ec; auto status = fs::symlink_status(path, ec);
            bool folder = fs::is_directory(status);
            auto size = folder ? 0 : fs::file_size(path, ec);
            auto modified = fs::last_write_time(path, ec).time_since_epoch().count();
            key.add(relative + '\n' + (folder ? "d " : "f ") + std::to_string(size) + ' ' + std::to_string(modified) + '\n');
        }
        return hex(key.finish());
    }
    struct Receiver {
        uint32_t id; ClipboardID clipboard; uint32_t sequence, packet = 0;
        fs::path directory, current; std::vector<fs::path> roots;
        // Resumable transfers live in cache/resume/<key>/: data/, entries.txt (finished entries,
        // "size<TAB>relative" per line) and current.txt (the file being written, same form).
        fs::path resume; std::string currentLine; bool keep = false;
        std::ofstream output; std::unique_ptr<Digest> digest;
        uint64_t size = 0, received = 0, total = 0; size_t entries = 0;
        std::chrono::steady_clock::time_point reported = std::chrono::steady_clock::now();
        bool committed = false;
        ~Receiver() {
            output.close(); if (committed) return;
            std::error_code ec;
            if (resume.empty()) fs::remove_all(directory, ec);
            else if (!keep) fs::remove_all(resume, ec);
        }
        void finished(const std::string& relative, uint64_t bytes) {
            if (resume.empty()) return;
            std::ofstream log; open_utf8_path(log, resume / "entries.txt", std::ios::binary | std::ios::app);
            log << bytes << '\t' << relative << '\n'; log.close();
            if (!log) throw std::runtime_error("Cannot record transfer progress");
            std::error_code ec; fs::remove(resume / "current.txt", ec);
        }
    };
    std::unique_ptr<Sender> tx;
    std::unique_ptr<Receiver> rx;
    Impl(IStream* s, Completed c, fs::path p) : stream(s), completed(std::move(c)), cache(std::move(p)) {
        std::error_code ec;
        if (fs::exists(cache / discardResumeMarker, ec)) {
            fs::remove(cache / discardResumeMarker, ec); fs::remove_all(cache / "resume", ec);
            freshNextSend = true;
            LOG((CLOG_INFO "file clipboard: transfer was cancelled; partial copies removed"));
        }
    }
    // Disconnected (not cancelled): keep the partial copy so the same selection can resume.
    ~Impl() { if (rx && !rx->resume.empty()) rx->keep = true; }
    // Sender: skip what the receiver already holds, then continue in the middle of entry N+1.
    void skip(uint32_t entries, const std::string& listed, uint64_t partial) {
        auto& s = *tx; Digest list; fs::path path; std::string relative; uint64_t present = 0;
        for (uint32_t i = 0; i < entries; ++i) {
            if (!s.next(path, relative)) throw std::runtime_error("Resume point is past the selection; copy again");
            auto status = fs::symlink_status(path);
            uint64_t size = fs::is_directory(status) ? 0 : fs::file_size(path);
            list.add(relative + '\n' + std::to_string(size) + '\n'); present += size;
        }
        if (list.finish() != listed) throw std::runtime_error("Resume point does not match the selection; copy again");
        if (partial) {
            if (!s.next(path, relative) || !fs::is_regular_file(fs::symlink_status(path)) || fs::file_size(path) < partial)
                throw std::runtime_error("Resume point does not match the selection; copy again");
            s.path = path; s.size = fs::file_size(path); s.modified = fs::last_write_time(path);
            open_utf8_path(s.input, path, std::ios::binary);
            if (!s.input) throw std::runtime_error("Cannot open source file");
            s.digest.reset(new Digest);
            for (uint64_t done = 0; done < partial;) {
                std::string bytes(static_cast<size_t>(std::min<uint64_t>(chunkSize, partial - done)), '\0');
                if (!s.input.read(&bytes[0], bytes.size())) throw std::runtime_error("Source file changed or became unreadable");
                s.digest->add(bytes); done += bytes.size();
            }
            s.sent = partial; present += partial;
        }
        s.total = present;
        if (entries || partial)
            LOG((CLOG_INFO "file clipboard: resuming at %u items, %s bytes", entries, std::to_string(present).c_str()));
    }
    // Receiver: open or create cache/resume/<key>; returns the FCRS fields.
    void resumeReceiver(Receiver& r, const std::string& key, uint32_t& entries, std::string& listed, uint64_t& partial) {
        auto folder = cache / "resume"; pruneResume(folder, key);
        r.resume = folder / key; r.directory = r.resume / "data";
        fs::create_directories(r.directory);
#if !SYSAPI_WIN32
        fs::permissions(folder, fs::perms::owner_all, fs::perm_options::replace);
        fs::permissions(r.resume, fs::perms::owner_all, fs::perm_options::replace);
#endif
        Digest list; entries = 0; partial = 0; uint64_t present = 0;
        auto parse = [](const std::string& line, uint64_t& size, std::string& relative) {
            auto tab = line.find('\t'); if (tab == std::string::npos) return false;
            try { size = number(line.substr(0, tab)); relative = line.substr(tab + 1); safeRelative(relative); } catch (const std::exception&) { return false; }
            return true;
        };
        {
            std::ifstream log; open_utf8_path(log, r.resume / "entries.txt", std::ios::binary);
            std::string line; uint64_t size; std::string relative;
            while (log && std::getline(log, line)) {
                if (!parse(line, size, relative)) break;
                list.add(relative + '\n' + std::to_string(size) + '\n'); present += size; ++entries;
                if (relative.find('/') == std::string::npos) r.roots.push_back(fs::u8path(relative));
            }
        }
        std::ofstream touch; open_utf8_path(touch, r.resume / "entries.txt", std::ios::binary | std::ios::app); touch.close();
        r.entries = entries; listed = list.finish();
        std::ifstream current; open_utf8_path(current, r.resume / "current.txt", std::ios::binary);
        std::string line; uint64_t size = 0; std::string relative;
        if (current && std::getline(current, line) && parse(line, size, relative)) {
            current.close();
            auto path = r.directory / fs::u8path(relative); std::error_code ec;
            // What is on disk is what counts: a write cut off by the disconnect shortens it.
            uint64_t have = fs::is_regular_file(path, ec) ? fs::file_size(path, ec) : 0;
            if (ec || have == 0 || have > size) { fs::remove(path, ec); fs::remove(r.resume / "current.txt", ec); }
            else {
                fs::resize_file(path, have);
                std::ifstream input; open_utf8_path(input, path, std::ios::binary);
                r.digest.reset(new Digest);
                for (uint64_t done = 0; done < have;) {
                    std::string bytes(static_cast<size_t>(std::min<uint64_t>(chunkSize, have - done)), '\0');
                    if (!input.read(&bytes[0], bytes.size())) throw std::runtime_error("Cannot read partial file");
                    r.digest->add(bytes); done += bytes.size();
                }
                input.close();
                open_utf8_path(r.output, path, std::ios::binary | std::ios::app);
                if (!r.output) throw std::runtime_error("Cannot reopen partial file");
                if (relative.find('/') == std::string::npos) r.roots.push_back(fs::u8path(relative));
                r.current = path; r.size = size; r.received = have; r.currentLine = line; ++r.entries;
                partial = have; present += have;
            }
        } else { current.close(); std::error_code ec; fs::remove(r.resume / "current.txt", ec); }
        r.total = present;
    }
    void advance() {
        auto& s = *tx;
        if (s.endingTransfer) { LOG((CLOG_INFO "file clipboard: sent %s bytes", std::to_string(s.total).c_str())); tx.reset(); return; }
        if (s.endingFile) { s.input.close(); s.digest.reset(); s.endingFile = false; }
        if (s.input.is_open()) {
            if (s.sent < s.size) {
                std::string bytes(static_cast<size_t>(std::min<uint64_t>(chunkSize, s.size - s.sent)), '\0');
                if (!s.input.read(&bytes[0], bytes.size())) throw std::runtime_error("Source file changed or became unreadable");
                s.digest->add(bytes); s.sent += bytes.size(); s.total += bytes.size(); progress("sent", s.total, s.reported);
                ProtocolUtil::writef(stream, chunk, s.id, &bytes); return;
            }
            if (s.input.peek() != EOF || fs::last_write_time(s.path) != s.modified || fs::file_size(s.path) != s.size)
                throw std::runtime_error("Source file changed while copying; copy again");
            auto hash = s.digest->finish(); s.endingFile = true;
            ProtocolUtil::writef(stream, fileEnd, s.id, &hash); return;
        }
        fs::path path; std::string relative;
        if (!s.next(path, relative)) { s.endingTransfer = true; ProtocolUtil::writef(stream, done, s.id); return; }
        safeRelative(relative);
        auto status = fs::symlink_status(path);
        UInt8 kind = fs::is_directory(status) ? 2 : 1;
        if (kind == 1 && !fs::is_regular_file(status)) throw std::runtime_error("Links and special files are not supported");
        std::string length = "0";
        if (kind == 1) {
            s.path = path; s.size = fs::file_size(path); s.sent = 0; s.modified = fs::last_write_time(path);
            open_utf8_path(s.input, path, std::ios::binary);
            if (!s.input) throw std::runtime_error("Cannot open source file");
            s.digest.reset(new Digest); length = std::to_string(s.size);
        }
        ProtocolUtil::writef(stream, entry, s.id, kind, &relative, &length);
    }
    void cancel() {
        if (tx) { ProtocolUtil::writef(stream, abort, tx->id); tx.reset(); }
        if (rx) { std::string reason = "Clipboard changed or transfer cancelled"; ProtocolUtil::writef(stream, rejected, rx->id, &reason); rx.reset(); }
    }
};

FileClipboardTransfer::FileClipboardTransfer(IStream* stream, Completed c, const fs::path& cache) :
    impl_(new Impl(stream, std::move(c), cache.empty() ? DataDirectories::profile() / "FileClipboardCache" : cache)) {}
FileClipboardTransfer::~FileClipboardTransfer() = default;
bool FileClipboardTransfer::sending() const { return !!impl_->tx; }
void FileClipboardTransfer::cancel() { impl_->cancel(); }
void FileClipboardTransfer::start(const std::string& handle, ClipboardID clipboard, uint32_t sequence, bool resume) {
    auto& p = *impl_; p.cancel();
    auto source = clipboardFiles(handle);
    auto sender = std::make_unique<Impl::Sender>();
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&sender->id), sizeof(sender->id)) != 1) throw std::runtime_error("Cannot create transfer ID");
    if (!sender->id) sender->id = 1;
    sender->files = source; sender->clipboard = clipboard; sender->sequence = sequence;
    p.tx = std::move(sender);
    LOG((CLOG_INFO "file clipboard: sending %u selected items", static_cast<unsigned>(source->roots.size())));
    if (resume && !freshNextSend.exchange(false)) {
        auto key = Impl::resumeKey(source); p.tx->awaitingResume = true;
        ProtocolUtil::writef(p.stream, beginResume, p.tx->id, clipboard, sequence, &key);
    } else ProtocolUtil::writef(p.stream, begin, p.tx->id, clipboard, sequence);
}
bool FileClipboardTransfer::receive(const unsigned char* code) {
    if (memcmp(code, "FC", 2) != 0) return false;
    auto& p = *impl_; UInt32 id = 0, acknowledgement = 0;
    const bool senderMessage = memcmp(code, ack, 4) == 0 || memcmp(code, rejected, 4) == 0 || memcmp(code, resumeAt, 4) == 0;
    try {
        if (memcmp(code, ack, 4) == 0) {
            UInt32 counter = 0;
            if (!ProtocolUtil::readf(p.stream, ack + 4, &id, &counter)) throw std::runtime_error("Invalid file acknowledgement");
            if (p.tx && p.tx->id == id && counter == p.tx->packet) { p.tx->awaitingResume = false; ++p.tx->packet; p.advance(); }
            return true;
        }
        if (memcmp(code, resumeAt, 4) == 0) {
            UInt32 entries = 0; std::string listed, partial;
            if (!ProtocolUtil::readf(p.stream, resumeAt + 4, &id, &entries, &listed, &partial) || listed.size() != 32)
                throw std::runtime_error("Invalid resume point");
            if (p.tx && p.tx->id == id && p.tx->awaitingResume && p.tx->packet == 0) {
                p.tx->awaitingResume = false; ++p.tx->packet; p.skip(entries, listed, number(partial)); p.advance();
            }
            return true;
        }
        if (memcmp(code, rejected, 4) == 0) {
            std::string reason;
            if (!ProtocolUtil::readf(p.stream, rejected + 4, &id, &reason)) throw std::runtime_error("Invalid file rejection");
            if (p.tx && p.tx->id == id) { LOG((CLOG_WARN "file clipboard: receiver rejected transfer: %.200s", reason.c_str())); p.tx.reset(); }
            return true;
        }
        if (memcmp(code, abort, 4) == 0) {
            if (!ProtocolUtil::readf(p.stream, abort + 4, &id)) throw std::runtime_error("Invalid file cancellation");
            if (p.rx && p.rx->id == id) p.rx.reset();
            return true;
        }
        if (memcmp(code, begin, 4) == 0) {
            ClipboardID clipboard = 0; UInt32 sequence = 0;
            if (!ProtocolUtil::readf(p.stream, begin + 4, &id, &clipboard, &sequence) || !id || clipboard != kClipboardClipboard)
                throw std::runtime_error("Invalid file clipboard offer");
            p.rx.reset();
            auto receive = std::make_unique<Impl::Receiver>(); receive->id = id; receive->clipboard = clipboard; receive->sequence = sequence;
            fs::create_directories(p.cache);
#if !SYSAPI_WIN32
            fs::permissions(p.cache, fs::perms::owner_all, fs::perm_options::replace);
#endif
            receive->directory = p.cache / (randomName() + ".partial");
            if (!fs::create_directory(receive->directory)) throw std::runtime_error("Cannot create receive directory");
#if !SYSAPI_WIN32
            fs::permissions(receive->directory, fs::perms::owner_all, fs::perm_options::replace);
#endif
            p.rx = std::move(receive);
            pruneResume(p.cache / "resume", "");
            LOG((CLOG_INFO "file clipboard: receiving files"));
        } else if (memcmp(code, beginResume, 4) == 0) {
            ClipboardID clipboard = 0; UInt32 sequence = 0; std::string key;
            if (!ProtocolUtil::readf(p.stream, beginResume + 4, &id, &clipboard, &sequence, &key) || !id || clipboard != kClipboardClipboard || !validKey(key))
                throw std::runtime_error("Invalid file clipboard offer");
            p.rx.reset();
            fs::create_directories(p.cache);
#if !SYSAPI_WIN32
            fs::permissions(p.cache, fs::perms::owner_all, fs::perm_options::replace);
#endif
            auto receive = std::make_unique<Impl::Receiver>(); receive->id = id; receive->clipboard = clipboard; receive->sequence = sequence;
            UInt32 entries = 0; std::string listed; uint64_t partial = 0;
            p.rx = std::move(receive);
            p.resumeReceiver(*p.rx, key, entries, listed, partial);
            LOG((CLOG_INFO "file clipboard: receiving files"));
            if (entries || partial) LOG((CLOG_INFO "file clipboard: resuming at %u items, %s bytes", static_cast<unsigned>(entries), std::to_string(p.rx->total).c_str()));
            p.rx->packet++;
            auto held = std::to_string(partial); UInt32 finished = entries;
            ProtocolUtil::writef(p.stream, resumeAt, id, finished, &listed, &held);
            return true;
        } else if (memcmp(code, entry, 4) == 0) {
            UInt8 kind = 0; std::string relative, length;
            if (!ProtocolUtil::readf(p.stream, entry + 4, &id, &kind, &relative, &length)) throw std::runtime_error("Invalid file entry");
            if (!p.rx || id != p.rx->id || p.rx->output.is_open()) throw std::runtime_error("Unexpected file entry");
            auto& r = *p.rx; safeRelative(relative); auto size = number(length);
            if ((kind != 1 && kind != 2) || (kind == 2 && size != 0) || ++r.entries > 1000000) throw std::runtime_error("Invalid entry type or too many entries");
            auto path = r.directory / fs::u8path(relative);
            if (!fs::is_directory(path.parent_path()) || fs::exists(path)) throw std::runtime_error("Conflicting file names or missing parent folder");
            if (relative.find('/') == std::string::npos) {
                if (r.roots.size() == 4096) throw std::runtime_error("Too many selected items");
                r.roots.push_back(fs::u8path(relative));
            }
            if (kind == 2) { fs::create_directory(path); r.finished(relative, 0); }
            else {
                if (!r.resume.empty()) {
                    std::ofstream note; open_utf8_path(note, r.resume / "current.txt", std::ios::binary | std::ios::trunc);
                    r.currentLine = length + '\t' + relative; note << r.currentLine << '\n'; note.close();
                }
                if (fs::space(r.directory).available < size) throw std::runtime_error("Not enough disk space for this file");
                open_utf8_path(r.output, path, std::ios::binary);
                if (!r.output) throw std::runtime_error("Cannot create received file");
                r.current = path; r.size = size; r.received = 0; r.digest.reset(new Digest);
            }
        } else if (memcmp(code, chunk, 4) == 0) {
            std::string bytes;
            if (!ProtocolUtil::readf(p.stream, chunk + 4, &id, &bytes)) throw std::runtime_error("Invalid file chunk");
            if (!p.rx || id != p.rx->id || !p.rx->output.is_open() || bytes.empty() || bytes.size() > chunkSize || bytes.size() > p.rx->size - p.rx->received)
                throw std::runtime_error("Unexpected or oversized file chunk");
            auto& r = *p.rx; r.output.write(bytes.data(), bytes.size());
            if (!r.output) throw std::runtime_error("Cannot write received file; check disk space");
            r.digest->add(bytes); r.received += bytes.size(); r.total += bytes.size(); progress("received", r.total, r.reported);
        } else if (memcmp(code, fileEnd, 4) == 0) {
            std::string hash;
            if (!ProtocolUtil::readf(p.stream, fileEnd + 4, &id, &hash)) throw std::runtime_error("Invalid file completion");
            if (!p.rx || id != p.rx->id || !p.rx->output.is_open() || p.rx->received != p.rx->size || hash.size() != 32 || p.rx->digest->finish() != hash)
                throw std::runtime_error("Received file is incomplete or checksum differs");
            p.rx->output.close();
            if (!p.rx->output) throw std::runtime_error("Cannot finish received file");
            p.rx->digest.reset();
            if (!p.rx->currentLine.empty()) {
                auto tab = p.rx->currentLine.find('\t');
                p.rx->finished(p.rx->currentLine.substr(tab + 1), p.rx->size); p.rx->currentLine.clear();
            }
        } else if (memcmp(code, done, 4) == 0) {
            if (!ProtocolUtil::readf(p.stream, done + 4, &id)) throw std::runtime_error("Invalid clipboard completion");
            if (!p.rx || id != p.rx->id || p.rx->output.is_open() || p.rx->roots.empty()) throw std::runtime_error("Incomplete clipboard transfer");
            auto& r = *p.rx;
            acknowledgement = r.packet;
            auto complete = p.cache / randomName(); fs::rename(r.directory, complete); r.directory = complete;
            if (!r.resume.empty()) { std::error_code ec; fs::remove_all(r.resume, ec); r.resume.clear(); }
            std::vector<fs::path> roots; for (const auto& root : r.roots) roots.push_back(complete / root);
            auto handle = registerClipboardFiles(roots);
            p.completed(r.clipboard, r.sequence, handle); r.committed = true;
            LOG((CLOG_INFO "file clipboard: received and verified %s bytes; %u items ready to paste", std::to_string(r.total).c_str(), static_cast<unsigned>(roots.size())));
            p.rx.reset();
        } else return false;
        if (p.rx) acknowledgement = p.rx->packet++;
        ProtocolUtil::writef(p.stream, ack, id, acknowledgement);
    } catch (const std::exception& e) {
        std::string reason = e.what(); LOG((CLOG_WARN "file clipboard: %s", reason.c_str()));
        if (senderMessage) { if (p.tx) ProtocolUtil::writef(p.stream, abort, p.tx->id); p.tx.reset(); }
        else { ProtocolUtil::writef(p.stream, rejected, id, &reason); p.rx.reset(); }
    }
    return true;
}
}
