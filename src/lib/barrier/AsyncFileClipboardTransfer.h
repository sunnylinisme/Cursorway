// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "FileClipboardTransfer.h"
#include "base/Event.h"
class IEventQueue;
namespace barrier {
// Disk operations never run on the input/network event thread. The wire protocol is unchanged.
class AsyncFileClipboardTransfer {
public:
    AsyncFileClipboardTransfer(IStream*, FileClipboardTransfer::Completed, IEventQueue*,
                               const fs::path& cache = {}, std::function<void()> beforeOutput = {});
    ~AsyncFileClipboardTransfer();
    void start(const std::string&, ClipboardID, uint32_t);
    // The peer can resume interrupted transfers (FCBR/FCRS).
    void setResume(bool resume) { resume_ = resume; }
    bool receive(const unsigned char*);
    void cancel();
    // Files from the peer are on their way (between its offer and the end).
    bool receiving() const { return incoming_ != 0; }
    // Called on the event thread when the peer begins sending files, before any data arrives.
    // Used to empty the local clipboard so a paste during the transfer cannot paste older content.
    void onIncoming(std::function<void(ClipboardID, uint32_t)> started) { started_ = std::move(started); }
    void poll(); // Also usable by integration tests without an OS event queue.
    static void finishShutdown(int exitCode); // Call before destroying app/queue/log globals.
private:
    struct State;
    std::shared_ptr<State> state_;
    IStream* stream_;
    FileClipboardTransfer::Completed completed_;
    std::function<void(ClipboardID, uint32_t)> started_;
    IEventQueue* events_;
    uint32_t outgoing_ = 0, incoming_ = 0;
    bool resume_ = false;
    void ready(const Event&, void*);
};
}
