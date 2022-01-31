#include "ctrlc.h"

#include <atomic>
#include <csignal>


namespace {

std::atomic<bool> Stopped = false;
std::atomic<int> SigIntsLeft = 0;

} // namespace

namespace util {

void HandleSigInt(int maxtries) {
    SigIntsLeft.store(maxtries);
    ::signal(SIGINT, +[](int) {
        if (SigIntsLeft.fetch_sub(1) <= 1) {
            ::signal(SIGINT, SIG_DFL);
        }
        Stopped.store(true, std::memory_order_release);
    });
}

bool WasInterrupted() {
    return Stopped.load(std::memory_order_acquire);
}

} // namespace util
