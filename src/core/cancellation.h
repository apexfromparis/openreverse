#pragma once

#include <atomic>
#include <memory>
#include <utility>

namespace openreverse {

class CancellationToken {
public:
    CancellationToken() : state_(std::make_shared<std::atomic<bool>>(false)) {}

    bool IsCancellationRequested() const
    {
        return state_ && state_->load(std::memory_order_relaxed);
    }

private:
    explicit CancellationToken(std::shared_ptr<std::atomic<bool>> state) : state_(std::move(state)) {}
    std::shared_ptr<std::atomic<bool>> state_;

    friend class CancellationSource;
};

class CancellationSource {
public:
    CancellationSource() : state_(std::make_shared<std::atomic<bool>>(false)) {}

    CancellationToken Token() const { return CancellationToken(state_); }
    void Cancel() const { state_->store(true, std::memory_order_relaxed); }

private:
    std::shared_ptr<std::atomic<bool>> state_;
};

} // namespace openreverse
