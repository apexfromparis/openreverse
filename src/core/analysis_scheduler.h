#pragma once

#include "core/cancellation.h"

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace openreverse {

enum class AnalysisJobState {
    Queued,
    Running,
    Completed,
    Cancelled,
    Failed
};

struct AnalysisJobSnapshot {
    uint64_t id = 0;
    std::string name;
    AnalysisJobState state = AnalysisJobState::Queued;
    float progress = 0.0f;
    std::string error;
};

class AnalysisScheduler {
public:
    using Completion = std::function<void()>;
    using ProgressCallback = std::function<void(float)>;
    using Work = std::function<Completion(const CancellationToken&, const ProgressCallback&)>;

    AnalysisScheduler();
    ~AnalysisScheduler();

    AnalysisScheduler(const AnalysisScheduler&) = delete;
    AnalysisScheduler& operator=(const AnalysisScheduler&) = delete;

    uint64_t Submit(std::string name, Work work);
    void Cancel(uint64_t id);
    void CancelAllAndWait();
    void DrainCompletions();
    AnalysisJobSnapshot GetJob(uint64_t id) const;
    void Shutdown();

private:
    struct Job {
        uint64_t id = 0;
        std::string name;
        Work work;
        CancellationSource cancellation;
        AnalysisJobState state = AnalysisJobState::Queued;
        float progress = 0.0f;
        std::string error;
    };

    struct PendingCompletion {
        std::shared_ptr<Job> job;
        Completion callback;
    };

    void WorkerLoop();

    mutable std::mutex mutex_;
    std::condition_variable workReady_;
    std::condition_variable idle_;
    std::deque<std::shared_ptr<Job>> queue_;
    std::deque<PendingCompletion> completions_;
    std::map<uint64_t, std::shared_ptr<Job>> jobs_;
    std::thread worker_;
    uint64_t nextId_ = 1;
    bool active_ = false;
    bool stopping_ = false;
};

} // namespace openreverse
