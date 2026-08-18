#include "analysis_scheduler.h"

#include <algorithm>
#include <exception>
#include <utility>

namespace openreverse {

AnalysisScheduler::AnalysisScheduler() : worker_(&AnalysisScheduler::WorkerLoop, this) {}

AnalysisScheduler::~AnalysisScheduler()
{
    Shutdown();
}

uint64_t AnalysisScheduler::Submit(std::string name, Work work)
{
    if (!work)
        return 0;

    auto job = std::make_shared<Job>();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopping_)
            return 0;
        constexpr size_t kMaxJobHistory = 256;
        while (jobs_.size() >= kMaxJobHistory)
        {
            const auto finished = std::find_if(jobs_.begin(), jobs_.end(), [](const auto& entry) {
                const auto state = entry.second->state;
                return state == AnalysisJobState::Completed || state == AnalysisJobState::Cancelled ||
                       state == AnalysisJobState::Failed;
            });
            if (finished == jobs_.end()) break;
            jobs_.erase(finished);
        }
        job->id = nextId_++;
        job->name = std::move(name);
        job->work = std::move(work);
        jobs_[job->id] = job;
        queue_.push_back(job);
    }
    workReady_.notify_one();
    return job->id;
}

void AnalysisScheduler::Cancel(uint64_t id)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto found = jobs_.find(id);
    if (found == jobs_.end())
        return;
    found->second->cancellation.Cancel();
    if (found->second->state == AnalysisJobState::Queued)
    {
        found->second->state = AnalysisJobState::Cancelled;
        found->second->work = {};
    }
}

void AnalysisScheduler::CancelAllAndWait()
{
    std::unique_lock<std::mutex> lock(mutex_);
    for (auto& pair : jobs_)
    {
        pair.second->cancellation.Cancel();
        if (pair.second->state == AnalysisJobState::Queued)
        {
            pair.second->state = AnalysisJobState::Cancelled;
            pair.second->work = {};
        }
    }
    queue_.clear();
    workReady_.notify_all();
    idle_.wait(lock, [&] { return !active_ && queue_.empty(); });
    completions_.clear();
}

void AnalysisScheduler::DrainCompletions()
{
    std::deque<PendingCompletion> completions;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        completions.swap(completions_);
    }
    for (auto& completion : completions)
    {
        if (!completion.callback) continue;
        try
        {
            completion.callback();
        }
        catch (const std::exception& error)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            completion.job->state = AnalysisJobState::Failed;
            completion.job->error = error.what();
        }
        catch (...)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            completion.job->state = AnalysisJobState::Failed;
            completion.job->error = "Unknown completion failure";
        }
    }
}

AnalysisJobSnapshot AnalysisScheduler::GetJob(uint64_t id) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto found = jobs_.find(id);
    if (found == jobs_.end())
        return {};
    return {found->second->id, found->second->name, found->second->state,
            found->second->progress, found->second->error};
}

void AnalysisScheduler::Shutdown()
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopping_)
            return;
        stopping_ = true;
        for (auto& pair : jobs_)
        {
            pair.second->cancellation.Cancel();
            if (pair.second->state == AnalysisJobState::Queued)
            {
                pair.second->state = AnalysisJobState::Cancelled;
                pair.second->work = {};
            }
        }
        queue_.clear();
    }
    workReady_.notify_all();
    if (worker_.joinable()) worker_.join();
    std::lock_guard<std::mutex> lock(mutex_);
    completions_.clear();
}

void AnalysisScheduler::WorkerLoop()
{
    while (true)
    {
        std::shared_ptr<Job> job;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            workReady_.wait(lock, [&] { return stopping_ || !queue_.empty(); });
            if (stopping_ && queue_.empty())
                break;
            job = queue_.front();
            queue_.pop_front();
            if (job->cancellation.Token().IsCancellationRequested())
            {
                job->state = AnalysisJobState::Cancelled;
                if (queue_.empty()) idle_.notify_all();
                continue;
            }
            job->state = AnalysisJobState::Running;
            active_ = true;
        }

        Completion completion;
        try
        {
            const auto progress = [this, weakJob = std::weak_ptr<Job>(job)](float value) {
                if (auto current = weakJob.lock())
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    current->progress = std::max(0.0f, std::min(1.0f, value));
                }
            };
            completion = job->work(job->cancellation.Token(), progress);
        }
        catch (const std::exception& error)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            job->error = error.what();
        }
        catch (...)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            job->error = "Unknown analysis failure";
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            job->work = {};
            const bool cancelled = job->cancellation.Token().IsCancellationRequested();
            if (cancelled)
                job->state = AnalysisJobState::Cancelled;
            else if (!job->error.empty())
                job->state = AnalysisJobState::Failed;
            else
            {
                job->state = AnalysisJobState::Completed;
                job->progress = 1.0f;
                if (completion) completions_.push_back({job, std::move(completion)});
            }
            active_ = false;
            idle_.notify_all();
        }
    }

    std::lock_guard<std::mutex> lock(mutex_);
    active_ = false;
    idle_.notify_all();
}

} // namespace openreverse
