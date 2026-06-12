/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file TaskMonitor.h
/// \brief Interface for monitoring long-running tasks with progress and cancellation
#pragma once

#include <string>
#include <functional>
#include <atomic>
#include <vector>
#include <algorithm>
#include "CancelledException.h"

namespace ghidra {

/// Callback type for cancellation listeners
using CancelledListener = std::function<void()>;

/**
 * TaskMonitor provides an interface that allows potentially long running tasks to show
 * progress and check for user cancellation.
 * Translated from: ghidra.util.task.TaskMonitor (Java interface)
 */
class TaskMonitor {
public:
    /// A value to indicate that this monitor has no progress value set
    static constexpr int64_t NO_PROGRESS_VALUE = -1;

    virtual ~TaskMonitor() = default;

    /// Returns true if the user has cancelled the operation
    virtual bool isCancelled() const = 0;

    /// True (the default) signals to paint the progress information inside of the progress bar
    virtual void setShowProgressValue(bool showProgressValue) = 0;

    /// Sets the message displayed on the task monitor
    virtual void setMessage(const std::string& message) = 0;

    /// Gets the last set message of this monitor
    virtual std::string getMessage() const = 0;

    /// Sets the current progress value
    virtual void setProgress(int64_t value) = 0;

    /// Initialized this TaskMonitor to the given max values. Current value set to zero.
    virtual void initialize(int64_t max) = 0;

    /// Initializes the progress value to 0, sets the max value and message
    virtual void initialize(int64_t max, const std::string& message);

    /// Set the progress maximum value
    virtual void setMaximum(int64_t max) = 0;

    /// Returns the current maximum value for progress
    virtual int64_t getMaximum() const = 0;

    /// An indeterminate task monitor may choose to show an animation instead of updating progress
    virtual void setIndeterminate(bool indeterminate) = 0;

    /// Returns true if this monitor shows no progress
    virtual bool isIndeterminate() const = 0;

    /// Check to see if this monitor has been cancelled
    /// \throws CancelledException if monitor has been cancelled
    virtual void checkCancelled();

    /// Increases the progress value by 1
    virtual void incrementProgress();

    /// Changes the progress value by the specified amount
    virtual void incrementProgress(int64_t incrementAmount) = 0;

    /// Increases the progress value by 1, and checks if this monitor has been cancelled
    virtual void increment();

    /// Changes the progress value by the specified amount, and checks if cancelled
    virtual void increment(int64_t incrementAmount);

    /// Returns the current progress value or NO_PROGRESS_VALUE if there is no value set
    virtual int64_t getProgress() const = 0;

    /// Cancel the task
    virtual void cancel() = 0;

    /// Add cancelled listener
    virtual void addCancelledListener(CancelledListener listener) = 0;

    /// Remove cancelled listener (by identity - not supported, use index-based approach)
    virtual void removeCancelledListener(CancelledListener listener) = 0;

    /// Set the enablement of the Cancel button
    virtual void setCancelEnabled(bool enable) = 0;

    /// Returns true if cancel ability is enabled
    virtual bool isCancelEnabled() const = 0;

    /// Clear the cancellation so that this TaskMonitor may be reused
    virtual void clearCancelled() = 0;
};

/**
 * A 'do nothing' task monitor (stub/dummy).
 * Translated from: ghidra.util.task.StubTaskMonitor
 */
class StubTaskMonitor : public TaskMonitor {
private:
    std::atomic<bool> cancelled_{false};
    std::atomic<int64_t> progress_{0};
    std::atomic<int64_t> maximum_{0};
    std::string message_;
    bool indeterminate_ = false;
    bool cancelEnabled_ = true;
    bool showProgress_ = true;

public:
    bool isCancelled() const override { return cancelled_.load(); }
    void setShowProgressValue(bool show) override { showProgress_ = show; }
    void setMessage(const std::string& msg) override { message_ = msg; }
    std::string getMessage() const override { return message_; }
    void setProgress(int64_t value) override { progress_.store(value); }
    void initialize(int64_t max) override { progress_.store(0); maximum_.store(max); }
    void setMaximum(int64_t max) override {
        maximum_.store(max);
        if (progress_.load() > max) progress_.store(max);
    }
    int64_t getMaximum() const override { return maximum_.load(); }
    void setIndeterminate(bool ind) override { indeterminate_ = ind; }
    bool isIndeterminate() const override { return indeterminate_; }
    void incrementProgress(int64_t amount) override { progress_.fetch_add(amount); }
    int64_t getProgress() const override { return progress_.load(); }
    void cancel() override { cancelled_.store(true); }
    void addCancelledListener(CancelledListener) override {}
    void removeCancelledListener(CancelledListener) override {}
    void setCancelEnabled(bool enable) override { cancelEnabled_ = enable; }
    bool isCancelEnabled() const override { return cancelEnabled_; }
    void clearCancelled() override { cancelled_.store(false); }
};

/// Static DUMMY monitor instance
inline TaskMonitor& getDummyMonitor() {
    static StubTaskMonitor dummy;
    return dummy;
}

} // namespace ghidra
