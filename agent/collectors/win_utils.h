#pragma once

// win_utils.h
//
// Small, reusable helpers for talking to the Win32 API safely:
//   - UniqueHandle : an RAII wrapper that closes a HANDLE automatically.
//   - narrow()     : converts a UTF-16 (wide) string to UTF-8.
//
// These are used across all the enrichment steps (T2-T8).

#include <windows.h>

#include <string>

namespace reaperwatch {

// ---------------------------------------------------------------------------
// UniqueHandle: owns a Win32 HANDLE and closes it in its destructor.
//
// Why: every OpenProcess/OpenProcessToken/etc. returns a handle you must
// CloseHandle exactly once. Doing that by hand is error-prone -- an early
// `return` on an error path silently leaks the handle. By wrapping the handle
// in an object, C++ guarantees the destructor runs when the object goes out of
// scope, so the handle is ALWAYS closed. This is the RAII pattern.
// ---------------------------------------------------------------------------
class UniqueHandle {
public:
    UniqueHandle() = default;
    explicit UniqueHandle(HANDLE h) : handle_(h) {}
    ~UniqueHandle() { reset(); }

    // A handle must have exactly one owner (two owners would double-close, a
    // bug). So we forbid copying, but allow "moving" ownership from one object
    // to another.
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    UniqueHandle(UniqueHandle&& other) noexcept : handle_(other.release()) {}
    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) {
            reset();
            handle_ = other.release();
        }
        return *this;
    }

    HANDLE get() const { return handle_; }

    // OpenProcess returns NULL on failure; some other APIs use
    // INVALID_HANDLE_VALUE. Treat both as "not a real handle".
    bool valid() const {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

    // Give up ownership without closing (caller takes responsibility).
    HANDLE release() {
        HANDLE h = handle_;
        handle_ = nullptr;
        return h;
    }

    // Close the current handle (if any) and become empty.
    void reset() {
        if (valid()) {
            CloseHandle(handle_);
        }
        handle_ = nullptr;
    }

private:
    HANDLE handle_ = nullptr;
};

// ---------------------------------------------------------------------------
// narrow(): convert a UTF-16 std::wstring (what Win32 -W APIs return) to a
// UTF-8 std::string (what our data model and JSON use). This is the single
// conversion point at the Win32 boundary.
// ---------------------------------------------------------------------------
inline std::string narrow(const std::wstring& wide) {
    if (wide.empty()) {
        return {};
    }
    const int len = WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
        nullptr, 0, nullptr, nullptr);
    if (len <= 0) {
        return {};
    }
    std::string out(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
        out.data(), len, nullptr, nullptr);
    return out;
}

// widen(): the reverse of narrow() -- UTF-8 std::string to UTF-16 std::wstring.
// Used when we must hand a path from our (UTF-8) model back to a wide Win32 API.
inline std::wstring widen(const std::string& utf8) {
    if (utf8.empty()) {
        return {};
    }
    const int len = MultiByteToWideChar(
        CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    if (len <= 0) {
        return {};
    }
    std::wstring out(static_cast<size_t>(len), L'\0');
    MultiByteToWideChar(
        CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), out.data(), len);
    return out;
}

}  // namespace reaperwatch
