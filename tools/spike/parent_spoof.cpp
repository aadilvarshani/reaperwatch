// RW-3 spike: launch notepad.exe, optionally claiming a different parent.
//
//   parent_spoof.exe normal             -> ordinary CreateProcess (the control)
//   parent_spoof.exe spoof <parent_pid> -> CreateProcess with the parent attribute set
//
// Prints our own PID and the PID of the child so we can line them up against
// header_pid / parent_pid in events.jsonl. Lab machine only.

#include <windows.h>

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "../../agent/collectors/win_utils.h"

using reaperwatch::UniqueHandle;

namespace {

// Owns the attribute list's memory and tears the list down on scope exit.
// Windows needs DeleteProcThreadAttributeList called once the list is no
// longer used, so this is the same RAII idea as UniqueHandle.
class ParentAttributeList {
public:
    // `parent` must outlive this object: Windows stores a pointer to it, not a copy.
    explicit ParentAttributeList(HANDLE& parent) {
        // Call 1: ask how many bytes a list with ONE attribute needs. This call
        // is expected to return FALSE (ERROR_INSUFFICIENT_BUFFER); we only want `size`.
        SIZE_T size = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
        if (size == 0) return;

        buffer_.resize(size);
        list_ = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(buffer_.data());

        // Call 2: build the list for real in our own memory.
        if (!InitializeProcThreadAttributeList(list_, 1, 0, &size)) {
            list_ = nullptr;
            return;
        }

        // The value is a pointer TO the handle variable, not the handle itself.
        if (!UpdateProcThreadAttribute(list_, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                       &parent, sizeof(HANDLE), nullptr, nullptr)) {
            DeleteProcThreadAttributeList(list_);
            list_ = nullptr;
        }
    }

    ~ParentAttributeList() {
        if (list_ != nullptr) DeleteProcThreadAttributeList(list_);
    }

    ParentAttributeList(const ParentAttributeList&) = delete;
    ParentAttributeList& operator=(const ParentAttributeList&) = delete;

    bool ok() const { return list_ != nullptr; }
    LPPROC_THREAD_ATTRIBUTE_LIST get() const { return list_; }

private:
    std::vector<BYTE> buffer_;
    LPPROC_THREAD_ATTRIBUTE_LIST list_ = nullptr;
};

bool launch_notepad(HANDLE parent_handle, PROCESS_INFORMATION& out) {
    STARTUPINFOEXW si{};
    si.StartupInfo.cb = sizeof(si);

    wchar_t command_line[] = L"notepad.exe";  // CreateProcessW may write to this buffer

    if (parent_handle == nullptr) {
        return CreateProcessW(nullptr, command_line, nullptr, nullptr, FALSE, 0,
                              nullptr, nullptr, &si.StartupInfo, &out) != FALSE;
    }

    ParentAttributeList attributes(parent_handle);
    if (!attributes.ok()) return false;
    si.lpAttributeList = attributes.get();

    return CreateProcessW(nullptr, command_line, nullptr, nullptr, FALSE,
                          EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
                          &si.StartupInfo, &out) != FALSE;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        std::wcerr << L"usage: parent_spoof normal | spoof <parent_pid>\n";
        return 2;
    }

    const std::wstring mode = argv[1];
    UniqueHandle parent;

    if (mode == L"spoof") {
        if (argc < 3) {
            std::wcerr << L"spoof needs a parent pid\n";
            return 2;
        }
        const DWORD parent_pid = static_cast<DWORD>(std::wcstoul(argv[2], nullptr, 10));

        // PROCESS_CREATE_PROCESS is the one right that lets a process be named as a parent.
        parent = UniqueHandle(OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parent_pid));
        if (!parent.valid()) {
            std::wcerr << L"OpenProcess failed, error " << GetLastError() << L"\n";
            return 1;
        }
    } else if (mode != L"normal") {
        std::wcerr << L"unknown mode\n";
        return 2;
    }

    PROCESS_INFORMATION pi{};
    HANDLE parent_handle = parent.get();  // nullptr in normal mode
    if (!launch_notepad(parent_handle, pi)) {
        std::wcerr << L"launch failed, error " << GetLastError() << L"\n";
        return 1;
    }

    std::wcout << L"creator (this program) pid: " << GetCurrentProcessId() << L"\n"
               << L"child (notepad) pid:        " << pi.dwProcessId << L"\n";

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
