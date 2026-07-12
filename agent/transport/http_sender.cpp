#include "http_sender.h"

#include <windows.h>
#include <winhttp.h>

namespace reaperwatch {
namespace {

// RAII for WinHTTP handles (HINTERNET), same shape as UniqueHandle in
// win_utils.h: WinHttpOpen -> a session, WinHttpConnect -> a connection,
// WinHttpOpenRequest -> a request, each layered on the one before it, each
// needing WinHttpCloseHandle exactly once.
class UniqueInet {
public:
    UniqueInet() = default;
    explicit UniqueInet(HINTERNET h) : handle_(h) {}
    ~UniqueInet() { if (handle_) WinHttpCloseHandle(handle_); }
    UniqueInet(const UniqueInet&) = delete;
    UniqueInet& operator=(const UniqueInet&) = delete;
    HINTERNET get() const { return handle_; }

private:
    HINTERNET handle_ = nullptr;
};

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(static_cast<size_t>(len), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), len);
    return out;
}

}  // namespace

void send_event_http(const std::string& host, int port, const std::string& api_key,
                     const std::string& json_line) {
    // Session: our identity as an HTTP client, roughly "open a browser instance".
    UniqueInet session(WinHttpOpen(L"ReaperWatch-Agent/1.0",
                                   WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                   WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session.get()) {
        return;
    }
    // A dead/unreachable console must never hang the sensor: short timeouts
    // (resolve, connect, send, receive) in milliseconds.
    WinHttpSetTimeouts(session.get(), 0, 3000, 5000, 5000);

    // Connect: which server (host:port) we're talking to.
    UniqueInet connect(WinHttpConnect(session.get(), widen(host).c_str(),
                                      static_cast<INTERNET_PORT>(port), 0));
    if (!connect.get()) {
        return;
    }

    // Request: the specific HTTP request (method + path) on that connection.
    UniqueInet request(WinHttpOpenRequest(connect.get(), L"POST", L"/api/ingest",
                                          nullptr, WINHTTP_NO_REFERER,
                                          WINHTTP_DEFAULT_ACCEPT_TYPES, 0));
    if (!request.get()) {
        return;
    }

    const std::wstring headers =
        L"Content-Type: application/json\r\nX-ReaperWatch-Key: " + widen(api_key) + L"\r\n";
    WinHttpAddRequestHeaders(request.get(), headers.c_str(),
                             static_cast<DWORD>(-1), WINHTTP_ADDREQ_FLAG_ADD);

    // Send the request with the JSON body, then read the response so the
    // request completes cleanly (we don't need the response content itself).
    const BOOL sent = WinHttpSendRequest(
        request.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        const_cast<char*>(json_line.data()), static_cast<DWORD>(json_line.size()),
        static_cast<DWORD>(json_line.size()), 0);
    if (!sent) {
        return;
    }
    WinHttpReceiveResponse(request.get(), nullptr);
}

}  // namespace reaperwatch
