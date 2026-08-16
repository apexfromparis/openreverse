#include "loopback_callback.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>

namespace openreverse::auth {

namespace {

constexpr size_t kMaximumHttpHeaderBytes = 16 * 1024;

void SendBrowserResponse(SOCKET socket, bool accepted)
{
    const char* body = accepted
        ? "<!doctype html><meta charset=utf-8><title>OpenReverse</title>"
          "<h1>Authentication response received.</h1>"
          "<p>You can return to OpenReverse. This page contains no account credential.</p>"
        : "<!doctype html><meta charset=utf-8><title>OpenReverse</title>"
          "<h1>Authentication request rejected.</h1>"
          "<p>Return to OpenReverse and start sign-in again.</p>";
    const std::string status = accepted ? "200 OK" : "400 Bad Request";
    const std::string response = "HTTP/1.1 " + status + "\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Cache-Control: no-store\r\n"
        "Pragma: no-cache\r\n"
        "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'\r\n"
        "Referrer-Policy: no-referrer\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Connection: close\r\nContent-Length: " + std::to_string(std::strlen(body)) +
        "\r\n\r\n" + body;
    send(socket, response.data(), static_cast<int>(response.size()), 0);
}

std::string Trim(std::string value)
{
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())))
        value.erase(value.begin());
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())))
        value.pop_back();
    return value;
}

bool ParseHttpRequest(const std::string& request, uint16_t port,
                      std::string& target, std::string& error)
{
    target.clear();
    const size_t lineEnd = request.find("\r\n");
    if (lineEnd == std::string::npos)
    {
        error = "Loopback callback request line is malformed";
        return false;
    }
    const std::string line = request.substr(0, lineEnd);
    if (line.rfind("GET ", 0) != 0 || line.size() < 14 ||
        line.substr(line.size() - 9) != " HTTP/1.1")
    {
        error = "Loopback callback accepts only HTTP/1.1 GET";
        return false;
    }
    target = line.substr(4, line.size() - 13);
    if (target.empty() || target.size() > 8192 || target.front() != '/')
    {
        error = "Loopback callback request target exceeds limits";
        return false;
    }
    const size_t query = target.find('?');
    if (target.substr(0, query) != "/callback")
    {
        error = "Loopback callback path is not allowed";
        return false;
    }

    const std::string expectedHost = "127.0.0.1:" + std::to_string(port);
    size_t hostCount = 0;
    size_t cursor = lineEnd + 2;
    while (cursor < request.size())
    {
        const size_t end = request.find("\r\n", cursor);
        if (end == std::string::npos || end == cursor) break;
        const std::string header = request.substr(cursor, end - cursor);
        const size_t colon = header.find(':');
        if (colon == std::string::npos)
        {
            error = "Loopback callback contains a malformed HTTP header";
            return false;
        }
        std::string name = header.substr(0, colon);
        std::transform(name.begin(), name.end(), name.begin(),
            [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
        if (name == "host")
        {
            ++hostCount;
            if (Trim(header.substr(colon + 1)) != expectedHost)
            {
                error = "Loopback callback Host header is not the active listener";
                return false;
            }
        }
        cursor = end + 2;
    }
    if (hostCount != 1)
    {
        error = "Loopback callback requires exactly one Host header";
        return false;
    }
    return true;
}

} // namespace

LoopbackCallbackServer::~LoopbackCallbackServer()
{
    Stop();
    if (winsockStarted_) WSACleanup();
}

bool LoopbackCallbackServer::Start(std::string& error)
{
    Stop();
    error.clear();
    if (!winsockStarted_)
    {
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
        {
            error = "Windows loopback networking could not be initialized";
            return false;
        }
        winsockStarted_ = true;
    }
    SOCKET socketHandle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socketHandle == INVALID_SOCKET)
    {
        error = "Loopback callback socket could not be created";
        return false;
    }
    BOOL exclusive = TRUE;
    if (setsockopt(socketHandle, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                   reinterpret_cast<const char*>(&exclusive), sizeof(exclusive)) != 0)
    {
        closesocket(socketHandle);
        error = "Loopback callback could not apply exclusive address ownership";
        return false;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(socketHandle, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0 ||
        listen(socketHandle, 1) != 0)
    {
        closesocket(socketHandle);
        error = "Loopback callback could not bind 127.0.0.1";
        return false;
    }
    int addressSize = sizeof(address);
    if (getsockname(socketHandle, reinterpret_cast<sockaddr*>(&address), &addressSize) != 0)
    {
        closesocket(socketHandle);
        error = "Loopback callback could not determine its ephemeral port";
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    listenSocket_ = static_cast<uintptr_t>(socketHandle);
    port_ = ntohs(address.sin_port);
    return port_ != 0;
}

bool LoopbackCallbackServer::WaitForRequest(std::chrono::milliseconds timeout,
                                            const std::atomic_bool& cancelled,
                                            std::string& requestTarget,
                                            std::string& error)
{
    requestTarget.clear();
    error.clear();
    SOCKET listening = INVALID_SOCKET;
    uint16_t port = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        listening = static_cast<SOCKET>(listenSocket_);
        port = port_;
    }
    if (listening == INVALID_SOCKET || port == 0)
    {
        error = "Loopback callback listener is not active";
        return false;
    }
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!cancelled.load())
    {
        const auto remaining = deadline - std::chrono::steady_clock::now();
        if (remaining <= std::chrono::steady_clock::duration::zero())
        {
            error = "Authentication callback timed out";
            return false;
        }
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(listening, &readable);
        const auto slice = (std::min)(std::chrono::duration_cast<std::chrono::milliseconds>(remaining),
                                      std::chrono::milliseconds(250));
        timeval wait{static_cast<long>(slice.count() / 1000),
                     static_cast<long>((slice.count() % 1000) * 1000)};
        const int selected = select(0, &readable, nullptr, nullptr, &wait);
        if (selected == 0) continue;
        if (selected == SOCKET_ERROR)
        {
            if (cancelled.load()) return false;
            error = "Loopback callback listener failed";
            return false;
        }
        sockaddr_in peer{};
        int peerSize = sizeof(peer);
        SOCKET client = accept(listening, reinterpret_cast<sockaddr*>(&peer), &peerSize);
        if (client == INVALID_SOCKET)
        {
            if (cancelled.load()) return false;
            error = "Loopback callback connection could not be accepted";
            return false;
        }
        bool accepted = peer.sin_family == AF_INET &&
            peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK);
        std::string request;
        if (accepted)
        {
            DWORD receiveTimeout = 2000;
            setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
                       reinterpret_cast<const char*>(&receiveTimeout), sizeof(receiveTimeout));
            std::array<char, 2048> buffer{};
            while (request.find("\r\n\r\n") == std::string::npos &&
                   request.size() < kMaximumHttpHeaderBytes)
            {
                const int received = recv(client, buffer.data(), static_cast<int>(buffer.size()), 0);
                if (received <= 0) break;
                request.append(buffer.data(), static_cast<size_t>(received));
            }
            accepted = request.find("\r\n\r\n") != std::string::npos &&
                request.size() <= kMaximumHttpHeaderBytes &&
                ParseHttpRequest(request, port, requestTarget, error);
        }
        else
        {
            error = "Loopback callback rejected a non-loopback peer";
        }
        SendBrowserResponse(client, accepted);
        shutdown(client, SD_BOTH);
        closesocket(client);
        return accepted;
    }
    return false;
}

void LoopbackCallbackServer::Stop()
{
    SOCKET socketHandle = INVALID_SOCKET;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        socketHandle = static_cast<SOCKET>(listenSocket_);
        listenSocket_ = static_cast<uintptr_t>(INVALID_SOCKET);
        port_ = 0;
    }
    if (socketHandle != INVALID_SOCKET)
    {
        shutdown(socketHandle, SD_BOTH);
        closesocket(socketHandle);
    }
}

std::string LoopbackCallbackServer::CallbackUri() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return port_ == 0 ? std::string{} :
        "http://127.0.0.1:" + std::to_string(port_) + "/callback";
}

uint16_t LoopbackCallbackServer::Port() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return port_;
}

} // namespace openreverse::auth
