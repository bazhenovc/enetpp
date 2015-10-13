
#define ENET_BUILDING_LIB 1

#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winmm.lib")
#endif

#include "enetpp.hh"

#include <string.h>

#ifdef _MSC_VER
#pragma warning(disable:4244)
#pragma warning(disable:4267)
#endif

//-----------------------------------------------------------------------------
// misc. defines

#define ENET_VERSION_CREATE(major, minor, patch) (((major) << 16) | ((minor) << 8) | (patch))
#define ENET_VERSION_GET_MAJOR(version) (((version) >> 16) & 0xFF)
#define ENET_VERSION_GET_MINOR(version) (((version) >> 8) & 0xFF)
#define ENET_VERSION_GET_PATCH(version) ((version)&0xFF)
#define ENET_VERSION ENET_VERSION_CREATE(ENET_VERSION_MAJOR, ENET_VERSION_MINOR, ENET_VERSION_PATCH)

#define ENET_MAX(x, y) ((x) > (y) ? (x) : (y))
#define ENET_MIN(x, y) ((x) < (y) ? (x) : (y))

#define ENET_TIME_OVERFLOW 86400000

#define ENET_TIME_LESS(a, b) ((a) - (b) >= ENET_TIME_OVERFLOW)
#define ENET_TIME_GREATER(a, b) ((b) - (a) >= ENET_TIME_OVERFLOW)
#define ENET_TIME_LESS_EQUAL(a, b) (!ENET_TIME_GREATER(a, b))
#define ENET_TIME_GREATER_EQUAL(a, b) (!ENET_TIME_LESS(a, b))

#define ENET_TIME_DIFFERENCE(a, b) ((a) - (b) >= ENET_TIME_OVERFLOW ? (b) - (a) : (a) - (b))

#define ENET_UNUSED(X) ((void)X)

//-----------------------------------------------------------------------------
// init

static ENetCallbacks callbacks = { malloc, free, abort };

int enet_initialize_with_callbacks(ENetVersion version, const ENetCallbacks* inits)
{
    if (version < ENET_VERSION_CREATE(1, 3, 0))
        return -1;

    if (inits->malloc != NULL || inits->free != NULL) {
        if (inits->malloc == NULL || inits->free == NULL)
            return -1;

        callbacks.malloc = inits->malloc;
        callbacks.free = inits->free;
    }

    if (inits->no_memory != NULL)
        callbacks.no_memory = inits->no_memory;

    return enet_initialize();
}

ENetVersion enet_linked_version(void) { return ENET_VERSION; }

void* enet_malloc(size_t size)
{
    void* memory = callbacks.malloc(size);

    if (memory == NULL)
        callbacks.no_memory();

    return memory;
}

void enet_free(void* memory) { callbacks.free(memory); }

//-----------------------------------------------------------------------------
// Unix platform

#ifdef _UNIX

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#define ENET_BUILDING_LIB 1
#include "enet/enet.h"

#ifdef __APPLE__
#ifdef HAS_POLL
#undef HAS_POLL
#endif
#ifndef HAS_FCNTL
#define HAS_FCNTL 1
#endif
#ifndef HAS_INET_PTON
#define HAS_INET_PTON 1
#endif
#ifndef HAS_INET_NTOP
#define HAS_INET_NTOP 1
#endif
#ifndef HAS_MSGHDR_FLAGS
#define HAS_MSGHDR_FLAGS 1
#endif
#ifndef HAS_SOCKLEN_T
#define HAS_SOCKLEN_T 1
#endif
#ifndef HAS_GETADDRINFO
#define HAS_GETADDRINFO 1
#endif
#ifndef HAS_GETNAMEINFO
#define HAS_GETNAMEINFO 1
#endif
#endif

#ifdef HAS_FCNTL
#include <fcntl.h>
#endif

#ifdef HAS_POLL
#include <sys/poll.h>
#endif

#ifndef HAS_SOCKLEN_T
typedef int socklen_t;
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static enet_uint32 timeBase = 0;

int enet_initialize(void) { return 0; }

void enet_deinitialize(void) {}

enet_uint32 enet_host_random_seed(void) { return (enet_uint32)time(NULL); }

enet_uint32 enet_time_get(void)
{
    struct timeval timeVal;

    gettimeofday(&timeVal, NULL);

    return timeVal.tv_sec * 1000 + timeVal.tv_usec / 1000 - timeBase;
}

void enet_time_set(enet_uint32 newTimeBase)
{
    struct timeval timeVal;

    gettimeofday(&timeVal, NULL);

    timeBase = timeVal.tv_sec * 1000 + timeVal.tv_usec / 1000 - newTimeBase;
}

int enet_address_set_host(ENetAddress* address, const char* name)
{
#ifdef HAS_GETADDRINFO
    struct addrinfo hints, * resultList = NULL, * result = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;

    if (getaddrinfo(name, NULL, NULL, &resultList) != 0)
        return -1;

    for (result = resultList; result != NULL; result = result->ai_next) {
        if (result->ai_family == AF_INET && result->ai_addr != NULL && result->ai_addrlen >= sizeof(struct sockaddr_in)) {
            struct sockaddr_in* sin = (struct sockaddr_in*)result->ai_addr;

            address->host = sin->sin_addr.s_addr;

            freeaddrinfo(resultList);

            return 0;
        }
    }

    if (resultList != NULL)
        freeaddrinfo(resultList);
#else
    struct hostent* hostEntry = NULL;
#ifdef HAS_GETHOSTBYNAME_R
    struct hostent hostData;
    char buffer[2048];
    int errnum;

#if defined(linux) || defined(__linux) || defined(__linux__) || defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__DragonFly__)
    gethostbyname_r(name, &hostData, buffer, sizeof(buffer), &hostEntry, &errnum);
#else
    hostEntry = gethostbyname_r(name, &hostData, buffer, sizeof(buffer), &errnum);
#endif
#else
    hostEntry = gethostbyname(name);
#endif

    if (hostEntry != NULL && hostEntry->h_addrtype == AF_INET) {
        address->host = *(enet_uint32*)hostEntry->h_addr_list[0];

        return 0;
    }
#endif

#ifdef HAS_INET_PTON
    if (!inet_pton(AF_INET, name, &address->host))
#else
    if (!inet_aton(name, (struct in_addr*)&address->host))
#endif
        return -1;

    return 0;
}

int enet_address_get_host_ip(const ENetAddress* address, char* name,
    size_t nameLength)
{
#ifdef HAS_INET_NTOP
    if (inet_ntop(AF_INET, &address->host, name, nameLength) == NULL)
#else
    char* addr = inet_ntoa(*(struct in_addr*)&address->host);
    if (addr != NULL) {
        size_t addrLen = strlen(addr);
        if (addrLen >= nameLength)
            return -1;
        memcpy(name, addr, addrLen + 1);
    }
    else
#endif
        return -1;
    return 0;
}

int enet_address_get_host(const ENetAddress* address, char* name,
    size_t nameLength)
{
#ifdef HAS_GETNAMEINFO
    struct sockaddr_in sin;
    int err;

    memset(&sin, 0, sizeof(struct sockaddr_in));

    sin.sin_family = AF_INET;
    sin.sin_port = ENET_HOST_TO_NET_16(address->port);
    sin.sin_addr.s_addr = address->host;

    err = getnameinfo((struct sockaddr*)&sin, sizeof(sin), name, nameLength, NULL,
        0, NI_NAMEREQD);
    if (!err) {
        if (name != NULL && nameLength > 0 && !memchr(name, '\0', nameLength))
            return -1;
        return 0;
    }
    if (err != EAI_NONAME)
        return 0;
#else
    struct in_addr in;
    struct hostent* hostEntry = NULL;
#ifdef HAS_GETHOSTBYADDR_R
    struct hostent hostData;
    char buffer[2048];
    int errnum;

    in.s_addr = address->host;

#if defined(linux) || defined(__linux) || defined(__linux__) || defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__DragonFly__)
    gethostbyaddr_r((char*)&in, sizeof(struct in_addr), AF_INET, &hostData,
        buffer, sizeof(buffer), &hostEntry, &errnum);
#else
    hostEntry = gethostbyaddr_r((char*)&in, sizeof(struct in_addr), AF_INET,
        &hostData, buffer, sizeof(buffer), &errnum);
#endif
#else
    in.s_addr = address->host;

    hostEntry = gethostbyaddr((char*)&in, sizeof(struct in_addr), AF_INET);
#endif

    if (hostEntry != NULL) {
        size_t hostLen = strlen(hostEntry->h_name);
        if (hostLen >= nameLength)
            return -1;
        memcpy(name, hostEntry->h_name, hostLen + 1);
        return 0;
    }
#endif

    return enet_address_get_host_ip(address, name, nameLength);
}

int enet_socket_bind(ENetSocket socket, const ENetAddress* address)
{
    struct sockaddr_in sin;

    memset(&sin, 0, sizeof(struct sockaddr_in));

    sin.sin_family = AF_INET;

    if (address != NULL) {
        sin.sin_port = ENET_HOST_TO_NET_16(address->port);
        sin.sin_addr.s_addr = address->host;
    }
    else {
        sin.sin_port = 0;
        sin.sin_addr.s_addr = INADDR_ANY;
    }

    return bind(socket, (struct sockaddr*)&sin, sizeof(struct sockaddr_in));
}

int enet_socket_get_address(ENetSocket socket, ENetAddress* address)
{
    struct sockaddr_in sin;
    socklen_t sinLength = sizeof(struct sockaddr_in);

    if (getsockname(socket, (struct sockaddr*)&sin, &sinLength) == -1)
        return -1;

    address->host = (enet_uint32)sin.sin_addr.s_addr;
    address->port = ENET_NET_TO_HOST_16(sin.sin_port);

    return 0;
}

int enet_socket_listen(ENetSocket socket, int backlog)
{
    return listen(socket, backlog < 0 ? SOMAXCONN : backlog);
}

ENetSocket enet_socket_create(ENetSocketType type)
{
    return socket(
        PF_INET, type == ENET_SOCKET_TYPE_DATAGRAM ? SOCK_DGRAM : SOCK_STREAM, 0);
}

int enet_socket_set_option(ENetSocket socket, ENetSocketOption option,
    int value)
{
    int result = -1;
    switch (option) {
    case ENET_SOCKOPT_NONBLOCK:
#ifdef HAS_FCNTL
        result = fcntl(socket, F_SETFL, (value ? O_NONBLOCK : 0) | (fcntl(socket, F_GETFL) & ~O_NONBLOCK));
#else
        result = ioctl(socket, FIONBIO, &value);
#endif
        break;

    case ENET_SOCKOPT_BROADCAST:
        result = setsockopt(socket, SOL_SOCKET, SO_BROADCAST, (char*)&value,
            sizeof(int));
        break;

    case ENET_SOCKOPT_REUSEADDR:
        result = setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, (char*)&value,
            sizeof(int));
        break;

    case ENET_SOCKOPT_RCVBUF:
        result = setsockopt(socket, SOL_SOCKET, SO_RCVBUF, (char*)&value, sizeof(int));
        break;

    case ENET_SOCKOPT_SNDBUF:
        result = setsockopt(socket, SOL_SOCKET, SO_SNDBUF, (char*)&value, sizeof(int));
        break;

    case ENET_SOCKOPT_RCVTIMEO: {
        struct timeval timeVal;
        timeVal.tv_sec = value / 1000;
        timeVal.tv_usec = (value % 1000) * 1000;
        result = setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeVal,
            sizeof(struct timeval));
        break;
    }

    case ENET_SOCKOPT_SNDTIMEO: {
        struct timeval timeVal;
        timeVal.tv_sec = value / 1000;
        timeVal.tv_usec = (value % 1000) * 1000;
        result = setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeVal,
            sizeof(struct timeval));
        break;
    }

    case ENET_SOCKOPT_NODELAY:
        result = setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, (char*)&value,
            sizeof(int));
        break;

    default:
        break;
    }
    return result == -1 ? -1 : 0;
}

int enet_socket_get_option(ENetSocket socket, ENetSocketOption option,
    int* value)
{
    int result = -1;
    socklen_t len;
    switch (option) {
    case ENET_SOCKOPT_ERROR:
        len = sizeof(int);
        result = getsockopt(socket, SOL_SOCKET, SO_ERROR, value, &len);
        break;

    default:
        break;
    }
    return result == -1 ? -1 : 0;
}

int enet_socket_connect(ENetSocket socket, const ENetAddress* address)
{
    struct sockaddr_in sin;
    int result;

    memset(&sin, 0, sizeof(struct sockaddr_in));

    sin.sin_family = AF_INET;
    sin.sin_port = ENET_HOST_TO_NET_16(address->port);
    sin.sin_addr.s_addr = address->host;

    result = connect(socket, (struct sockaddr*)&sin, sizeof(struct sockaddr_in));
    if (result == -1 && errno == EINPROGRESS)
        return 0;

    return result;
}

ENetSocket enet_socket_accept(ENetSocket socket, ENetAddress* address)
{
    int result;
    struct sockaddr_in sin;
    socklen_t sinLength = sizeof(struct sockaddr_in);

    result = accept(socket, address != NULL ? (struct sockaddr*)&sin : NULL,
        address != NULL ? &sinLength : NULL);

    if (result == -1)
        return ENET_SOCKET_NULL;

    if (address != NULL) {
        address->host = (enet_uint32)sin.sin_addr.s_addr;
        address->port = ENET_NET_TO_HOST_16(sin.sin_port);
    }

    return result;
}

int enet_socket_shutdown(ENetSocket socket, ENetSocketShutdown how)
{
    return shutdown(socket, (int)how);
}

void enet_socket_destroy(ENetSocket socket)
{
    if (socket != -1)
        close(socket);
}

int enet_socket_send(ENetSocket socket, const ENetAddress* address,
    const ENetBuffer* buffers, size_t bufferCount)
{
    struct msghdr msgHdr;
    struct sockaddr_in sin;
    int sentLength;

    memset(&msgHdr, 0, sizeof(struct msghdr));

    if (address != NULL) {
        memset(&sin, 0, sizeof(struct sockaddr_in));

        sin.sin_family = AF_INET;
        sin.sin_port = ENET_HOST_TO_NET_16(address->port);
        sin.sin_addr.s_addr = address->host;

        msgHdr.msg_name = &sin;
        msgHdr.msg_namelen = sizeof(struct sockaddr_in);
    }

    msgHdr.msg_iov = (struct iovec*)buffers;
    msgHdr.msg_iovlen = bufferCount;

    sentLength = sendmsg(socket, &msgHdr, MSG_NOSIGNAL);

    if (sentLength == -1) {
        if (errno == EWOULDBLOCK)
            return 0;

        return -1;
    }

    return sentLength;
}

int enet_socket_receive(ENetSocket socket, ENetAddress* address,
    ENetBuffer* buffers, size_t bufferCount)
{
    struct msghdr msgHdr;
    struct sockaddr_in sin;
    int recvLength;

    memset(&msgHdr, 0, sizeof(struct msghdr));

    if (address != NULL) {
        msgHdr.msg_name = &sin;
        msgHdr.msg_namelen = sizeof(struct sockaddr_in);
    }

    msgHdr.msg_iov = (struct iovec*)buffers;
    msgHdr.msg_iovlen = bufferCount;

    recvLength = recvmsg(socket, &msgHdr, MSG_NOSIGNAL);

    if (recvLength == -1) {
        if (errno == EWOULDBLOCK)
            return 0;

        return -1;
    }

#ifdef HAS_MSGHDR_FLAGS
    if (msgHdr.msg_flags & MSG_TRUNC)
        return -1;
#endif

    if (address != NULL) {
        address->host = (enet_uint32)sin.sin_addr.s_addr;
        address->port = ENET_NET_TO_HOST_16(sin.sin_port);
    }

    return recvLength;
}

int enet_socketset_select(ENetSocket maxSocket, ENetSocketSet* readSet,
    ENetSocketSet* writeSet, enet_uint32 timeout)
{
    struct timeval timeVal;

    timeVal.tv_sec = timeout / 1000;
    timeVal.tv_usec = (timeout % 1000) * 1000;

    return select(maxSocket + 1, readSet, writeSet, NULL, &timeVal);
}

int enet_socket_wait(ENetSocket socket, enet_uint32* condition,
    enet_uint32 timeout)
{
#ifdef HAS_POLL
    struct pollfd pollSocket;
    int pollCount;

    pollSocket.fd = socket;
    pollSocket.events = 0;

    if (*condition & ENET_SOCKET_WAIT_SEND)
        pollSocket.events |= POLLOUT;

    if (*condition & ENET_SOCKET_WAIT_RECEIVE)
        pollSocket.events |= POLLIN;

    pollCount = poll(&pollSocket, 1, timeout);

    if (pollCount < 0) {
        if (errno == EINTR && *condition & ENET_SOCKET_WAIT_INTERRUPT) {
            *condition = ENET_SOCKET_WAIT_INTERRUPT;

            return 0;
        }

        return -1;
    }

    *condition = ENET_SOCKET_WAIT_NONE;

    if (pollCount == 0)
        return 0;

    if (pollSocket.revents & POLLOUT)
        *condition |= ENET_SOCKET_WAIT_SEND;

    if (pollSocket.revents & POLLIN)
        *condition |= ENET_SOCKET_WAIT_RECEIVE;

    return 0;
#else
    fd_set readSet, writeSet;
    struct timeval timeVal;
    int selectCount;

    timeVal.tv_sec = timeout / 1000;
    timeVal.tv_usec = (timeout % 1000) * 1000;

    FD_ZERO(&readSet);
    FD_ZERO(&writeSet);

    if (*condition & ENET_SOCKET_WAIT_SEND)
        FD_SET(socket, &writeSet);

    if (*condition & ENET_SOCKET_WAIT_RECEIVE)
        FD_SET(socket, &readSet);

    selectCount = select(socket + 1, &readSet, &writeSet, NULL, &timeVal);

    if (selectCount < 0) {
        if (errno == EINTR && *condition & ENET_SOCKET_WAIT_INTERRUPT) {
            *condition = ENET_SOCKET_WAIT_INTERRUPT;

            return 0;
        }

        return -1;
    }

    *condition = ENET_SOCKET_WAIT_NONE;

    if (selectCount == 0)
        return 0;

    if (FD_ISSET(socket, &writeSet))
        *condition |= ENET_SOCKET_WAIT_SEND;

    if (FD_ISSET(socket, &readSet))
        *condition |= ENET_SOCKET_WAIT_RECEIVE;

    return 0;
#endif
}

#endif

//-----------------------------------------------------------------------------
// Windows platform

#ifdef _WIN32

#include <windows.h>
#include <mmsystem.h>

#define ENET_HOST_TO_NET_16(value) (htons(value))
#define ENET_HOST_TO_NET_32(value) (htonl(value))

#define ENET_NET_TO_HOST_16(value) (ntohs(value))
#define ENET_NET_TO_HOST_32(value) (ntohl(value))

#define ENET_SOCKETSET_EMPTY(sockset)           FD_ZERO(&(sockset))
#define ENET_SOCKETSET_ADD(sockset, socket)     FD_SET(socket, &(sockset))
#define ENET_SOCKETSET_REMOVE(sockset, socket)  FD_CLR(socket, &(sockset))
#define ENET_SOCKETSET_CHECK(sockset, socket)   FD_ISSET(socket, &(sockset))

static enet_uint32 timeBase = 0;

int enet_initialize(void)
{
    WORD versionRequested = MAKEWORD(1, 1);
    WSADATA wsaData;

    if (WSAStartup(versionRequested, &wsaData))
        return -1;

    if (LOBYTE(wsaData.wVersion) != 1 || HIBYTE(wsaData.wVersion) != 1) {
        WSACleanup();

        return -1;
    }

    timeBeginPeriod(1);

    return 0;
}

void enet_deinitialize(void)
{
    timeEndPeriod(1);

    WSACleanup();
}

enet_uint32 ENetHost::random_seed(void) { return (enet_uint32)timeGetTime(); }

enet_uint32 enet_time_get(void)
{
    return (enet_uint32)timeGetTime() - timeBase;
}

void enet_time_set(enet_uint32 newTimeBase)
{
    timeBase = (enet_uint32)timeGetTime() - newTimeBase;
}

int ENetAddress::set_host(const char* name)
{
    struct hostent* hostEntry;

    hostEntry = gethostbyname(name);
    if (hostEntry == NULL || hostEntry->h_addrtype != AF_INET) {
        unsigned long inet_host = inet_addr(name);
        if (inet_host == INADDR_NONE)
            return -1;
        host = inet_host;
        return 0;
    }

    host = *(enet_uint32*)hostEntry->h_addr_list[0];

    return 0;
}

int ENetAddress::get_host_ip(char* name, size_t nameLength)
{
    char* addr = inet_ntoa(*(struct in_addr*)&host);
    if (addr == NULL)
        return -1;
    else {
        size_t addrLen = strlen(addr);
        if (addrLen >= nameLength)
            return -1;
        memcpy(name, addr, addrLen + 1);
    }
    return 0;
}

int ENetAddress::get_host(char* name, size_t nameLength)
{
    struct in_addr in;
    struct hostent* hostEntry;

    in.s_addr = host;

    hostEntry = gethostbyaddr((char*)&in, sizeof(struct in_addr), AF_INET);
    if (hostEntry == NULL)
        return get_host_ip(name, nameLength);
    else {
        size_t hostLen = strlen(hostEntry->h_name);
        if (hostLen >= nameLength)
            return -1;
        memcpy(name, hostEntry->h_name, hostLen + 1);
    }

    return 0;
}

ENetSocket ENetSocket::create(ENetSocketType type)
{
    return ::socket(
        PF_INET, type == ENET_SOCKET_TYPE_DATAGRAM ? SOCK_DGRAM : SOCK_STREAM, 0);
}

int ENetSocket::bind(const ENetAddress* address)
{
    struct sockaddr_in sin;

    memset(&sin, 0, sizeof(struct sockaddr_in));

    sin.sin_family = AF_INET;

    if (address != NULL) {
        sin.sin_port        = ENET_HOST_TO_NET_16(address->port);
        sin.sin_addr.s_addr = address->host;
    }
    else {
        sin.sin_port        = 0;
        sin.sin_addr.s_addr = INADDR_ANY;
    }

    return ::bind(socket, (struct sockaddr*)&sin, sizeof(struct sockaddr_in)) == SOCKET_ERROR ? -1 : 0;
}

int ENetSocket::get_address(ENetAddress* address)
{
    struct sockaddr_in sin;
    int sinLength = sizeof(struct sockaddr_in);

    if (getsockname(socket, (struct sockaddr*)&sin, &sinLength) == -1)
        return -1;

    address->host = (enet_uint32)sin.sin_addr.s_addr;
    address->port = ENET_NET_TO_HOST_16(sin.sin_port);

    return 0;
}

int ENetSocket::listen(int backlog)
{
    return ::listen(socket, backlog < 0 ? SOMAXCONN : backlog) == SOCKET_ERROR ? -1 : 0;
}

int ENetSocket::set_option(ENetSocketOption option, int value)
{
    int result = SOCKET_ERROR;
    switch (option) {
    case ENET_SOCKOPT_NONBLOCK: {
        u_long nonBlocking = (u_long)value;
        result = ioctlsocket(socket, FIONBIO, &nonBlocking);
        break;
    }

    case ENET_SOCKOPT_BROADCAST:
        result = setsockopt(socket, SOL_SOCKET, SO_BROADCAST, (char*)&value,
            sizeof(int));
        break;

    case ENET_SOCKOPT_REUSEADDR:
        result = setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, (char*)&value,
            sizeof(int));
        break;

    case ENET_SOCKOPT_RCVBUF:
        result = setsockopt(socket, SOL_SOCKET, SO_RCVBUF, (char*)&value, sizeof(int));
        break;

    case ENET_SOCKOPT_SNDBUF:
        result = setsockopt(socket, SOL_SOCKET, SO_SNDBUF, (char*)&value, sizeof(int));
        break;

    case ENET_SOCKOPT_RCVTIMEO:
        result = setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&value,
            sizeof(int));
        break;

    case ENET_SOCKOPT_SNDTIMEO:
        result = setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (char*)&value,
            sizeof(int));
        break;

    case ENET_SOCKOPT_NODELAY:
        result = setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, (char*)&value,
            sizeof(int));
        break;

    default:
        break;
    }
    return result == SOCKET_ERROR ? -1 : 0;
}

int ENetSocket::get_option(ENetSocketOption option, int* value)
{
    int result = SOCKET_ERROR, len;
    switch (option) {
    case ENET_SOCKOPT_ERROR:
        len = sizeof(int);
        result = getsockopt(socket, SOL_SOCKET, SO_ERROR, (char*)value, &len);
        break;

    default:
        break;
    }
    return result == SOCKET_ERROR ? -1 : 0;
}

int ENetSocket::connect(const ENetAddress* address)
{
    struct sockaddr_in sin;
    int result;

    memset(&sin, 0, sizeof(struct sockaddr_in));

    sin.sin_family      = AF_INET;
    sin.sin_port        = ENET_HOST_TO_NET_16(address->port);
    sin.sin_addr.s_addr = address->host;

    result = ::connect(socket, (struct sockaddr*)&sin, sizeof(struct sockaddr_in));
    if (result == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK)
        return -1;

    return 0;
}

ENetSocket ENetSocket::accept(ENetAddress* address)
{
    SOCKET result;
    struct sockaddr_in sin = {0};
    int sinLength = sizeof(struct sockaddr_in);

    result = ::accept(socket, address != NULL ? (struct sockaddr*)&sin : NULL,
        address != NULL ? &sinLength : NULL);

    if (result == INVALID_SOCKET)
        return INVALID_SOCKET;

    if (address != NULL) {
        address->host = (enet_uint32)sin.sin_addr.s_addr;
        address->port = ENET_NET_TO_HOST_16(sin.sin_port);
    }

    return result;
}

int ENetSocket::shutdown(ENetSocketShutdown how)
{
    return ::shutdown(socket, (int)how) == SOCKET_ERROR ? -1 : 0;
}

void ENetSocket::destroy()
{
    if (socket != INVALID_SOCKET)
        closesocket(socket);
}

int ENetSocket::send(const ENetAddress* address, const ENetBuffer* buffers, size_t bufferCount)
{
    struct sockaddr_in sin;
    DWORD sentLength;

    if (address != NULL) {
        memset(&sin, 0, sizeof(struct sockaddr_in));

        sin.sin_family      = AF_INET;
        sin.sin_port        = ENET_HOST_TO_NET_16(address->port);
        sin.sin_addr.s_addr = address->host;
    }

    if (WSASendTo(socket, (LPWSABUF)buffers, (DWORD)bufferCount, &sentLength, 0,
            address != NULL ? (struct sockaddr*)&sin : NULL,
            address != NULL ? sizeof(struct sockaddr_in) : 0, NULL,
            NULL) == SOCKET_ERROR) {
        if (WSAGetLastError() == WSAEWOULDBLOCK)
            return 0;

        return -1;
    }

    return (int)sentLength;
}

int ENetSocket::receive(ENetAddress* address, ENetBuffer* buffers, size_t bufferCount)
{
    INT sinLength = sizeof(struct sockaddr_in);
    DWORD flags = 0, recvLength;
    struct sockaddr_in sin = { 0 };

    if (WSARecvFrom(socket, (LPWSABUF)buffers, (DWORD)bufferCount, &recvLength,
            &flags, address != NULL ? (struct sockaddr*)&sin : NULL,
            address != NULL ? &sinLength : NULL, NULL,
            NULL) == SOCKET_ERROR) {
        switch (WSAGetLastError()) {
        case WSAEWOULDBLOCK:
        case WSAECONNRESET:
            return 0;
        }

        return -1;
    }

    if (flags & MSG_PARTIAL)
        return -1;

    if (address != NULL) {
        address->host = (enet_uint32)sin.sin_addr.s_addr;
        address->port = ENET_NET_TO_HOST_16(sin.sin_port);
    }

    return (int)recvLength;
}

int ENetSocket::select(ENetSocketSet* readSet, ENetSocketSet* writeSet, enet_uint32 timeout)
{
    struct timeval timeVal;

    timeVal.tv_sec  = timeout / 1000;
    timeVal.tv_usec = (timeout % 1000) * 1000;

    return ::select(socket + 1, readSet, writeSet, NULL, &timeVal);
}

int ENetSocket::wait(enet_uint32* condition, enet_uint32 timeout)
{
    fd_set readSet, writeSet;
    struct timeval timeVal;
    int selectCount;

    timeVal.tv_sec  = timeout / 1000;
    timeVal.tv_usec = (timeout % 1000) * 1000;

    FD_ZERO(&readSet);
    FD_ZERO(&writeSet);

    if (*condition & ENET_SOCKET_WAIT_SEND)
        FD_SET(socket, &writeSet);

    if (*condition & ENET_SOCKET_WAIT_RECEIVE)
        FD_SET(socket, &readSet);

    selectCount = ::select(socket + 1, &readSet, &writeSet, NULL, &timeVal);

    if (selectCount < 0)
        return -1;

    *condition = ENET_SOCKET_WAIT_NONE;

    if (selectCount == 0)
        return 0;

    if (FD_ISSET(socket, &writeSet))
        *condition |= ENET_SOCKET_WAIT_SEND;

    if (FD_ISSET(socket, &readSet))
        *condition |= ENET_SOCKET_WAIT_RECEIVE;

    return 0;
}

#endif

//-----------------------------------------------------------------------------
// Protocol functions

static size_t commandSizes[ENET_PROTOCOL_COMMAND_COUNT] = {
    0, sizeof(ENetProtocolAcknowledge), sizeof(ENetProtocolConnect),
    sizeof(ENetProtocolVerifyConnect), sizeof(ENetProtocolDisconnect),
    sizeof(ENetProtocolPing), sizeof(ENetProtocolSendReliable),
    sizeof(ENetProtocolSendUnreliable), sizeof(ENetProtocolSendFragment),
    sizeof(ENetProtocolSendUnsequenced), sizeof(ENetProtocolBandwidthLimit),
    sizeof(ENetProtocolThrottleConfigure), sizeof(ENetProtocolSendFragment)
};

size_t enet_protocol_command_size(enet_uint8 commandNumber)
{
    return commandSizes[commandNumber & ENET_PROTOCOL_COMMAND_MASK];
}

static void enet_protocol_change_state(ENetHost* host, ENetPeer* peer, ENetPeerState state)
{
    ENET_UNUSED(host);

    if (state == ENET_PEER_STATE_CONNECTED || state == ENET_PEER_STATE_DISCONNECT_LATER)
        peer->on_connect();
    else
        peer->on_disconnect();

    peer->state = state;
}

static void enet_protocol_dispatch_state(ENetHost* host, ENetPeer* peer, ENetPeerState state)
{
    enet_protocol_change_state(host, peer, state);

    if (!peer->needsDispatch) {
        ENetList::insert(host->dispatchQueue.end(), &peer->dispatchList);

        peer->needsDispatch = 1;
    }
}

static int enet_protocol_dispatch_incoming_commands(ENetHost* host, ENetEvent* event)
{
    while (!host->dispatchQueue.empty()) {
        ENetPeer* peer = (ENetPeer*)ENetList::remove(host->dispatchQueue.begin());

        peer->needsDispatch = 0;

        switch (peer->state) {
        case ENET_PEER_STATE_CONNECTION_PENDING:
        case ENET_PEER_STATE_CONNECTION_SUCCEEDED:
            enet_protocol_change_state(host, peer, ENET_PEER_STATE_CONNECTED);

            event->type = ENET_EVENT_TYPE_CONNECT;
            event->peer = peer;
            event->data = peer->eventData;

            return 1;

        case ENET_PEER_STATE_ZOMBIE:
            host->recalculateBandwidthLimits = 1;

            event->type = ENET_EVENT_TYPE_DISCONNECT;
            event->peer = peer;
            event->data = peer->eventData;

            peer->reset();

            return 1;

        case ENET_PEER_STATE_CONNECTED:
            if (peer->dispatchedCommands.empty())
                continue;

            event->packet = peer->receive(&event->channelID);
            if (event->packet == NULL)
                continue;

            event->type = ENET_EVENT_TYPE_RECEIVE;
            event->peer = peer;

            if (!peer->dispatchedCommands.empty()) {
                peer->needsDispatch = 1;

                ENetList::insert(host->dispatchQueue.end(), &peer->dispatchList);
            }

            return 1;

        default:
            break;
        }
    }

    return 0;
}

static void enet_protocol_notify_connect(ENetHost* host, ENetPeer* peer, ENetEvent* event)
{
    host->recalculateBandwidthLimits = 1;

    if (event != NULL) {
        enet_protocol_change_state(host, peer, ENET_PEER_STATE_CONNECTED);

        event->type = ENET_EVENT_TYPE_CONNECT;
        event->peer = peer;
        event->data = peer->eventData;
    }
    else
        enet_protocol_dispatch_state(host, peer,
            peer->state == ENET_PEER_STATE_CONNECTING
                ? ENET_PEER_STATE_CONNECTION_SUCCEEDED
                : ENET_PEER_STATE_CONNECTION_PENDING);
}

static void enet_protocol_notify_disconnect(ENetHost* host, ENetPeer* peer, ENetEvent* event)
{
    if (peer->state >= ENET_PEER_STATE_CONNECTION_PENDING)
        host->recalculateBandwidthLimits = 1;

    if (peer->state != ENET_PEER_STATE_CONNECTING && peer->state < ENET_PEER_STATE_CONNECTION_SUCCEEDED)
        peer->reset();
    else if (event != NULL) {
        event->type = ENET_EVENT_TYPE_DISCONNECT;
        event->peer = peer;
        event->data = 0;

        peer->reset();
    }
    else {
        peer->eventData = 0;

        enet_protocol_dispatch_state(host, peer, ENET_PEER_STATE_ZOMBIE);
    }
}

static void enet_protocol_remove_sent_unreliable_commands(ENetPeer* peer)
{
    ENetOutgoingCommand* outgoingCommand;

    while (!peer->sentUnreliableCommands.empty()) {
        outgoingCommand = (ENetOutgoingCommand*)peer->sentUnreliableCommands.front();

        ENetList::remove(&outgoingCommand->outgoingCommandList);

        if (outgoingCommand->packet != NULL) {
            --outgoingCommand->packet->referenceCount;

            if (outgoingCommand->packet->referenceCount == 0) {
                outgoingCommand->packet->flags |= ENET_PACKET_FLAG_SENT;

                outgoingCommand->packet->destroy();
            }
        }

        enet_free(outgoingCommand);
    }
}

static ENetProtocolCommand enet_protocol_remove_sent_reliable_command(ENetPeer* peer, enet_uint16 reliableSequenceNumber, enet_uint8 channelID)
{
    ENetOutgoingCommand* outgoingCommand = NULL;
    ENetListIterator currentCommand;
    ENetProtocolCommand commandNumber;
    int wasSent = 1;

    for (currentCommand = peer->sentReliableCommands.begin();
         currentCommand != peer->sentReliableCommands.end();
         currentCommand = ENetList::next(currentCommand)) {
        outgoingCommand = (ENetOutgoingCommand*)currentCommand;

        if (outgoingCommand->reliableSequenceNumber == reliableSequenceNumber && outgoingCommand->command.header.channelID == channelID)
            break;
    }

    if (currentCommand == peer->sentReliableCommands.end()) {
        for (currentCommand = peer->outgoingReliableCommands.begin();
             currentCommand != peer->outgoingReliableCommands.end();
             currentCommand = ENetList::next(currentCommand)) {
            outgoingCommand = (ENetOutgoingCommand*)currentCommand;

            if (outgoingCommand->sendAttempts < 1)
                return ENET_PROTOCOL_COMMAND_NONE;

            if (outgoingCommand->reliableSequenceNumber == reliableSequenceNumber && outgoingCommand->command.header.channelID == channelID)
                break;
        }

        if (currentCommand == peer->outgoingReliableCommands.end())
            return ENET_PROTOCOL_COMMAND_NONE;

        wasSent = 0;
    }

    if (outgoingCommand == NULL)
        return ENET_PROTOCOL_COMMAND_NONE;

    if (channelID < peer->channelCount) {
        ENetChannel* channel = &peer->channels[channelID];
        enet_uint16 reliableWindow = reliableSequenceNumber / ENET_PEER_RELIABLE_WINDOW_SIZE;
        if (channel->reliableWindows[reliableWindow] > 0) {
            --channel->reliableWindows[reliableWindow];
            if (!channel->reliableWindows[reliableWindow])
                channel->usedReliableWindows &= ~(1 << reliableWindow);
        }
    }

    commandNumber = (ENetProtocolCommand)(outgoingCommand->command.header.command & ENET_PROTOCOL_COMMAND_MASK);

    ENetList::remove(&outgoingCommand->outgoingCommandList);

    if (outgoingCommand->packet != NULL) {
        if (wasSent)
            peer->reliableDataInTransit -= outgoingCommand->fragmentLength;

        --outgoingCommand->packet->referenceCount;

        if (outgoingCommand->packet->referenceCount == 0) {
            outgoingCommand->packet->flags |= ENET_PACKET_FLAG_SENT;

            outgoingCommand->packet->destroy();
        }
    }

    enet_free(outgoingCommand);

    if (peer->sentReliableCommands.empty())
        return commandNumber;

    outgoingCommand = (ENetOutgoingCommand*)peer->sentReliableCommands.front();

    peer->nextTimeout = outgoingCommand->sentTime + outgoingCommand->roundTripTimeout;

    return commandNumber;
}

static ENetPeer* enet_protocol_handle_connect(ENetHost* host, ENetProtocolHeader* header, ENetProtocol* command)
{
    ENET_UNUSED(header);

    enet_uint8 incomingSessionID, outgoingSessionID;
    enet_uint32 mtu, windowSize;
    ENetChannel* channel;
    size_t channelCount, duplicatePeers = 0;
    ENetPeer* currentPeer, * peer = NULL;
    ENetProtocol verifyCommand;

    channelCount = ENET_NET_TO_HOST_32(command->connect.channelCount);

    if (channelCount < ENET_PROTOCOL_MINIMUM_CHANNEL_COUNT || channelCount > ENET_PROTOCOL_MAXIMUM_CHANNEL_COUNT)
        return NULL;

    for (currentPeer = host->peers; currentPeer < &host->peers[host->peerCount];
         ++currentPeer) {
        if (currentPeer->state == ENET_PEER_STATE_DISCONNECTED) {
            if (peer == NULL)
                peer = currentPeer;
        }
        else if (currentPeer->state != ENET_PEER_STATE_CONNECTING && currentPeer->address.host == host->receivedAddress.host) {
            if (currentPeer->address.port == host->receivedAddress.port && currentPeer->connectID == command->connect.connectID)
                return NULL;

            ++duplicatePeers;
        }
    }

    if (peer == NULL || duplicatePeers >= host->duplicatePeers)
        return NULL;

    if (channelCount > host->channelLimit)
        channelCount = host->channelLimit;
    peer->channels = (ENetChannel*)enet_malloc(channelCount * sizeof(ENetChannel));
    if (peer->channels == NULL)
        return NULL;
    peer->channelCount = channelCount;
    peer->state = ENET_PEER_STATE_ACKNOWLEDGING_CONNECT;
    peer->connectID = command->connect.connectID;
    peer->address = host->receivedAddress;
    peer->outgoingPeerID = ENET_NET_TO_HOST_16(command->connect.outgoingPeerID);
    peer->incomingBandwidth = ENET_NET_TO_HOST_32(command->connect.incomingBandwidth);
    peer->outgoingBandwidth = ENET_NET_TO_HOST_32(command->connect.outgoingBandwidth);
    peer->packetThrottleInterval = ENET_NET_TO_HOST_32(command->connect.packetThrottleInterval);
    peer->packetThrottleAcceleration = ENET_NET_TO_HOST_32(command->connect.packetThrottleAcceleration);
    peer->packetThrottleDeceleration = ENET_NET_TO_HOST_32(command->connect.packetThrottleDeceleration);
    peer->eventData = ENET_NET_TO_HOST_32(command->connect.data);

    incomingSessionID = command->connect.incomingSessionID == 0xFF
        ? peer->outgoingSessionID
        : command->connect.incomingSessionID;
    incomingSessionID = (incomingSessionID + 1) & (ENET_PROTOCOL_HEADER_SESSION_MASK >> ENET_PROTOCOL_HEADER_SESSION_SHIFT);
    if (incomingSessionID == peer->outgoingSessionID)
        incomingSessionID = (incomingSessionID + 1) & (ENET_PROTOCOL_HEADER_SESSION_MASK >> ENET_PROTOCOL_HEADER_SESSION_SHIFT);
    peer->outgoingSessionID = incomingSessionID;

    outgoingSessionID = command->connect.outgoingSessionID == 0xFF
        ? peer->incomingSessionID
        : command->connect.outgoingSessionID;
    outgoingSessionID = (outgoingSessionID + 1) & (ENET_PROTOCOL_HEADER_SESSION_MASK >> ENET_PROTOCOL_HEADER_SESSION_SHIFT);
    if (outgoingSessionID == peer->incomingSessionID)
        outgoingSessionID = (outgoingSessionID + 1) & (ENET_PROTOCOL_HEADER_SESSION_MASK >> ENET_PROTOCOL_HEADER_SESSION_SHIFT);
    peer->incomingSessionID = outgoingSessionID;

    for (channel = peer->channels; channel < &peer->channels[channelCount];
         ++channel) {
        channel->outgoingReliableSequenceNumber = 0;
        channel->outgoingUnreliableSequenceNumber = 0;
        channel->incomingReliableSequenceNumber = 0;
        channel->incomingUnreliableSequenceNumber = 0;

        channel->incomingReliableCommands.clear();
        channel->incomingUnreliableCommands.clear();

        channel->usedReliableWindows = 0;
        memset(channel->reliableWindows, 0, sizeof(channel->reliableWindows));
    }

    mtu = ENET_NET_TO_HOST_32(command->connect.mtu);

    if (mtu < ENET_PROTOCOL_MINIMUM_MTU)
        mtu = ENET_PROTOCOL_MINIMUM_MTU;
    else if (mtu > ENET_PROTOCOL_MAXIMUM_MTU)
        mtu = ENET_PROTOCOL_MAXIMUM_MTU;

    peer->mtu = mtu;

    if (host->outgoingBandwidth == 0 && peer->incomingBandwidth == 0)
        peer->windowSize = ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE;
    else if (host->outgoingBandwidth == 0 || peer->incomingBandwidth == 0)
        peer->windowSize = (ENET_MAX(host->outgoingBandwidth, peer->incomingBandwidth) / ENET_PEER_WINDOW_SIZE_SCALE) * ENET_PROTOCOL_MINIMUM_WINDOW_SIZE;
    else
        peer->windowSize = (ENET_MIN(host->outgoingBandwidth, peer->incomingBandwidth) / ENET_PEER_WINDOW_SIZE_SCALE) * ENET_PROTOCOL_MINIMUM_WINDOW_SIZE;

    if (peer->windowSize < ENET_PROTOCOL_MINIMUM_WINDOW_SIZE)
        peer->windowSize = ENET_PROTOCOL_MINIMUM_WINDOW_SIZE;
    else if (peer->windowSize > ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE)
        peer->windowSize = ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE;

    if (host->incomingBandwidth == 0)
        windowSize = ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE;
    else
        windowSize = (host->incomingBandwidth / ENET_PEER_WINDOW_SIZE_SCALE) * ENET_PROTOCOL_MINIMUM_WINDOW_SIZE;

    if (windowSize > ENET_NET_TO_HOST_32(command->connect.windowSize))
        windowSize = ENET_NET_TO_HOST_32(command->connect.windowSize);

    if (windowSize < ENET_PROTOCOL_MINIMUM_WINDOW_SIZE)
        windowSize = ENET_PROTOCOL_MINIMUM_WINDOW_SIZE;
    else if (windowSize > ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE)
        windowSize = ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE;

    verifyCommand.header.command = ENET_PROTOCOL_COMMAND_VERIFY_CONNECT | ENET_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE;
    verifyCommand.header.channelID = 0xFF;
    verifyCommand.verifyConnect.outgoingPeerID = ENET_HOST_TO_NET_16(peer->incomingPeerID);
    verifyCommand.verifyConnect.incomingSessionID = incomingSessionID;
    verifyCommand.verifyConnect.outgoingSessionID = outgoingSessionID;
    verifyCommand.verifyConnect.mtu = ENET_HOST_TO_NET_32(peer->mtu);
    verifyCommand.verifyConnect.windowSize = ENET_HOST_TO_NET_32(windowSize);
    verifyCommand.verifyConnect.channelCount = ENET_HOST_TO_NET_32(channelCount);
    verifyCommand.verifyConnect.incomingBandwidth = ENET_HOST_TO_NET_32(host->incomingBandwidth);
    verifyCommand.verifyConnect.outgoingBandwidth = ENET_HOST_TO_NET_32(host->outgoingBandwidth);
    verifyCommand.verifyConnect.packetThrottleInterval = ENET_HOST_TO_NET_32(peer->packetThrottleInterval);
    verifyCommand.verifyConnect.packetThrottleAcceleration = ENET_HOST_TO_NET_32(peer->packetThrottleAcceleration);
    verifyCommand.verifyConnect.packetThrottleDeceleration = ENET_HOST_TO_NET_32(peer->packetThrottleDeceleration);
    verifyCommand.verifyConnect.connectID = peer->connectID;

    peer->queue_outgoing_command(&verifyCommand, NULL, 0, 0);

    return peer;
}

static int enet_protocol_handle_send_reliable(ENetHost* host, ENetPeer* peer, const ENetProtocol* command, enet_uint8** currentData)
{
    size_t dataLength;

    if (command->header.channelID >= peer->channelCount || (peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER))
        return -1;

    dataLength = ENET_NET_TO_HOST_16(command->sendReliable.dataLength);
    *currentData += dataLength;
    if (dataLength > host->maximumPacketSize || *currentData < host->receivedData || *currentData > &host->receivedData[host->receivedDataLength])
        return -1;

    if (peer->queue_incoming_command(command,
            (const enet_uint8*)command + sizeof(ENetProtocolSendReliable),
            dataLength, ENET_PACKET_FLAG_RELIABLE, 0) == NULL)
        return -1;

    return 0;
}

static int enet_protocol_handle_send_unsequenced(ENetHost* host, ENetPeer* peer, const ENetProtocol* command, enet_uint8** currentData)
{
    enet_uint32 unsequencedGroup, index;
    size_t dataLength;

    if (command->header.channelID >= peer->channelCount || (peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER))
        return -1;

    dataLength = ENET_NET_TO_HOST_16(command->sendUnsequenced.dataLength);
    *currentData += dataLength;
    if (dataLength > host->maximumPacketSize || *currentData < host->receivedData || *currentData > &host->receivedData[host->receivedDataLength])
        return -1;

    unsequencedGroup = ENET_NET_TO_HOST_16(command->sendUnsequenced.unsequencedGroup);
    index = unsequencedGroup % ENET_PEER_UNSEQUENCED_WINDOW_SIZE;

    if (unsequencedGroup < peer->incomingUnsequencedGroup)
        unsequencedGroup += 0x10000;

    if (unsequencedGroup >= (enet_uint32)peer->incomingUnsequencedGroup + ENET_PEER_FREE_UNSEQUENCED_WINDOWS * ENET_PEER_UNSEQUENCED_WINDOW_SIZE)
        return 0;

    unsequencedGroup &= 0xFFFF;

    if (unsequencedGroup - index != peer->incomingUnsequencedGroup) {
        peer->incomingUnsequencedGroup = unsequencedGroup - index;

        memset(peer->unsequencedWindow, 0, sizeof(peer->unsequencedWindow));
    }
    else if (peer->unsequencedWindow[index / 32] & (1 << (index % 32)))
        return 0;

    if (peer->queue_incoming_command(command,
            (const enet_uint8*)command + sizeof(ENetProtocolSendUnsequenced),
            dataLength, ENET_PACKET_FLAG_UNSEQUENCED, 0) == NULL)
        return -1;

    peer->unsequencedWindow[index / 32] |= 1 << (index % 32);

    return 0;
}

static int enet_protocol_handle_send_unreliable(ENetHost* host, ENetPeer* peer, const ENetProtocol* command, enet_uint8** currentData)
{
    size_t dataLength;

    if (command->header.channelID >= peer->channelCount || (peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER))
        return -1;

    dataLength = ENET_NET_TO_HOST_16(command->sendUnreliable.dataLength);
    *currentData += dataLength;
    if (dataLength > host->maximumPacketSize || *currentData < host->receivedData || *currentData > &host->receivedData[host->receivedDataLength])
        return -1;

    if (peer->queue_incoming_command(command,
            (const enet_uint8*)command + sizeof(ENetProtocolSendUnreliable),
            dataLength, 0, 0) == NULL)
        return -1;

    return 0;
}

static int enet_protocol_handle_send_fragment(ENetHost* host, ENetPeer* peer, const ENetProtocol* command, enet_uint8** currentData)
{
    enet_uint32 fragmentNumber, fragmentCount, fragmentOffset, fragmentLength,
        startSequenceNumber, totalLength;
    ENetChannel* channel;
    enet_uint16 startWindow, currentWindow;
    ENetListIterator currentCommand;
    ENetIncomingCommand* startCommand = NULL;

    if (command->header.channelID >= peer->channelCount || (peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER))
        return -1;

    fragmentLength = ENET_NET_TO_HOST_16(command->sendFragment.dataLength);
    *currentData += fragmentLength;
    if (fragmentLength > host->maximumPacketSize || *currentData < host->receivedData || *currentData > &host->receivedData[host->receivedDataLength])
        return -1;

    channel = &peer->channels[command->header.channelID];
    startSequenceNumber = ENET_NET_TO_HOST_16(command->sendFragment.startSequenceNumber);
    startWindow = startSequenceNumber / ENET_PEER_RELIABLE_WINDOW_SIZE;
    currentWindow = channel->incomingReliableSequenceNumber / ENET_PEER_RELIABLE_WINDOW_SIZE;

    if (startSequenceNumber < channel->incomingReliableSequenceNumber)
        startWindow += ENET_PEER_RELIABLE_WINDOWS;

    if (startWindow < currentWindow || startWindow >= currentWindow + ENET_PEER_FREE_RELIABLE_WINDOWS - 1)
        return 0;

    fragmentNumber = ENET_NET_TO_HOST_32(command->sendFragment.fragmentNumber);
    fragmentCount = ENET_NET_TO_HOST_32(command->sendFragment.fragmentCount);
    fragmentOffset = ENET_NET_TO_HOST_32(command->sendFragment.fragmentOffset);
    totalLength = ENET_NET_TO_HOST_32(command->sendFragment.totalLength);

    if (fragmentCount > ENET_PROTOCOL_MAXIMUM_FRAGMENT_COUNT || fragmentNumber >= fragmentCount || totalLength > host->maximumPacketSize || fragmentOffset >= totalLength || fragmentLength > totalLength - fragmentOffset)
        return -1;

    for (currentCommand = ENetList::previous(channel->incomingReliableCommands.end());
         currentCommand != channel->incomingReliableCommands.end();
         currentCommand = ENetList::previous(currentCommand)) {
        ENetIncomingCommand* incomingCommand = (ENetIncomingCommand*)currentCommand;

        if (startSequenceNumber >= channel->incomingReliableSequenceNumber) {
            if (incomingCommand->reliableSequenceNumber < channel->incomingReliableSequenceNumber)
                continue;
        }
        else if (incomingCommand->reliableSequenceNumber >= channel->incomingReliableSequenceNumber)
            break;

        if (incomingCommand->reliableSequenceNumber <= startSequenceNumber) {
            if (incomingCommand->reliableSequenceNumber < startSequenceNumber)
                break;

            if ((incomingCommand->command.header.command & ENET_PROTOCOL_COMMAND_MASK) != ENET_PROTOCOL_COMMAND_SEND_FRAGMENT || totalLength != incomingCommand->packet->dataLength || fragmentCount != incomingCommand->fragmentCount)
                return -1;

            startCommand = incomingCommand;
            break;
        }
    }

    if (startCommand == NULL) {
        ENetProtocol hostCommand = *command;

        hostCommand.header.reliableSequenceNumber = startSequenceNumber;

        startCommand = peer->queue_incoming_command(
            &hostCommand, NULL, totalLength, ENET_PACKET_FLAG_RELIABLE,
            fragmentCount);
        if (startCommand == NULL)
            return -1;
    }

    if ((startCommand->fragments[fragmentNumber / 32] & (1 << (fragmentNumber % 32))) == 0) {
        --startCommand->fragmentsRemaining;

        startCommand->fragments[fragmentNumber / 32] |= (1 << (fragmentNumber % 32));

        if (fragmentOffset + fragmentLength > startCommand->packet->dataLength)
            fragmentLength = startCommand->packet->dataLength - fragmentOffset;

        memcpy(startCommand->packet->data + fragmentOffset,
            (enet_uint8*)command + sizeof(ENetProtocolSendFragment),
            fragmentLength);

        if (startCommand->fragmentsRemaining <= 0)
            peer->dispatch_incoming_reliable_commands(channel);
    }

    return 0;
}

static int enet_protocol_handle_send_unreliable_fragment(ENetHost* host, ENetPeer* peer, const ENetProtocol* command, enet_uint8** currentData)
{
    enet_uint32 fragmentNumber, fragmentCount, fragmentOffset, fragmentLength,
        reliableSequenceNumber, startSequenceNumber, totalLength;
    enet_uint16 reliableWindow, currentWindow;
    ENetChannel* channel;
    ENetListIterator currentCommand;
    ENetIncomingCommand* startCommand = NULL;

    if (command->header.channelID >= peer->channelCount || (peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER))
        return -1;

    fragmentLength = ENET_NET_TO_HOST_16(command->sendFragment.dataLength);
    *currentData += fragmentLength;
    if (fragmentLength > host->maximumPacketSize || *currentData < host->receivedData || *currentData > &host->receivedData[host->receivedDataLength])
        return -1;

    channel = &peer->channels[command->header.channelID];
    reliableSequenceNumber = command->header.reliableSequenceNumber;
    startSequenceNumber = ENET_NET_TO_HOST_16(command->sendFragment.startSequenceNumber);

    reliableWindow = reliableSequenceNumber / ENET_PEER_RELIABLE_WINDOW_SIZE;
    currentWindow = channel->incomingReliableSequenceNumber / ENET_PEER_RELIABLE_WINDOW_SIZE;

    if (reliableSequenceNumber < channel->incomingReliableSequenceNumber)
        reliableWindow += ENET_PEER_RELIABLE_WINDOWS;

    if (reliableWindow < currentWindow || reliableWindow >= currentWindow + ENET_PEER_FREE_RELIABLE_WINDOWS - 1)
        return 0;

    if (reliableSequenceNumber == channel->incomingReliableSequenceNumber && startSequenceNumber <= channel->incomingUnreliableSequenceNumber)
        return 0;

    fragmentNumber = ENET_NET_TO_HOST_32(command->sendFragment.fragmentNumber);
    fragmentCount = ENET_NET_TO_HOST_32(command->sendFragment.fragmentCount);
    fragmentOffset = ENET_NET_TO_HOST_32(command->sendFragment.fragmentOffset);
    totalLength = ENET_NET_TO_HOST_32(command->sendFragment.totalLength);

    if (fragmentCount > ENET_PROTOCOL_MAXIMUM_FRAGMENT_COUNT || fragmentNumber >= fragmentCount || totalLength > host->maximumPacketSize || fragmentOffset >= totalLength || fragmentLength > totalLength - fragmentOffset)
        return -1;

    for (currentCommand = ENetList::previous(channel->incomingUnreliableCommands.end());
         currentCommand != channel->incomingUnreliableCommands.end();
         currentCommand = ENetList::previous(currentCommand)) {
        ENetIncomingCommand* incomingCommand = (ENetIncomingCommand*)currentCommand;

        if (reliableSequenceNumber >= channel->incomingReliableSequenceNumber) {
            if (incomingCommand->reliableSequenceNumber < channel->incomingReliableSequenceNumber)
                continue;
        }
        else if (incomingCommand->reliableSequenceNumber >= channel->incomingReliableSequenceNumber)
            break;

        if (incomingCommand->reliableSequenceNumber < reliableSequenceNumber)
            break;

        if (incomingCommand->reliableSequenceNumber > reliableSequenceNumber)
            continue;

        if (incomingCommand->unreliableSequenceNumber <= startSequenceNumber) {
            if (incomingCommand->unreliableSequenceNumber < startSequenceNumber)
                break;

            if ((incomingCommand->command.header.command & ENET_PROTOCOL_COMMAND_MASK) != ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE_FRAGMENT || totalLength != incomingCommand->packet->dataLength || fragmentCount != incomingCommand->fragmentCount)
                return -1;

            startCommand = incomingCommand;
            break;
        }
    }

    if (startCommand == NULL) {
        startCommand = peer->queue_incoming_command(command, NULL, totalLength, ENET_PACKET_FLAG_UNRELIABLE_FRAGMENT,
            fragmentCount);
        if (startCommand == NULL)
            return -1;
    }

    if ((startCommand->fragments[fragmentNumber / 32] & (1 << (fragmentNumber % 32))) == 0) {
        --startCommand->fragmentsRemaining;

        startCommand->fragments[fragmentNumber / 32] |= (1 << (fragmentNumber % 32));

        if (fragmentOffset + fragmentLength > startCommand->packet->dataLength)
            fragmentLength = startCommand->packet->dataLength - fragmentOffset;

        memcpy(startCommand->packet->data + fragmentOffset,
            (enet_uint8*)command + sizeof(ENetProtocolSendFragment),
            fragmentLength);

        if (startCommand->fragmentsRemaining <= 0)
            peer->dispatch_incoming_unreliable_commands(channel);
    }

    return 0;
}

static int enet_protocol_handle_ping(ENetHost* host, ENetPeer* peer, const ENetProtocol* command)
{
    ENET_UNUSED(command);
    ENET_UNUSED(host);

    if (peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER)
        return -1;

    return 0;
}

static int enet_protocol_handle_bandwidth_limit(ENetHost* host, ENetPeer* peer, const ENetProtocol* command)
{
    if (peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER)
        return -1;

    if (peer->incomingBandwidth != 0)
        --host->bandwidthLimitedPeers;

    peer->incomingBandwidth = ENET_NET_TO_HOST_32(command->bandwidthLimit.incomingBandwidth);
    peer->outgoingBandwidth = ENET_NET_TO_HOST_32(command->bandwidthLimit.outgoingBandwidth);

    if (peer->incomingBandwidth != 0)
        ++host->bandwidthLimitedPeers;

    if (peer->incomingBandwidth == 0 && host->outgoingBandwidth == 0)
        peer->windowSize = ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE;
    else if (peer->incomingBandwidth == 0 || host->outgoingBandwidth == 0)
        peer->windowSize = (ENET_MAX(peer->incomingBandwidth, host->outgoingBandwidth) / ENET_PEER_WINDOW_SIZE_SCALE) * ENET_PROTOCOL_MINIMUM_WINDOW_SIZE;
    else
        peer->windowSize = (ENET_MIN(peer->incomingBandwidth, host->outgoingBandwidth) / ENET_PEER_WINDOW_SIZE_SCALE) * ENET_PROTOCOL_MINIMUM_WINDOW_SIZE;

    if (peer->windowSize < ENET_PROTOCOL_MINIMUM_WINDOW_SIZE)
        peer->windowSize = ENET_PROTOCOL_MINIMUM_WINDOW_SIZE;
    else if (peer->windowSize > ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE)
        peer->windowSize = ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE;

    return 0;
}

static int enet_protocol_handle_throttle_configure(ENetHost* host, ENetPeer* peer, const ENetProtocol* command)
{
    ENET_UNUSED(host);

    if (peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER)
        return -1;

    peer->packetThrottleInterval = ENET_NET_TO_HOST_32(command->throttleConfigure.packetThrottleInterval);
    peer->packetThrottleAcceleration = ENET_NET_TO_HOST_32(
        command->throttleConfigure.packetThrottleAcceleration);
    peer->packetThrottleDeceleration = ENET_NET_TO_HOST_32(
        command->throttleConfigure.packetThrottleDeceleration);

    return 0;
}

static int enet_protocol_handle_disconnect(ENetHost* host, ENetPeer* peer, const ENetProtocol* command)
{
    if (peer->state == ENET_PEER_STATE_DISCONNECTED || peer->state == ENET_PEER_STATE_ZOMBIE || peer->state == ENET_PEER_STATE_ACKNOWLEDGING_DISCONNECT)
        return 0;

    peer->reset_queues();

    if (peer->state == ENET_PEER_STATE_CONNECTION_SUCCEEDED || peer->state == ENET_PEER_STATE_DISCONNECTING || peer->state == ENET_PEER_STATE_CONNECTING)
        enet_protocol_dispatch_state(host, peer, ENET_PEER_STATE_ZOMBIE);
    else if (peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER) {
        if (peer->state == ENET_PEER_STATE_CONNECTION_PENDING)
            host->recalculateBandwidthLimits = 1;

        peer->reset();
    }
    else if (command->header.command & ENET_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE)
        enet_protocol_change_state(host, peer,
            ENET_PEER_STATE_ACKNOWLEDGING_DISCONNECT);
    else
        enet_protocol_dispatch_state(host, peer, ENET_PEER_STATE_ZOMBIE);

    if (peer->state != ENET_PEER_STATE_DISCONNECTED)
        peer->eventData = ENET_NET_TO_HOST_32(command->disconnect.data);

    return 0;
}

static int enet_protocol_handle_acknowledge(ENetHost* host, ENetEvent* event,
    ENetPeer* peer, const ENetProtocol* command)
{
    enet_uint32 roundTripTime, receivedSentTime, receivedReliableSequenceNumber;
    ENetProtocolCommand commandNumber;

    if (peer->state == ENET_PEER_STATE_DISCONNECTED || peer->state == ENET_PEER_STATE_ZOMBIE)
        return 0;

    receivedSentTime = ENET_NET_TO_HOST_16(command->acknowledge.receivedSentTime);
    receivedSentTime |= host->serviceTime & 0xFFFF0000;
    if ((receivedSentTime & 0x8000) > (host->serviceTime & 0x8000))
        receivedSentTime -= 0x10000;

    if (ENET_TIME_LESS(host->serviceTime, receivedSentTime))
        return 0;

    peer->lastReceiveTime = host->serviceTime;
    peer->earliestTimeout = 0;

    roundTripTime = ENET_TIME_DIFFERENCE(host->serviceTime, receivedSentTime);

    peer->throttle(roundTripTime);

    peer->roundTripTimeVariance -= peer->roundTripTimeVariance / 4;

    if (roundTripTime >= peer->roundTripTime) {
        peer->roundTripTime += (roundTripTime - peer->roundTripTime) / 8;
        peer->roundTripTimeVariance += (roundTripTime - peer->roundTripTime) / 4;
    }
    else {
        peer->roundTripTime -= (peer->roundTripTime - roundTripTime) / 8;
        peer->roundTripTimeVariance += (peer->roundTripTime - roundTripTime) / 4;
    }

    if (peer->roundTripTime < peer->lowestRoundTripTime)
        peer->lowestRoundTripTime = peer->roundTripTime;

    if (peer->roundTripTimeVariance > peer->highestRoundTripTimeVariance)
        peer->highestRoundTripTimeVariance = peer->roundTripTimeVariance;

    if (peer->packetThrottleEpoch == 0 || ENET_TIME_DIFFERENCE(host->serviceTime, peer->packetThrottleEpoch) >= peer->packetThrottleInterval) {
        peer->lastRoundTripTime = peer->lowestRoundTripTime;
        peer->lastRoundTripTimeVariance = peer->highestRoundTripTimeVariance;
        peer->lowestRoundTripTime = peer->roundTripTime;
        peer->highestRoundTripTimeVariance = peer->roundTripTimeVariance;
        peer->packetThrottleEpoch = host->serviceTime;
    }

    receivedReliableSequenceNumber = ENET_NET_TO_HOST_16(command->acknowledge.receivedReliableSequenceNumber);

    commandNumber = enet_protocol_remove_sent_reliable_command(
        peer, receivedReliableSequenceNumber, command->header.channelID);

    switch (peer->state) {
    case ENET_PEER_STATE_ACKNOWLEDGING_CONNECT:
        if (commandNumber != ENET_PROTOCOL_COMMAND_VERIFY_CONNECT)
            return -1;

        enet_protocol_notify_connect(host, peer, event);
        break;

    case ENET_PEER_STATE_DISCONNECTING:
        if (commandNumber != ENET_PROTOCOL_COMMAND_DISCONNECT)
            return -1;

        enet_protocol_notify_disconnect(host, peer, event);
        break;

    case ENET_PEER_STATE_DISCONNECT_LATER:
        if (peer->outgoingReliableCommands.empty() && peer->outgoingUnreliableCommands.empty() && peer->sentReliableCommands.empty())
            peer->disconnect(peer->eventData);
        break;

    default:
        break;
    }

    return 0;
}

static int enet_protocol_handle_verify_connect(ENetHost* host, ENetEvent* event,
    ENetPeer* peer, const ENetProtocol* command)
{
    enet_uint32 mtu, windowSize;
    size_t channelCount;

    if (peer->state != ENET_PEER_STATE_CONNECTING)
        return 0;

    channelCount = ENET_NET_TO_HOST_32(command->verifyConnect.channelCount);

    if (channelCount < ENET_PROTOCOL_MINIMUM_CHANNEL_COUNT || channelCount > ENET_PROTOCOL_MAXIMUM_CHANNEL_COUNT || ENET_NET_TO_HOST_32(command->verifyConnect.packetThrottleInterval) != peer->packetThrottleInterval || ENET_NET_TO_HOST_32(command->verifyConnect.packetThrottleAcceleration) != peer->packetThrottleAcceleration || ENET_NET_TO_HOST_32(command->verifyConnect.packetThrottleDeceleration) != peer->packetThrottleDeceleration || command->verifyConnect.connectID != peer->connectID) {
        peer->eventData = 0;

        enet_protocol_dispatch_state(host, peer, ENET_PEER_STATE_ZOMBIE);

        return -1;
    }

    enet_protocol_remove_sent_reliable_command(peer, 1, 0xFF);

    if (channelCount < peer->channelCount)
        peer->channelCount = channelCount;

    peer->outgoingPeerID = ENET_NET_TO_HOST_16(command->verifyConnect.outgoingPeerID);
    peer->incomingSessionID = command->verifyConnect.incomingSessionID;
    peer->outgoingSessionID = command->verifyConnect.outgoingSessionID;

    mtu = ENET_NET_TO_HOST_32(command->verifyConnect.mtu);

    if (mtu < ENET_PROTOCOL_MINIMUM_MTU)
        mtu = ENET_PROTOCOL_MINIMUM_MTU;
    else if (mtu > ENET_PROTOCOL_MAXIMUM_MTU)
        mtu = ENET_PROTOCOL_MAXIMUM_MTU;

    if (mtu < peer->mtu)
        peer->mtu = mtu;

    windowSize = ENET_NET_TO_HOST_32(command->verifyConnect.windowSize);

    if (windowSize < ENET_PROTOCOL_MINIMUM_WINDOW_SIZE)
        windowSize = ENET_PROTOCOL_MINIMUM_WINDOW_SIZE;

    if (windowSize > ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE)
        windowSize = ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE;

    if (windowSize < peer->windowSize)
        peer->windowSize = windowSize;

    peer->incomingBandwidth = ENET_NET_TO_HOST_32(command->verifyConnect.incomingBandwidth);
    peer->outgoingBandwidth = ENET_NET_TO_HOST_32(command->verifyConnect.outgoingBandwidth);

    enet_protocol_notify_connect(host, peer, event);
    return 0;
}

static int enet_protocol_handle_incoming_commands(ENetHost* host, ENetEvent* event)
{
    ENetProtocolHeader* header;
    ENetProtocol* command;
    ENetPeer* peer;
    enet_uint8* currentData;
    size_t headerSize;
    enet_uint16 peerID, flags;
    enet_uint8 sessionID;

    if (host->receivedDataLength < (size_t) & ((ENetProtocolHeader*)0)->sentTime)
        return 0;

    header = (ENetProtocolHeader*)host->receivedData;

    peerID = ENET_NET_TO_HOST_16(header->peerID);
    sessionID = (peerID & ENET_PROTOCOL_HEADER_SESSION_MASK) >> ENET_PROTOCOL_HEADER_SESSION_SHIFT;
    flags = peerID & ENET_PROTOCOL_HEADER_FLAG_MASK;
    peerID &= ~(ENET_PROTOCOL_HEADER_FLAG_MASK | ENET_PROTOCOL_HEADER_SESSION_MASK);

    headerSize = (flags & ENET_PROTOCOL_HEADER_FLAG_SENT_TIME
            ? sizeof(ENetProtocolHeader)
            : (size_t) & ((ENetProtocolHeader*)0)->sentTime);
    if (host->checksum != NULL)
        headerSize += sizeof(enet_uint32);

    if (peerID == ENET_PROTOCOL_MAXIMUM_PEER_ID)
        peer = NULL;
    else if (peerID >= host->peerCount)
        return 0;
    else {
        peer = &host->peers[peerID];

        if (peer->state == ENET_PEER_STATE_DISCONNECTED || peer->state == ENET_PEER_STATE_ZOMBIE || ((host->receivedAddress.host != peer->address.host || host->receivedAddress.port != peer->address.port) && peer->address.host != ENET_HOST_BROADCAST) || (peer->outgoingPeerID < ENET_PROTOCOL_MAXIMUM_PEER_ID && sessionID != peer->incomingSessionID))
            return 0;
    }

    if (flags & ENET_PROTOCOL_HEADER_FLAG_COMPRESSED) {
        size_t originalSize;
        if (host->compressor.context == NULL || host->compressor.decompress == NULL)
            return 0;

        originalSize = host->compressor.decompress(
            host->compressor.context, host->receivedData + headerSize,
            host->receivedDataLength - headerSize, host->packetData[1] + headerSize,
            sizeof(host->packetData[1]) - headerSize);
        if (originalSize <= 0 || originalSize > sizeof(host->packetData[1]) - headerSize)
            return 0;

        memcpy(host->packetData[1], header, headerSize);
        host->receivedData = host->packetData[1];
        host->receivedDataLength = headerSize + originalSize;
    }

    if (host->checksum != NULL) {
        enet_uint32* checksum = (enet_uint32*)&host
                                    ->receivedData[headerSize - sizeof(enet_uint32)],
                     desiredChecksum = *checksum;
        ENetBuffer buffer;

        *checksum = peer != NULL ? peer->connectID : 0;

        buffer.data = host->receivedData;
        buffer.dataLength = host->receivedDataLength;

        if (host->checksum(&buffer, 1) != desiredChecksum)
            return 0;
    }

    if (peer != NULL) {
        peer->address.host = host->receivedAddress.host;
        peer->address.port = host->receivedAddress.port;
        peer->incomingDataTotal += host->receivedDataLength;
    }

    currentData = host->receivedData + headerSize;

    while (currentData < &host->receivedData[host->receivedDataLength]) {
        enet_uint8 commandNumber;
        size_t commandSize;

        command = (ENetProtocol*)currentData;

        if (currentData + sizeof(ENetProtocolCommandHeader) > &host->receivedData[host->receivedDataLength])
            break;

        commandNumber = command->header.command & ENET_PROTOCOL_COMMAND_MASK;
        if (commandNumber >= ENET_PROTOCOL_COMMAND_COUNT)
            break;

        commandSize = commandSizes[commandNumber];
        if (commandSize == 0 || currentData + commandSize > &host->receivedData[host->receivedDataLength])
            break;

        currentData += commandSize;

        if (peer == NULL && commandNumber != ENET_PROTOCOL_COMMAND_CONNECT)
            break;

        command->header.reliableSequenceNumber = ENET_NET_TO_HOST_16(command->header.reliableSequenceNumber);

        switch (commandNumber) {
        case ENET_PROTOCOL_COMMAND_ACKNOWLEDGE:
            if (enet_protocol_handle_acknowledge(host, event, peer, command))
                goto commandError;
            break;

        case ENET_PROTOCOL_COMMAND_CONNECT:
            if (peer != NULL)
                goto commandError;
            peer = enet_protocol_handle_connect(host, header, command);
            if (peer == NULL)
                goto commandError;
            break;

        case ENET_PROTOCOL_COMMAND_VERIFY_CONNECT:
            if (enet_protocol_handle_verify_connect(host, event, peer, command))
                goto commandError;
            break;

        case ENET_PROTOCOL_COMMAND_DISCONNECT:
            if (enet_protocol_handle_disconnect(host, peer, command))
                goto commandError;
            break;

        case ENET_PROTOCOL_COMMAND_PING:
            if (enet_protocol_handle_ping(host, peer, command))
                goto commandError;
            break;

        case ENET_PROTOCOL_COMMAND_SEND_RELIABLE:
            if (enet_protocol_handle_send_reliable(host, peer, command,
                    &currentData))
                goto commandError;
            break;

        case ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE:
            if (enet_protocol_handle_send_unreliable(host, peer, command,
                    &currentData))
                goto commandError;
            break;

        case ENET_PROTOCOL_COMMAND_SEND_UNSEQUENCED:
            if (enet_protocol_handle_send_unsequenced(host, peer, command,
                    &currentData))
                goto commandError;
            break;

        case ENET_PROTOCOL_COMMAND_SEND_FRAGMENT:
            if (enet_protocol_handle_send_fragment(host, peer, command,
                    &currentData))
                goto commandError;
            break;

        case ENET_PROTOCOL_COMMAND_BANDWIDTH_LIMIT:
            if (enet_protocol_handle_bandwidth_limit(host, peer, command))
                goto commandError;
            break;

        case ENET_PROTOCOL_COMMAND_THROTTLE_CONFIGURE:
            if (enet_protocol_handle_throttle_configure(host, peer, command))
                goto commandError;
            break;

        case ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE_FRAGMENT:
            if (enet_protocol_handle_send_unreliable_fragment(host, peer, command,
                    &currentData))
                goto commandError;
            break;

        default:
            goto commandError;
        }

        if (peer != NULL && (command->header.command & ENET_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE) != 0) {
            enet_uint16 sentTime;

            if (!(flags & ENET_PROTOCOL_HEADER_FLAG_SENT_TIME))
                break;

            sentTime = ENET_NET_TO_HOST_16(header->sentTime);

            switch (peer->state) {
            case ENET_PEER_STATE_DISCONNECTING:
            case ENET_PEER_STATE_ACKNOWLEDGING_CONNECT:
            case ENET_PEER_STATE_DISCONNECTED:
            case ENET_PEER_STATE_ZOMBIE:
                break;

            case ENET_PEER_STATE_ACKNOWLEDGING_DISCONNECT:
                if ((command->header.command & ENET_PROTOCOL_COMMAND_MASK) == ENET_PROTOCOL_COMMAND_DISCONNECT)
                    peer->queue_acknowledgement(command, sentTime);
                break;

            default:
                peer->queue_acknowledgement(command, sentTime);
                break;
            }
        }
    }

commandError:
    if (event != NULL && event->type != ENET_EVENT_TYPE_NONE)
        return 1;

    return 0;
}

static int enet_protocol_receive_incoming_commands(ENetHost* host, ENetEvent* event)
{
    int packets;

    for (packets = 0; packets < 256; ++packets) {
        int receivedLength;
        ENetBuffer buffer;

        buffer.data = host->packetData[0];
        buffer.dataLength = sizeof(host->packetData[0]);

        receivedLength = host->socket.receive(&host->receivedAddress, &buffer, 1);

        if (receivedLength < 0)
            return -1;

        if (receivedLength == 0)
            return 0;

        host->receivedData = host->packetData[0];
        host->receivedDataLength = receivedLength;

        host->totalReceivedData += receivedLength;
        host->totalReceivedPackets++;

        if (host->intercept != NULL) {
            switch (host->intercept(host, event)) {
            case 1:
                if (event != NULL && event->type != ENET_EVENT_TYPE_NONE)
                    return 1;

                continue;

            case -1:
                return -1;

            default:
                break;
            }
        }

        switch (enet_protocol_handle_incoming_commands(host, event)) {
        case 1:
            return 1;

        case -1:
            return -1;

        default:
            break;
        }
    }

    return -1;
}

static void enet_protocol_send_acknowledgements(ENetHost* host, ENetPeer* peer)
{
    ENetProtocol* command = &host->commands[host->commandCount];
    ENetBuffer* buffer = &host->buffers[host->bufferCount];
    ENetAcknowledgement* acknowledgement;
    ENetListIterator currentAcknowledgement;
    enet_uint16 reliableSequenceNumber;

    currentAcknowledgement = peer->acknowledgements.begin();

    while (currentAcknowledgement != peer->acknowledgements.end()) {
        if (command >= &host->commands[sizeof(host->commands) / sizeof(ENetProtocol)] || buffer >= &host->buffers[sizeof(host->buffers) / sizeof(ENetBuffer)] || peer->mtu - host->packetSize < sizeof(ENetProtocolAcknowledge)) {
            host->continueSending = 1;

            break;
        }

        acknowledgement = (ENetAcknowledgement*)currentAcknowledgement;

        currentAcknowledgement = ENetList::next(currentAcknowledgement);

        buffer->data = command;
        buffer->dataLength = sizeof(ENetProtocolAcknowledge);

        host->packetSize += buffer->dataLength;

        reliableSequenceNumber = ENET_HOST_TO_NET_16(acknowledgement->command.header.reliableSequenceNumber);

        command->header.command = ENET_PROTOCOL_COMMAND_ACKNOWLEDGE;
        command->header.channelID = acknowledgement->command.header.channelID;
        command->header.reliableSequenceNumber = reliableSequenceNumber;
        command->acknowledge.receivedReliableSequenceNumber = reliableSequenceNumber;
        command->acknowledge.receivedSentTime = ENET_HOST_TO_NET_16(acknowledgement->sentTime);

        if ((acknowledgement->command.header.command & ENET_PROTOCOL_COMMAND_MASK) == ENET_PROTOCOL_COMMAND_DISCONNECT)
            enet_protocol_dispatch_state(host, peer, ENET_PEER_STATE_ZOMBIE);

        ENetList::remove(&acknowledgement->acknowledgementList);
        enet_free(acknowledgement);

        ++command;
        ++buffer;
    }

    host->commandCount = command - host->commands;
    host->bufferCount = buffer - host->buffers;
}

static void enet_protocol_send_unreliable_outgoing_commands(ENetHost* host, ENetPeer* peer)
{
    ENetProtocol* command = &host->commands[host->commandCount];
    ENetBuffer* buffer = &host->buffers[host->bufferCount];
    ENetOutgoingCommand* outgoingCommand;
    ENetListIterator currentCommand;

    currentCommand = peer->outgoingUnreliableCommands.begin();

    while (currentCommand != peer->outgoingUnreliableCommands.end()) {
        size_t commandSize;

        outgoingCommand = (ENetOutgoingCommand*)currentCommand;
        commandSize = commandSizes[outgoingCommand->command.header.command & ENET_PROTOCOL_COMMAND_MASK];

        if (command >= &host->commands[sizeof(host->commands) / sizeof(ENetProtocol)] || buffer + 1 >= &host->buffers[sizeof(host->buffers) / sizeof(ENetBuffer)] || peer->mtu - host->packetSize < commandSize || (outgoingCommand->packet != NULL && peer->mtu - host->packetSize < commandSize + outgoingCommand->fragmentLength)) {
            host->continueSending = 1;

            break;
        }

        currentCommand = ENetList::next(currentCommand);

        if (outgoingCommand->packet != NULL && outgoingCommand->fragmentOffset == 0) {
            peer->packetThrottleCounter += ENET_PEER_PACKET_THROTTLE_COUNTER;
            peer->packetThrottleCounter %= ENET_PEER_PACKET_THROTTLE_SCALE;

            if (peer->packetThrottleCounter > peer->packetThrottle) {
                enet_uint16 reliableSequenceNumber = outgoingCommand->reliableSequenceNumber,
                            unreliableSequenceNumber = outgoingCommand->unreliableSequenceNumber;
                for (;;) {
                    --outgoingCommand->packet->referenceCount;

                    if (outgoingCommand->packet->referenceCount == 0)
                        outgoingCommand->packet->destroy();

                    ENetList::remove(&outgoingCommand->outgoingCommandList);
                    enet_free(outgoingCommand);

                    if (currentCommand == peer->outgoingUnreliableCommands.end())
                        break;

                    outgoingCommand = (ENetOutgoingCommand*)currentCommand;
                    if (outgoingCommand->reliableSequenceNumber != reliableSequenceNumber || outgoingCommand->unreliableSequenceNumber != unreliableSequenceNumber)
                        break;

                    currentCommand = ENetList::next(currentCommand);
                }

                continue;
            }
        }

        buffer->data = command;
        buffer->dataLength = commandSize;

        host->packetSize += buffer->dataLength;

        *command = outgoingCommand->command;

        ENetList::remove(&outgoingCommand->outgoingCommandList);

        if (outgoingCommand->packet != NULL) {
            ++buffer;

            buffer->data = outgoingCommand->packet->data + outgoingCommand->fragmentOffset;
            buffer->dataLength = outgoingCommand->fragmentLength;

            host->packetSize += buffer->dataLength;

            ENetList::insert(peer->sentUnreliableCommands.end(), outgoingCommand);
        }
        else
            enet_free(outgoingCommand);

        ++command;
        ++buffer;
    }

    host->commandCount = command - host->commands;
    host->bufferCount = buffer - host->buffers;

    if (peer->state == ENET_PEER_STATE_DISCONNECT_LATER && peer->outgoingReliableCommands.empty() && peer->outgoingUnreliableCommands.empty() && peer->sentReliableCommands.empty())
        peer->disconnect(peer->eventData);
}

static int enet_protocol_check_timeouts(ENetHost* host, ENetPeer* peer, ENetEvent* event)
{
    ENetOutgoingCommand* outgoingCommand;
    ENetListIterator currentCommand, insertPosition;

    currentCommand = peer->sentReliableCommands.begin();
    insertPosition = peer->outgoingReliableCommands.begin();

    while (currentCommand != peer->sentReliableCommands.end()) {
        outgoingCommand = (ENetOutgoingCommand*)currentCommand;

        currentCommand = ENetList::next(currentCommand);

        if (ENET_TIME_DIFFERENCE(host->serviceTime, outgoingCommand->sentTime) < outgoingCommand->roundTripTimeout)
            continue;

        if (peer->earliestTimeout == 0 || ENET_TIME_LESS(outgoingCommand->sentTime, peer->earliestTimeout))
            peer->earliestTimeout = outgoingCommand->sentTime;

        if (peer->earliestTimeout != 0 && (ENET_TIME_DIFFERENCE(host->serviceTime, peer->earliestTimeout) >= peer->timeoutMaximum || (outgoingCommand->roundTripTimeout >= outgoingCommand->roundTripTimeoutLimit && ENET_TIME_DIFFERENCE(host->serviceTime, peer->earliestTimeout) >= peer->timeoutMinimum))) {
            enet_protocol_notify_disconnect(host, peer, event);

            return 1;
        }

        if (outgoingCommand->packet != NULL)
            peer->reliableDataInTransit -= outgoingCommand->fragmentLength;

        ++peer->packetsLost;

        outgoingCommand->roundTripTimeout *= 2;

        ENetList::insert(insertPosition,
            ENetList::remove(&outgoingCommand->outgoingCommandList));

        if (currentCommand == peer->sentReliableCommands.begin() && !peer->sentReliableCommands.empty()) {
            outgoingCommand = (ENetOutgoingCommand*)currentCommand;

            peer->nextTimeout = outgoingCommand->sentTime + outgoingCommand->roundTripTimeout;
        }
    }

    return 0;
}

static int enet_protocol_send_reliable_outgoing_commands(ENetHost* host, ENetPeer* peer)
{
    ENetProtocol* command = &host->commands[host->commandCount];
    ENetBuffer* buffer = &host->buffers[host->bufferCount];
    ENetOutgoingCommand* outgoingCommand;
    ENetListIterator currentCommand;
    ENetChannel* channel;
    enet_uint16 reliableWindow;
    size_t commandSize;
    int windowExceeded = 0, windowWrap = 0, canPing = 1;

    currentCommand = peer->outgoingReliableCommands.begin();

    while (currentCommand != peer->outgoingReliableCommands.end()) {
        outgoingCommand = (ENetOutgoingCommand*)currentCommand;

        channel = outgoingCommand->command.header.channelID < peer->channelCount
            ? &peer->channels[outgoingCommand->command.header.channelID]
            : NULL;
        reliableWindow = outgoingCommand->reliableSequenceNumber / ENET_PEER_RELIABLE_WINDOW_SIZE;
        if (channel != NULL) {
            if (!windowWrap && outgoingCommand->sendAttempts < 1 && !(outgoingCommand->reliableSequenceNumber % ENET_PEER_RELIABLE_WINDOW_SIZE) && (channel->reliableWindows[(reliableWindow + ENET_PEER_RELIABLE_WINDOWS - 1) % ENET_PEER_RELIABLE_WINDOWS] >= ENET_PEER_RELIABLE_WINDOW_SIZE || channel->usedReliableWindows & ((((1 << ENET_PEER_FREE_RELIABLE_WINDOWS) - 1) << reliableWindow) | (((1 << ENET_PEER_FREE_RELIABLE_WINDOWS) - 1) >> (ENET_PEER_RELIABLE_WINDOWS - reliableWindow)))))
                windowWrap = 1;
            if (windowWrap) {
                currentCommand = ENetList::next(currentCommand);

                continue;
            }
        }

        if (outgoingCommand->packet != NULL) {
            if (!windowExceeded) {
                enet_uint32 windowSize = (peer->packetThrottle * peer->windowSize) / ENET_PEER_PACKET_THROTTLE_SCALE;

                if (peer->reliableDataInTransit + outgoingCommand->fragmentLength > ENET_MAX(windowSize, peer->mtu))
                    windowExceeded = 1;
            }
            if (windowExceeded) {
                currentCommand = ENetList::next(currentCommand);

                continue;
            }
        }

        canPing = 0;

        commandSize = commandSizes[outgoingCommand->command.header.command & ENET_PROTOCOL_COMMAND_MASK];
        if (command >= &host->commands[sizeof(host->commands) / sizeof(ENetProtocol)] || buffer + 1 >= &host->buffers[sizeof(host->buffers) / sizeof(ENetBuffer)] || peer->mtu - host->packetSize < commandSize || (outgoingCommand->packet != NULL && (enet_uint16)(peer->mtu - host->packetSize) < (enet_uint16)(commandSize + outgoingCommand->fragmentLength))) {
            host->continueSending = 1;

            break;
        }

        currentCommand = ENetList::next(currentCommand);

        if (channel != NULL && outgoingCommand->sendAttempts < 1) {
            channel->usedReliableWindows |= 1 << reliableWindow;
            ++channel->reliableWindows[reliableWindow];
        }

        ++outgoingCommand->sendAttempts;

        if (outgoingCommand->roundTripTimeout == 0) {
            outgoingCommand->roundTripTimeout = peer->roundTripTime + 4 * peer->roundTripTimeVariance;
            outgoingCommand->roundTripTimeoutLimit = peer->timeoutLimit * outgoingCommand->roundTripTimeout;
        }

        if (peer->sentReliableCommands.empty())
            peer->nextTimeout = host->serviceTime + outgoingCommand->roundTripTimeout;

        ENetList::insert(peer->sentReliableCommands.end(),
            ENetList::remove(&outgoingCommand->outgoingCommandList));

        outgoingCommand->sentTime = host->serviceTime;

        buffer->data = command;
        buffer->dataLength = commandSize;

        host->packetSize += buffer->dataLength;
        host->headerFlags |= ENET_PROTOCOL_HEADER_FLAG_SENT_TIME;

        *command = outgoingCommand->command;

        if (outgoingCommand->packet != NULL) {
            ++buffer;

            buffer->data = outgoingCommand->packet->data + outgoingCommand->fragmentOffset;
            buffer->dataLength = outgoingCommand->fragmentLength;

            host->packetSize += outgoingCommand->fragmentLength;

            peer->reliableDataInTransit += outgoingCommand->fragmentLength;
        }

        ++peer->packetsSent;

        ++command;
        ++buffer;
    }

    host->commandCount = command - host->commands;
    host->bufferCount = buffer - host->buffers;

    return canPing;
}

static int enet_protocol_send_outgoing_commands(ENetHost* host, ENetEvent* event, int checkForTimeouts)
{
    enet_uint8 headerData[sizeof(ENetProtocolHeader) + sizeof(enet_uint32)];
    ENetProtocolHeader* header = (ENetProtocolHeader*)headerData;
    ENetPeer* currentPeer;
    int sentLength;
    size_t shouldCompress = 0;

    host->continueSending = 1;

    while (host->continueSending)
        for (host->continueSending = 0, currentPeer = host->peers;
             currentPeer < &host->peers[host->peerCount]; ++currentPeer) {
            if (currentPeer->state == ENET_PEER_STATE_DISCONNECTED || currentPeer->state == ENET_PEER_STATE_ZOMBIE)
                continue;

            host->headerFlags = 0;
            host->commandCount = 0;
            host->bufferCount = 1;
            host->packetSize = sizeof(ENetProtocolHeader);

            if (!currentPeer->acknowledgements.empty())
                enet_protocol_send_acknowledgements(host, currentPeer);

            if (checkForTimeouts != 0 && !currentPeer->sentReliableCommands.empty() && ENET_TIME_GREATER_EQUAL(host->serviceTime,
                                                                                           currentPeer->nextTimeout) && enet_protocol_check_timeouts(host, currentPeer, event) == 1) {
                if (event != NULL && event->type != ENET_EVENT_TYPE_NONE)
                    return 1;
                else
                    continue;
            }

            if ((currentPeer->outgoingReliableCommands.empty() || enet_protocol_send_reliable_outgoing_commands(host, currentPeer)) && currentPeer->sentReliableCommands.empty() && ENET_TIME_DIFFERENCE(host->serviceTime, currentPeer->lastReceiveTime) >= currentPeer->pingInterval && currentPeer->mtu - host->packetSize >= sizeof(ENetProtocolPing)) {
                currentPeer->ping();
                enet_protocol_send_reliable_outgoing_commands(host, currentPeer);
            }

            if (!currentPeer->outgoingUnreliableCommands.empty())
                enet_protocol_send_unreliable_outgoing_commands(host, currentPeer);

            if (host->commandCount == 0)
                continue;

            if (currentPeer->packetLossEpoch == 0)
                currentPeer->packetLossEpoch = host->serviceTime;
            else if (ENET_TIME_DIFFERENCE(host->serviceTime, currentPeer->packetLossEpoch) >= ENET_PEER_PACKET_LOSS_INTERVAL
                && currentPeer->packetsSent > 0) {
                enet_uint32 packetLoss = currentPeer->packetsLost * ENET_PEER_PACKET_LOSS_SCALE / currentPeer->packetsSent;

#ifdef ENET_DEBUG
                printf("peer %u: %f%%+-%f%% packet loss, %u+-%u ms round trip time, "
                       "%f%% throttle, %u/%u outgoing, %u/%u incoming\n",
                    currentPeer->incomingPeerID,
                    currentPeer->packetLoss / (float)ENET_PEER_PACKET_LOSS_SCALE,
                    currentPeer->packetLossVariance / (float)ENET_PEER_PACKET_LOSS_SCALE,
                    currentPeer->roundTripTime, currentPeer->roundTripTimeVariance,
                    currentPeer->packetThrottle / (float)ENET_PEER_PACKET_THROTTLE_SCALE,
                    enet_list_size(&currentPeer->outgoingReliableCommands),
                    enet_list_size(&currentPeer->outgoingUnreliableCommands),
                    currentPeer->channels != NULL
                        ? enet_list_size(
                              &currentPeer->channels->incomingReliableCommands)
                        : 0,
                    currentPeer->channels != NULL
                        ? enet_list_size(
                              &currentPeer->channels->incomingUnreliableCommands)
                        : 0);
#endif

                currentPeer->packetLossVariance -= currentPeer->packetLossVariance / 4;

                if (packetLoss >= currentPeer->packetLoss) {
                    currentPeer->packetLoss += (packetLoss - currentPeer->packetLoss) / 8;
                    currentPeer->packetLossVariance += (packetLoss - currentPeer->packetLoss) / 4;
                }
                else {
                    currentPeer->packetLoss -= (currentPeer->packetLoss - packetLoss) / 8;
                    currentPeer->packetLossVariance += (currentPeer->packetLoss - packetLoss) / 4;
                }

                currentPeer->packetLossEpoch = host->serviceTime;
                currentPeer->packetsSent = 0;
                currentPeer->packetsLost = 0;
            }

            host->buffers->data = headerData;
            if (host->headerFlags & ENET_PROTOCOL_HEADER_FLAG_SENT_TIME) {
                header->sentTime = ENET_HOST_TO_NET_16(host->serviceTime & 0xFFFF);

                host->buffers->dataLength = sizeof(ENetProtocolHeader);
            }
            else
                host->buffers->dataLength = (size_t) & ((ENetProtocolHeader*)0)->sentTime;

            shouldCompress = 0;
            if (host->compressor.context != NULL && host->compressor.compress != NULL) {
                size_t originalSize = host->packetSize - sizeof(ENetProtocolHeader),
                       compressedSize = host->compressor.compress(
                           host->compressor.context, &host->buffers[1],
                           host->bufferCount - 1, originalSize, host->packetData[1],
                           originalSize);
                if (compressedSize > 0 && compressedSize < originalSize) {
                    host->headerFlags |= ENET_PROTOCOL_HEADER_FLAG_COMPRESSED;
                    shouldCompress = compressedSize;
#ifdef ENET_DEBUG_COMPRESS
                    printf("peer %u: compressed %u -> %u (%u%%)\n",
                        currentPeer->incomingPeerID, originalSize, compressedSize,
                        (compressedSize * 100) / originalSize);
#endif
                }
            }

            if (currentPeer->outgoingPeerID < ENET_PROTOCOL_MAXIMUM_PEER_ID)
                host->headerFlags |= currentPeer->outgoingSessionID
                    << ENET_PROTOCOL_HEADER_SESSION_SHIFT;
            header->peerID = ENET_HOST_TO_NET_16(currentPeer->outgoingPeerID | host->headerFlags);
            if (host->checksum != NULL) {
                enet_uint32* checksum = (enet_uint32*)&headerData[host->buffers->dataLength];
                *checksum = currentPeer->outgoingPeerID < ENET_PROTOCOL_MAXIMUM_PEER_ID
                    ? currentPeer->connectID
                    : 0;
                host->buffers->dataLength += sizeof(enet_uint32);
                *checksum = host->checksum(host->buffers, host->bufferCount);
            }

            if (shouldCompress > 0) {
                host->buffers[1].data = host->packetData[1];
                host->buffers[1].dataLength = shouldCompress;
                host->bufferCount = 2;
            }

            currentPeer->lastSendTime = host->serviceTime;

            sentLength = host->socket.send(&currentPeer->address, host->buffers,
                host->bufferCount);

            enet_protocol_remove_sent_unreliable_commands(currentPeer);

            if (sentLength < 0)
                return -1;

            host->totalSentData += sentLength;
            host->totalSentPackets++;
        }

    return 0;
}

//-----------------------------------------------------------------------------
// ENetPacket

ENetPacket* ENetPacket::create(const void* data, size_t dataLength, enet_uint32 flags)
{
    ENetPacket* packet = (ENetPacket*)enet_malloc(sizeof(ENetPacket));
    if (packet == NULL)
        return NULL;

    if (flags & ENET_PACKET_FLAG_NO_ALLOCATE)
        packet->data = (enet_uint8*)data;
    else if (dataLength <= 0)
        packet->data = NULL;
    else {
        packet->data = (enet_uint8*)enet_malloc(dataLength);
        if (packet->data == NULL) {
            enet_free(packet);
            return NULL;
        }

        if (data != NULL)
            memcpy(packet->data, data, dataLength);
    }

    packet->referenceCount = 0;
    packet->flags = flags;
    packet->dataLength = dataLength;
    packet->freeCallback = NULL;
    packet->userData = NULL;

    return packet;
}

void ENetPacket::destroy()
{
    if (freeCallback != NULL)
        (*freeCallback)(this);
    if (!(flags & ENET_PACKET_FLAG_NO_ALLOCATE) && data != NULL)
        enet_free(data);
    enet_free(this);
}

int ENetPacket::resize(size_t dataLength)
{
    enet_uint8* newData;

    if (dataLength <= dataLength || (flags & ENET_PACKET_FLAG_NO_ALLOCATE)) {
        dataLength = dataLength;

        return 0;
    }

    newData = (enet_uint8*)enet_malloc(dataLength);
    if (newData == NULL)
        return -1;

    memcpy(newData, data, dataLength);
    enet_free(data);

    data = newData;
    dataLength = dataLength;

    return 0;
}

static int initializedCRC32 = 0;
static enet_uint32 crcTable[256];

static enet_uint32 reflect_crc(int val, int bits)
{
    int result = 0, bit;

    for (bit = 0; bit < bits; bit++) {
        if (val & 1)
            result |= 1 << (bits - 1 - bit);
        val >>= 1;
    }

    return result;
}

static void initialize_crc32(void)
{
    int byte;

    for (byte = 0; byte < 256; ++byte) {
        enet_uint32 crc = reflect_crc(byte, 8) << 24;
        int offset;

        for (offset = 0; offset < 8; ++offset) {
            if (crc & 0x80000000)
                crc = (crc << 1) ^ 0x04c11db7;
            else
                crc <<= 1;
        }

        crcTable[byte] = reflect_crc(crc, 32);
    }

    initializedCRC32 = 1;
}

enet_uint32 ENetPacket::crc32(const ENetBuffer* buffers, size_t bufferCount)
{
    enet_uint32 crc = 0xFFFFFFFF;

    if (!initializedCRC32)
        initialize_crc32();

    while (bufferCount-- > 0) {
        const enet_uint8* data = (const enet_uint8*)buffers->data,
                          * dataEnd = &data[buffers->dataLength];

        while (data < dataEnd) {
            crc = (crc >> 8) ^ crcTable[(crc & 0xFF) ^ *data++];
        }

        ++buffers;
    }

    return ENET_HOST_TO_NET_32(~crc);
}

//-----------------------------------------------------------------------------
// ENetHost

void ENetHost::flush()
{
    serviceTime = enet_time_get();

    enet_protocol_send_outgoing_commands(this, NULL, 0);
}

int ENetHost::check_events(ENetEvent* event)
{
    if (event == NULL)
        return -1;

    event->type     = ENET_EVENT_TYPE_NONE;
    event->peer     = NULL;
    event->packet   = NULL;

    return enet_protocol_dispatch_incoming_commands(this, event);
}

int ENetHost::service(ENetEvent* event, enet_uint32 timeout)
{
    enet_uint32 waitCondition;

    if (event != NULL) {
        event->type = ENET_EVENT_TYPE_NONE;
        event->peer = NULL;
        event->packet = NULL;

        switch (enet_protocol_dispatch_incoming_commands(this, event)) {
        case 1:
            return 1;

        case -1:
#ifdef ENET_DEBUG
            perror("Error dispatching incoming packets");
#endif

            return -1;

        default:
            break;
        }
    }

    serviceTime = enet_time_get();

    timeout += serviceTime;

    do {
        if (ENET_TIME_DIFFERENCE(serviceTime, bandwidthThrottleEpoch) >= ENET_HOST_BANDWIDTH_THROTTLE_INTERVAL)
            bandwidth_throttle();

        switch (enet_protocol_send_outgoing_commands(this, event, 1)) {
        case 1:
            return 1;

        case -1:
#ifdef ENET_DEBUG
            perror("Error sending outgoing packets");
#endif

            return -1;

        default:
            break;
        }

        switch (enet_protocol_receive_incoming_commands(this, event)) {
        case 1:
            return 1;

        case -1:
#ifdef ENET_DEBUG
            perror("Error receiving incoming packets");
#endif

            return -1;

        default:
            break;
        }

        switch (enet_protocol_send_outgoing_commands(this, event, 1)) {
        case 1:
            return 1;

        case -1:
#ifdef ENET_DEBUG
            perror("Error sending outgoing packets");
#endif

            return -1;

        default:
            break;
        }

        if (event != NULL) {
            switch (enet_protocol_dispatch_incoming_commands(this, event)) {
            case 1:
                return 1;

            case -1:
#ifdef ENET_DEBUG
                perror("Error dispatching incoming packets");
#endif

                return -1;

            default:
                break;
            }
        }

        if (ENET_TIME_GREATER_EQUAL(serviceTime, timeout))
            return 0;

        do {
            serviceTime = enet_time_get();

            if (ENET_TIME_GREATER_EQUAL(serviceTime, timeout))
                return 0;

            waitCondition = ENET_SOCKET_WAIT_RECEIVE | ENET_SOCKET_WAIT_INTERRUPT;

            if (socket.wait(&waitCondition, ENET_TIME_DIFFERENCE(timeout, serviceTime)) != 0)
                return -1;
        } while (waitCondition & ENET_SOCKET_WAIT_INTERRUPT);

        serviceTime = enet_time_get();
    } while (waitCondition & ENET_SOCKET_WAIT_RECEIVE);

    return 0;
}

ENetHost* ENetHost::create(const ENetAddress* address, size_t peerCount,
    size_t channelLimit, enet_uint32 incomingBandwidth,
    enet_uint32 outgoingBandwidth)
{
    ENetHost* host;
    ENetPeer* currentPeer;

    if (peerCount > ENET_PROTOCOL_MAXIMUM_PEER_ID)
        return NULL;

    host = (ENetHost*)enet_malloc(sizeof(ENetHost));
    if (host == NULL)
        return NULL;
    memset(host, 0, sizeof(ENetHost));

    host->peers = (ENetPeer*)enet_malloc(peerCount * sizeof(ENetPeer));
    if (host->peers == NULL) {
        enet_free(host);

        return NULL;
    }
    memset(host->peers, 0, peerCount * sizeof(ENetPeer));

    host->socket = ENetSocket::create(ENET_SOCKET_TYPE_DATAGRAM);
    if (host->socket == ENetSocket::null_socket() || (address != NULL && host->socket.bind(address) < 0)) {
        if (host->socket != ENetSocket::null_socket())
            host->socket.destroy();

        enet_free(host->peers);
        enet_free(host);

        return NULL;
    }

    host->socket.set_option(ENET_SOCKOPT_NONBLOCK, 1);
    host->socket.set_option(ENET_SOCKOPT_BROADCAST, 1);
    host->socket.set_option(ENET_SOCKOPT_RCVBUF, ENET_HOST_RECEIVE_BUFFER_SIZE);
    host->socket.set_option(ENET_SOCKOPT_SNDBUF, ENET_HOST_SEND_BUFFER_SIZE);

    if (address != NULL && host->socket.get_address(&host->address) < 0)
        host->address = *address;

    if (!channelLimit || channelLimit > ENET_PROTOCOL_MAXIMUM_CHANNEL_COUNT)
        channelLimit = ENET_PROTOCOL_MAXIMUM_CHANNEL_COUNT;
    else if (channelLimit < ENET_PROTOCOL_MINIMUM_CHANNEL_COUNT)
        channelLimit = ENET_PROTOCOL_MINIMUM_CHANNEL_COUNT;

    host->randomSeed                = (enet_uint32)(size_t)host;
    host->randomSeed                += ENetHost::random_seed();
    host->randomSeed                = (host->randomSeed << 16) | (host->randomSeed >> 16);
    host->channelLimit              = channelLimit;
    host->incomingBandwidth         = incomingBandwidth;
    host->outgoingBandwidth         = outgoingBandwidth;
    host->bandwidthThrottleEpoch    = 0;
    host->recalculateBandwidthLimits = 0;
    host->mtu                       = ENET_HOST_DEFAULT_MTU;
    host->peerCount                 = peerCount;
    host->commandCount              = 0;
    host->bufferCount               = 0;
    host->checksum                  = NULL;
    host->receivedAddress.host      = ENET_HOST_ANY;
    host->receivedAddress.port      = 0;
    host->receivedData              = NULL;
    host->receivedDataLength        = 0;

    host->totalSentData             = 0;
    host->totalSentPackets          = 0;
    host->totalReceivedData         = 0;
    host->totalReceivedPackets      = 0;

    host->connectedPeers            = 0;
    host->bandwidthLimitedPeers     = 0;
    host->duplicatePeers            = ENET_PROTOCOL_MAXIMUM_PEER_ID;
    host->maximumPacketSize         = ENET_HOST_DEFAULT_MAXIMUM_PACKET_SIZE;
    host->maximumWaitingData        = ENET_HOST_DEFAULT_MAXIMUM_WAITING_DATA;

    host->compressor.context        = NULL;
    host->compressor.compress       = NULL;
    host->compressor.decompress     = NULL;
    host->compressor.destroy        = NULL;

    host->intercept = NULL;

    host->dispatchQueue.clear();

    for (currentPeer = host->peers; currentPeer < &host->peers[host->peerCount];
         ++currentPeer) {
        currentPeer->host = host;
        currentPeer->incomingPeerID = currentPeer - host->peers;
        currentPeer->outgoingSessionID = currentPeer->incomingSessionID = 0xFF;
        currentPeer->data = NULL;

        currentPeer->acknowledgements.clear();
        currentPeer->sentReliableCommands.clear();
        currentPeer->sentUnreliableCommands.clear();
        currentPeer->outgoingReliableCommands.clear();
        currentPeer->outgoingUnreliableCommands.clear();
        currentPeer->dispatchedCommands.clear();

        currentPeer->reset();
    }

    return host;
}

void ENetHost::destroy()
{
    ENetPeer* currentPeer;

    //if (host == NULL)
    //    return;

    socket.destroy();

    for (currentPeer = peers; currentPeer < &peers[peerCount]; ++currentPeer) {
        currentPeer->reset();
    }

    if (compressor.context != NULL && compressor.destroy)
        (*compressor.destroy)(compressor.context);

    enet_free(peers);
    enet_free(this);
}

ENetPeer* ENetHost::connect(const ENetAddress* address, size_t channelCount, enet_uint32 data)
{
    ENetPeer* currentPeer;
    ENetChannel* channel;
    ENetProtocol command;

    if (channelCount < ENET_PROTOCOL_MINIMUM_CHANNEL_COUNT)
        channelCount = ENET_PROTOCOL_MINIMUM_CHANNEL_COUNT;
    else if (channelCount > ENET_PROTOCOL_MAXIMUM_CHANNEL_COUNT)
        channelCount = ENET_PROTOCOL_MAXIMUM_CHANNEL_COUNT;

    for (currentPeer = peers; currentPeer < &peers[peerCount]; ++currentPeer) {
        if (currentPeer->state == ENET_PEER_STATE_DISCONNECTED)
            break;
    }

    if (currentPeer >= &peers[peerCount])
        return NULL;

    currentPeer->channels = (ENetChannel*)enet_malloc(channelCount * sizeof(ENetChannel));
    if (currentPeer->channels == NULL)
        return NULL;
    currentPeer->channelCount   = channelCount;
    currentPeer->state          = ENET_PEER_STATE_CONNECTING;
    currentPeer->address        = *address;
    currentPeer->connectID      = ++randomSeed;

    if (outgoingBandwidth == 0)
        currentPeer->windowSize = ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE;
    else
        currentPeer->windowSize = (outgoingBandwidth / ENET_PEER_WINDOW_SIZE_SCALE) * ENET_PROTOCOL_MINIMUM_WINDOW_SIZE;

    if (currentPeer->windowSize < ENET_PROTOCOL_MINIMUM_WINDOW_SIZE)
        currentPeer->windowSize = ENET_PROTOCOL_MINIMUM_WINDOW_SIZE;
    else if (currentPeer->windowSize > ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE)
        currentPeer->windowSize = ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE;

    for (channel = currentPeer->channels; channel < &currentPeer->channels[channelCount]; ++channel) {
        channel->outgoingReliableSequenceNumber     = 0;
        channel->outgoingUnreliableSequenceNumber   = 0;
        channel->incomingReliableSequenceNumber     = 0;
        channel->incomingUnreliableSequenceNumber   = 0;

        channel->incomingReliableCommands.clear();
        channel->incomingUnreliableCommands.clear();

        channel->usedReliableWindows = 0;
        memset(channel->reliableWindows, 0, sizeof(channel->reliableWindows));
    }

    command.header.command                      = ENET_PROTOCOL_COMMAND_CONNECT | ENET_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE;
    command.header.channelID                    = 0xFF;
    command.connect.outgoingPeerID              = ENET_HOST_TO_NET_16(currentPeer->incomingPeerID);
    command.connect.incomingSessionID           = currentPeer->incomingSessionID;
    command.connect.outgoingSessionID           = currentPeer->outgoingSessionID;
    command.connect.mtu                         = ENET_HOST_TO_NET_32(currentPeer->mtu);
    command.connect.windowSize                  = ENET_HOST_TO_NET_32(currentPeer->windowSize);
    command.connect.channelCount                = ENET_HOST_TO_NET_32(channelCount);
    command.connect.incomingBandwidth           = ENET_HOST_TO_NET_32(incomingBandwidth);
    command.connect.outgoingBandwidth           = ENET_HOST_TO_NET_32(outgoingBandwidth);
    command.connect.packetThrottleInterval      = ENET_HOST_TO_NET_32(currentPeer->packetThrottleInterval);
    command.connect.packetThrottleAcceleration  = ENET_HOST_TO_NET_32(currentPeer->packetThrottleAcceleration);
    command.connect.packetThrottleDeceleration  = ENET_HOST_TO_NET_32(currentPeer->packetThrottleDeceleration);
    command.connect.connectID                   = currentPeer->connectID;
    command.connect.data                        = ENET_HOST_TO_NET_32(data);

    currentPeer->queue_outgoing_command(&command, NULL, 0, 0);

    return currentPeer;
}

void ENetHost::broadcast(enet_uint8 channelID, ENetPacket* packet)
{
    ENetPeer* currentPeer;

    for (currentPeer = peers; currentPeer < &peers[peerCount]; ++currentPeer) {
        if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
            continue;

        currentPeer->send(channelID, packet);
    }

    if (packet->referenceCount == 0)
        packet->destroy();
}

void ENetHost::compress(const ENetCompressor* icompressor)
{
    if (compressor.context != NULL && compressor.destroy)
        (*compressor.destroy)(compressor.context);

    if (icompressor)
        compressor = *icompressor;
    else
        compressor.context = NULL;
}

void ENetHost::channel_limit(size_t ichannelLimit)
{
    if (!ichannelLimit || ichannelLimit > ENET_PROTOCOL_MAXIMUM_CHANNEL_COUNT)
        ichannelLimit = ENET_PROTOCOL_MAXIMUM_CHANNEL_COUNT;
    else if (ichannelLimit < ENET_PROTOCOL_MINIMUM_CHANNEL_COUNT)
        ichannelLimit = ENET_PROTOCOL_MINIMUM_CHANNEL_COUNT;

    channelLimit = ichannelLimit;
}

void ENetHost::bandwidth_limit(enet_uint32 iincomingBandwidth, enet_uint32 ioutgoingBandwidth)
{
    incomingBandwidth           = iincomingBandwidth;
    outgoingBandwidth           = ioutgoingBandwidth;
    recalculateBandwidthLimits  = 1;
}

void ENetHost::bandwidth_throttle()
{
    enet_uint32 timeCurrent = enet_time_get(),
                elapsedTime = timeCurrent - bandwidthThrottleEpoch,
                peersRemaining = (enet_uint32)connectedPeers,
                dataTotal = ~0, bandwidth = ~0, throttle = 0, bandwidthLimit = 0;
    int needsAdjustment = bandwidthLimitedPeers > 0 ? 1 : 0;
    ENetPeer* peer;
    ENetProtocol command;

    if (elapsedTime < ENET_HOST_BANDWIDTH_THROTTLE_INTERVAL)
        return;

    bandwidthThrottleEpoch = timeCurrent;

    if (peersRemaining == 0)
        return;

    if (outgoingBandwidth != 0) {
        dataTotal = 0;
        bandwidth = (outgoingBandwidth * elapsedTime) / 1000;

        for (peer = peers; peer < &peers[peerCount]; ++peer) {
            if (peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER)
                continue;

            dataTotal += peer->outgoingDataTotal;
        }
    }

    while (peersRemaining > 0 && needsAdjustment != 0) {
        needsAdjustment = 0;

        if (dataTotal <= bandwidth)
            throttle = ENET_PEER_PACKET_THROTTLE_SCALE;
        else
            throttle = (bandwidth * ENET_PEER_PACKET_THROTTLE_SCALE) / dataTotal;

        for (peer = peers; peer < &peers[peerCount]; ++peer) {
            enet_uint32 peerBandwidth;

            if ((peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER) || peer->incomingBandwidth == 0 || peer->outgoingBandwidthThrottleEpoch == timeCurrent)
                continue;

            peerBandwidth = (peer->incomingBandwidth * elapsedTime) / 1000;
            if ((throttle * peer->outgoingDataTotal) / ENET_PEER_PACKET_THROTTLE_SCALE <= peerBandwidth)
                continue;

            peer->packetThrottleLimit = (peerBandwidth * ENET_PEER_PACKET_THROTTLE_SCALE) / peer->outgoingDataTotal;

            if (peer->packetThrottleLimit == 0)
                peer->packetThrottleLimit = 1;

            if (peer->packetThrottle > peer->packetThrottleLimit)
                peer->packetThrottle = peer->packetThrottleLimit;

            peer->outgoingBandwidthThrottleEpoch = timeCurrent;

            peer->incomingDataTotal = 0;
            peer->outgoingDataTotal = 0;

            needsAdjustment = 1;
            --peersRemaining;
            bandwidth -= peerBandwidth;
            dataTotal -= peerBandwidth;
        }
    }

    if (peersRemaining > 0) {
        if (dataTotal <= bandwidth)
            throttle = ENET_PEER_PACKET_THROTTLE_SCALE;
        else
            throttle = (bandwidth * ENET_PEER_PACKET_THROTTLE_SCALE) / dataTotal;

        for (peer = peers; peer < &peers[peerCount]; ++peer) {
            if ((peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER) || peer->outgoingBandwidthThrottleEpoch == timeCurrent)
                continue;

            peer->packetThrottleLimit = throttle;

            if (peer->packetThrottle > peer->packetThrottleLimit)
                peer->packetThrottle = peer->packetThrottleLimit;

            peer->incomingDataTotal = 0;
            peer->outgoingDataTotal = 0;
        }
    }

    if (recalculateBandwidthLimits) {
        recalculateBandwidthLimits = 0;

        peersRemaining  = (enet_uint32)connectedPeers;
        bandwidth       = incomingBandwidth;
        needsAdjustment = 1;

        if (bandwidth == 0)
            bandwidthLimit = 0;
        else
            while (peersRemaining > 0 && needsAdjustment != 0) {
                needsAdjustment = 0;
                bandwidthLimit = bandwidth / peersRemaining;

                for (peer = peers; peer < &peers[peerCount]; ++peer) {
                    if ((peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER) || peer->incomingBandwidthThrottleEpoch == timeCurrent)
                        continue;

                    if (peer->outgoingBandwidth > 0 && peer->outgoingBandwidth >= bandwidthLimit)
                        continue;

                    peer->incomingBandwidthThrottleEpoch = timeCurrent;

                    needsAdjustment = 1;
                    --peersRemaining;
                    bandwidth -= peer->outgoingBandwidth;
                }
            }

        for (peer = peers; peer < &peers[peerCount]; ++peer) {
            if (peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER)
                continue;

            command.header.command                      = ENET_PROTOCOL_COMMAND_BANDWIDTH_LIMIT | ENET_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE;
            command.header.channelID                    = 0xFF;
            command.bandwidthLimit.outgoingBandwidth    = ENET_HOST_TO_NET_32(outgoingBandwidth);

            if (peer->incomingBandwidthThrottleEpoch == timeCurrent)
                command.bandwidthLimit.incomingBandwidth = ENET_HOST_TO_NET_32(peer->outgoingBandwidth);
            else
                command.bandwidthLimit.incomingBandwidth = ENET_HOST_TO_NET_32(bandwidthLimit);

            peer->queue_outgoing_command(&command, NULL, 0, 0);
        }
    }
}

//-----------------------------------------------------------------------------
// ENetPeer

void ENetPeer::throttle_configure(enet_uint32 interval,
    enet_uint32 acceleration,
    enet_uint32 deceleration)
{
    ENetProtocol command;

    packetThrottleInterval      = interval;
    packetThrottleAcceleration  = acceleration;
    packetThrottleDeceleration  = deceleration;

    command.header.command      = ENET_PROTOCOL_COMMAND_THROTTLE_CONFIGURE | ENET_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE;
    command.header.channelID    = 0xFF;

    command.throttleConfigure.packetThrottleInterval        = ENET_HOST_TO_NET_32(interval);
    command.throttleConfigure.packetThrottleAcceleration    = ENET_HOST_TO_NET_32(acceleration);
    command.throttleConfigure.packetThrottleDeceleration    = ENET_HOST_TO_NET_32(deceleration);

    queue_outgoing_command(&command, NULL, 0, 0);
}

int ENetPeer::throttle(enet_uint32 rtt)
{
    if (lastRoundTripTime <= lastRoundTripTimeVariance) {
        packetThrottle = packetThrottleLimit;
    }
    else if (rtt < lastRoundTripTime) {
        packetThrottle += packetThrottleAcceleration;

        if (packetThrottle > packetThrottleLimit)
            packetThrottle = packetThrottleLimit;

        return 1;
    }
    else if (rtt > lastRoundTripTime + 2 * lastRoundTripTimeVariance) {
        if (packetThrottle > packetThrottleDeceleration)
            packetThrottle -= packetThrottleDeceleration;
        else
            packetThrottle = 0;

        return -1;
    }

    return 0;
}

int ENetPeer::send(enet_uint8 channelID, ENetPacket* packet)
{
    ENetChannel* channel = &channels[channelID];
    ENetProtocol command;
    size_t fragmentLength;

    if (state != ENET_PEER_STATE_CONNECTED || channelID >= channelCount || packet->dataLength > host->maximumPacketSize)
        return -1;

    fragmentLength = mtu - sizeof(ENetProtocolHeader) - sizeof(ENetProtocolSendFragment);
    if (host->checksum != NULL)
        fragmentLength -= sizeof(enet_uint32);

    if (packet->dataLength > fragmentLength) {
        enet_uint32 fragmentCount = (packet->dataLength + fragmentLength - 1) / fragmentLength,
                    fragmentNumber, fragmentOffset;
        enet_uint8 commandNumber;
        enet_uint16 startSequenceNumber;
        ENetList fragments;
        ENetOutgoingCommand* fragment;

        if (fragmentCount > ENET_PROTOCOL_MAXIMUM_FRAGMENT_COUNT)
            return -1;

        if ((packet->flags & (ENET_PACKET_FLAG_RELIABLE | ENET_PACKET_FLAG_UNRELIABLE_FRAGMENT)) == ENET_PACKET_FLAG_UNRELIABLE_FRAGMENT && channel->outgoingUnreliableSequenceNumber < 0xFFFF) {
            commandNumber = ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE_FRAGMENT;
            startSequenceNumber = ENET_HOST_TO_NET_16(channel->outgoingUnreliableSequenceNumber + 1);
        }
        else {
            commandNumber = ENET_PROTOCOL_COMMAND_SEND_FRAGMENT | ENET_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE;
            startSequenceNumber = ENET_HOST_TO_NET_16(channel->outgoingReliableSequenceNumber + 1);
        }

        fragments.clear();

        for (fragmentNumber = 0, fragmentOffset = 0;
             fragmentOffset < packet->dataLength;
             ++fragmentNumber, fragmentOffset += fragmentLength) {
            if (packet->dataLength - fragmentOffset < fragmentLength)
                fragmentLength = packet->dataLength - fragmentOffset;

            fragment = (ENetOutgoingCommand*)enet_malloc(sizeof(ENetOutgoingCommand));
            if (fragment == NULL) {
                while (!fragments.empty()) {
                    fragment = (ENetOutgoingCommand*)ENetList::remove(fragments.begin());

                    enet_free(fragment);
                }

                return -1;
            }

            fragment->fragmentOffset                            = fragmentOffset;
            fragment->fragmentLength                            = fragmentLength;
            fragment->packet                                    = packet;
            fragment->command.header.command                    = commandNumber;
            fragment->command.header.channelID                  = channelID;
            fragment->command.sendFragment.startSequenceNumber  = startSequenceNumber;
            fragment->command.sendFragment.dataLength           = ENET_HOST_TO_NET_16(fragmentLength);
            fragment->command.sendFragment.fragmentCount        = ENET_HOST_TO_NET_32(fragmentCount);
            fragment->command.sendFragment.fragmentNumber       = ENET_HOST_TO_NET_32(fragmentNumber);
            fragment->command.sendFragment.totalLength          = ENET_HOST_TO_NET_32(packet->dataLength);
            fragment->command.sendFragment.fragmentOffset       = ENET_NET_TO_HOST_32(fragmentOffset);

            ENetList::insert(fragments.end(), fragment);
        }

        packet->referenceCount += fragmentNumber;

        while (!fragments.empty()) {
            fragment = (ENetOutgoingCommand*)ENetList::remove(fragments.begin());

            setup_outgoing_command(fragment);
        }

        return 0;
    }

    command.header.channelID = channelID;

    if ((packet->flags & (ENET_PACKET_FLAG_RELIABLE | ENET_PACKET_FLAG_UNSEQUENCED)) == ENET_PACKET_FLAG_UNSEQUENCED) {
        command.header.command              = ENET_PROTOCOL_COMMAND_SEND_UNSEQUENCED | ENET_PROTOCOL_COMMAND_FLAG_UNSEQUENCED;
        command.sendUnsequenced.dataLength  = ENET_HOST_TO_NET_16(packet->dataLength);
    }
    else if (packet->flags & ENET_PACKET_FLAG_RELIABLE || channel->outgoingUnreliableSequenceNumber >= 0xFFFF) {
        command.header.command              = ENET_PROTOCOL_COMMAND_SEND_RELIABLE | ENET_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE;
        command.sendReliable.dataLength     = ENET_HOST_TO_NET_16(packet->dataLength);
    }
    else {
        command.header.command              = ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE;
        command.sendUnreliable.dataLength   = ENET_HOST_TO_NET_16(packet->dataLength);
    }

    if (queue_outgoing_command(&command, packet, 0, packet->dataLength) == NULL)
        return -1;

    return 0;
}

ENetPacket* ENetPeer::receive(enet_uint8* channelID)
{
    ENetIncomingCommand* incomingCommand;
    ENetPacket* packet;

    if (dispatchedCommands.empty())
        return NULL;

    incomingCommand = (ENetIncomingCommand*)ENetList::remove(dispatchedCommands.begin());

    if (channelID != NULL)
        *channelID = incomingCommand->command.header.channelID;

    packet = incomingCommand->packet;

    --packet->referenceCount;

    if (incomingCommand->fragments != NULL)
        enet_free(incomingCommand->fragments);

    enet_free(incomingCommand);

    totalWaitingData -= packet->dataLength;

    return packet;
}

static void enet_peer_reset_outgoing_commands(ENetList* queue)
{
    ENetOutgoingCommand* outgoingCommand;

    while (!queue->empty()) {
        outgoingCommand = (ENetOutgoingCommand*)ENetList::remove(queue->begin());

        if (outgoingCommand->packet != NULL) {
            --outgoingCommand->packet->referenceCount;

            if (outgoingCommand->packet->referenceCount == 0)
                outgoingCommand->packet->destroy();
        }

        enet_free(outgoingCommand);
    }
}

static void enet_peer_remove_incoming_commands(ENetList* queue, ENetListIterator startCommand, ENetListIterator endCommand)
{
    ENET_UNUSED(queue);

    ENetListIterator currentCommand;

    for (currentCommand = startCommand; currentCommand != endCommand;) {
        ENetIncomingCommand* incomingCommand = (ENetIncomingCommand*)currentCommand;

        currentCommand = ENetList::next(currentCommand);

        ENetList::remove(&incomingCommand->incomingCommandList);

        if (incomingCommand->packet != NULL) {
            --incomingCommand->packet->referenceCount;

            if (incomingCommand->packet->referenceCount == 0)
                incomingCommand->packet->destroy();
        }

        if (incomingCommand->fragments != NULL)
            enet_free(incomingCommand->fragments);

        enet_free(incomingCommand);
    }
}

static void enet_peer_reset_incoming_commands(ENetList* queue)
{
    enet_peer_remove_incoming_commands(queue, queue->begin(), queue->end());
}

void ENetPeer::reset_queues()
{
    ENetChannel* channel;

    if (needsDispatch) {
        ENetList::remove(&dispatchList);

        needsDispatch = 0;
    }

    while (!acknowledgements.empty())
        enet_free(ENetList::remove(acknowledgements.begin()));

    enet_peer_reset_outgoing_commands(&sentReliableCommands);
    enet_peer_reset_outgoing_commands(&sentUnreliableCommands);
    enet_peer_reset_outgoing_commands(&outgoingReliableCommands);
    enet_peer_reset_outgoing_commands(&outgoingUnreliableCommands);
    enet_peer_reset_incoming_commands(&dispatchedCommands);

    if (channels != NULL && channelCount > 0) {
        for (channel = channels; channel < &channels[channelCount]; ++channel) {
            enet_peer_reset_incoming_commands(&channel->incomingReliableCommands);
            enet_peer_reset_incoming_commands(&channel->incomingUnreliableCommands);
        }

        enet_free(channels);
    }

    channels = NULL;
    channelCount = 0;
}

void ENetPeer::on_connect()
{
    if (state != ENET_PEER_STATE_CONNECTED && state != ENET_PEER_STATE_DISCONNECT_LATER) {
        if (incomingBandwidth != 0)
            ++host->bandwidthLimitedPeers;

        ++host->connectedPeers;
    }
}

void ENetPeer::on_disconnect()
{
    if (state == ENET_PEER_STATE_CONNECTED || state == ENET_PEER_STATE_DISCONNECT_LATER) {
        if (incomingBandwidth != 0)
            --host->bandwidthLimitedPeers;

        --host->connectedPeers;
    }
}

void ENetPeer::reset()
{
    on_disconnect();

    outgoingPeerID = ENET_PROTOCOL_MAXIMUM_PEER_ID;
    connectID = 0;

    state = ENET_PEER_STATE_DISCONNECTED;

    incomingBandwidth               = 0;
    outgoingBandwidth               = 0;
    incomingBandwidthThrottleEpoch  = 0;
    outgoingBandwidthThrottleEpoch  = 0;
    incomingDataTotal               = 0;
    outgoingDataTotal               = 0;
    lastSendTime                    = 0;
    lastReceiveTime                 = 0;
    nextTimeout                     = 0;
    earliestTimeout                 = 0;
    packetLossEpoch                 = 0;
    packetsSent                     = 0;
    packetsLost                     = 0;
    packetLoss                      = 0;
    packetLossVariance              = 0;
    packetThrottle                  = ENET_PEER_DEFAULT_PACKET_THROTTLE;
    packetThrottleLimit             = ENET_PEER_PACKET_THROTTLE_SCALE;
    packetThrottleCounter           = 0;
    packetThrottleEpoch             = 0;
    packetThrottleAcceleration      = ENET_PEER_PACKET_THROTTLE_ACCELERATION;
    packetThrottleDeceleration      = ENET_PEER_PACKET_THROTTLE_DECELERATION;
    packetThrottleInterval          = ENET_PEER_PACKET_THROTTLE_INTERVAL;
    pingInterval                    = ENET_PEER_PING_INTERVAL;
    timeoutLimit                    = ENET_PEER_TIMEOUT_LIMIT;
    timeoutMinimum                  = ENET_PEER_TIMEOUT_MINIMUM;
    timeoutMaximum                  = ENET_PEER_TIMEOUT_MAXIMUM;
    lastRoundTripTime               = ENET_PEER_DEFAULT_ROUND_TRIP_TIME;
    lowestRoundTripTime             = ENET_PEER_DEFAULT_ROUND_TRIP_TIME;
    lastRoundTripTimeVariance       = 0;
    highestRoundTripTimeVariance    = 0;
    roundTripTime                   = ENET_PEER_DEFAULT_ROUND_TRIP_TIME;
    roundTripTimeVariance           = 0;
    mtu                             = host->mtu;
    reliableDataInTransit           = 0;
    outgoingReliableSequenceNumber  = 0;
    windowSize                      = ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE;
    incomingUnsequencedGroup        = 0;
    outgoingUnsequencedGroup        = 0;
    eventData                       = 0;
    totalWaitingData                = 0;

    memset(unsequencedWindow, 0, sizeof(unsequencedWindow));

    reset_queues();
}

void ENetPeer::ping()
{
    ENetProtocol command;

    if (state != ENET_PEER_STATE_CONNECTED)
        return;

    command.header.command      = ENET_PROTOCOL_COMMAND_PING | ENET_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE;
    command.header.channelID    = 0xFF;

    queue_outgoing_command(&command, NULL, 0, 0);
}

void ENetPeer::ping_interval(enet_uint32 pingInterval)
{
    pingInterval = pingInterval ? pingInterval : ENET_PEER_PING_INTERVAL;
}

void ENetPeer::timeout(enet_uint32 timeoutLimit, enet_uint32 timeoutMinimum, enet_uint32 timeoutMaximum)
{
    timeoutLimit    = timeoutLimit   ? timeoutLimit : ENET_PEER_TIMEOUT_LIMIT;
    timeoutMinimum  = timeoutMinimum ? timeoutMinimum : ENET_PEER_TIMEOUT_MINIMUM;
    timeoutMaximum  = timeoutMaximum ? timeoutMaximum : ENET_PEER_TIMEOUT_MAXIMUM;
}

void ENetPeer::disconnect_now(enet_uint32 data)
{
    ENetProtocol command;

    if (state == ENET_PEER_STATE_DISCONNECTED)
        return;

    if (state != ENET_PEER_STATE_ZOMBIE && state != ENET_PEER_STATE_DISCONNECTING) {
        reset_queues();

        command.header.command      = ENET_PROTOCOL_COMMAND_DISCONNECT | ENET_PROTOCOL_COMMAND_FLAG_UNSEQUENCED;
        command.header.channelID    = 0xFF;
        command.disconnect.data     = ENET_HOST_TO_NET_32(data);

        queue_outgoing_command(&command, NULL, 0, 0);

        host->flush();
    }

    reset();
}

void ENetPeer::disconnect(enet_uint32 data)
{
    ENetProtocol command;

    if (state == ENET_PEER_STATE_DISCONNECTING || state == ENET_PEER_STATE_DISCONNECTED || state == ENET_PEER_STATE_ACKNOWLEDGING_DISCONNECT || state == ENET_PEER_STATE_ZOMBIE)
        return;

    reset_queues();

    command.header.command      = ENET_PROTOCOL_COMMAND_DISCONNECT;
    command.header.channelID    = 0xFF;
    command.disconnect.data     = ENET_HOST_TO_NET_32(data);

    if (state == ENET_PEER_STATE_CONNECTED || state == ENET_PEER_STATE_DISCONNECT_LATER)
        command.header.command |= ENET_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE;
    else
        command.header.command |= ENET_PROTOCOL_COMMAND_FLAG_UNSEQUENCED;

    queue_outgoing_command(&command, NULL, 0, 0);

    if (state == ENET_PEER_STATE_CONNECTED || state == ENET_PEER_STATE_DISCONNECT_LATER) {
        on_disconnect();

        state = ENET_PEER_STATE_DISCONNECTING;
    } else {
        host->flush();
        reset();
    }
}

void ENetPeer::disconnect_later(enet_uint32 data)
{
    if ((state == ENET_PEER_STATE_CONNECTED || state == ENET_PEER_STATE_DISCONNECT_LATER) && !(outgoingReliableCommands.empty() && outgoingUnreliableCommands.empty() && sentReliableCommands.empty())) {
        state = ENET_PEER_STATE_DISCONNECT_LATER;
        eventData = data;
    }
    else
        disconnect(data);
}

ENetAcknowledgement* ENetPeer::queue_acknowledgement(const ENetProtocol* command, enet_uint16 sentTime)
{
    ENetAcknowledgement* acknowledgement;

    if (command->header.channelID < channelCount) {
        ENetChannel* channel = &channels[command->header.channelID];
        enet_uint16 reliableWindow = command->header.reliableSequenceNumber / ENET_PEER_RELIABLE_WINDOW_SIZE,
                    currentWindow = channel->incomingReliableSequenceNumber / ENET_PEER_RELIABLE_WINDOW_SIZE;

        if (command->header.reliableSequenceNumber < channel->incomingReliableSequenceNumber)
            reliableWindow += ENET_PEER_RELIABLE_WINDOWS;

        if (reliableWindow >= currentWindow + ENET_PEER_FREE_RELIABLE_WINDOWS - 1 && reliableWindow <= currentWindow + ENET_PEER_FREE_RELIABLE_WINDOWS)
            return NULL;
    }

    acknowledgement = (ENetAcknowledgement*)enet_malloc(sizeof(ENetAcknowledgement));
    if (acknowledgement == NULL)
        return NULL;

    outgoingDataTotal += sizeof(ENetProtocolAcknowledge);

    acknowledgement->sentTime   = sentTime;
    acknowledgement->command    = *command;

    ENetList::insert(acknowledgements.end(), acknowledgement);

    return acknowledgement;
}

void ENetPeer::setup_outgoing_command(ENetOutgoingCommand* outgoingCommand)
{
    ENetChannel* channel = &channels[outgoingCommand->command.header.channelID];

    outgoingDataTotal += enet_protocol_command_size(outgoingCommand->command.header.command) + outgoingCommand->fragmentLength;

    if (outgoingCommand->command.header.channelID == 0xFF) {
        ++outgoingReliableSequenceNumber;

        outgoingCommand->reliableSequenceNumber = outgoingReliableSequenceNumber;
        outgoingCommand->unreliableSequenceNumber   = 0;
    }
    else if (outgoingCommand->command.header.command & ENET_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE) {
        ++channel->outgoingReliableSequenceNumber;
        channel->outgoingUnreliableSequenceNumber   = 0;

        outgoingCommand->reliableSequenceNumber = channel->outgoingReliableSequenceNumber;
        outgoingCommand->unreliableSequenceNumber   = 0;
    }
    else if (outgoingCommand->command.header.command & ENET_PROTOCOL_COMMAND_FLAG_UNSEQUENCED) {
        ++outgoingUnsequencedGroup;

        outgoingCommand->reliableSequenceNumber     = 0;
        outgoingCommand->unreliableSequenceNumber   = 0;
    }
    else {
        if (outgoingCommand->fragmentOffset == 0)
            ++channel->outgoingUnreliableSequenceNumber;

        outgoingCommand->reliableSequenceNumber     = channel->outgoingReliableSequenceNumber;
        outgoingCommand->unreliableSequenceNumber   = channel->outgoingUnreliableSequenceNumber;
    }

    outgoingCommand->sendAttempts                           = 0;
    outgoingCommand->sentTime                               = 0;
    outgoingCommand->roundTripTimeout                       = 0;
    outgoingCommand->roundTripTimeoutLimit                  = 0;
    outgoingCommand->command.header.reliableSequenceNumber  = ENET_HOST_TO_NET_16(outgoingCommand->reliableSequenceNumber);

    switch (outgoingCommand->command.header.command & ENET_PROTOCOL_COMMAND_MASK) {
    case ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE:
        outgoingCommand->command.sendUnreliable.unreliableSequenceNumber = ENET_HOST_TO_NET_16(outgoingCommand->unreliableSequenceNumber);
        break;

    case ENET_PROTOCOL_COMMAND_SEND_UNSEQUENCED:
        outgoingCommand->command.sendUnsequenced.unsequencedGroup = ENET_HOST_TO_NET_16(outgoingUnsequencedGroup);
        break;

    default:
        break;
    }

    if (outgoingCommand->command.header.command & ENET_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE)
        ENetList::insert(outgoingReliableCommands.end(), outgoingCommand);
    else
        ENetList::insert(outgoingUnreliableCommands.end(), outgoingCommand);
}

ENetOutgoingCommand* ENetPeer::queue_outgoing_command(
    const ENetProtocol* command, ENetPacket* packet,
    enet_uint32 offset, enet_uint16 length)
{
    ENetOutgoingCommand* outgoingCommand = (ENetOutgoingCommand*)enet_malloc(sizeof(ENetOutgoingCommand));
    if (outgoingCommand == NULL)
        return NULL;

    outgoingCommand->command        = *command;
    outgoingCommand->fragmentOffset = offset;
    outgoingCommand->fragmentLength = length;
    outgoingCommand->packet         = packet;
    if (packet != NULL)
        ++packet->referenceCount;

    setup_outgoing_command(outgoingCommand);

    return outgoingCommand;
}

void ENetPeer::dispatch_incoming_unreliable_commands(ENetChannel* channel)
{
    ENetListIterator droppedCommand, startCommand, currentCommand;

    for (droppedCommand = startCommand = currentCommand = channel->incomingUnreliableCommands.begin();
         currentCommand != channel->incomingUnreliableCommands.end();
         currentCommand = ENetList::next(currentCommand)) {
        ENetIncomingCommand* incomingCommand = (ENetIncomingCommand*)currentCommand;

        if ((incomingCommand->command.header.command & ENET_PROTOCOL_COMMAND_MASK) == ENET_PROTOCOL_COMMAND_SEND_UNSEQUENCED)
            continue;

        if (incomingCommand->reliableSequenceNumber == channel->incomingReliableSequenceNumber) {
            if (incomingCommand->fragmentsRemaining <= 0) {
                channel->incomingUnreliableSequenceNumber = incomingCommand->unreliableSequenceNumber;
                continue;
            }

            if (startCommand != currentCommand) {
                ENetList::move(dispatchedCommands.end(), startCommand, ENetList::previous(currentCommand));

                if (!needsDispatch) {
                    ENetList::insert(host->dispatchQueue.end(), &dispatchList);

                    needsDispatch = 1;
                }

                droppedCommand = currentCommand;
            }
            else if (droppedCommand != currentCommand)
                droppedCommand = ENetList::previous(currentCommand);
        }
        else {
            enet_uint16 reliableWindow = incomingCommand->reliableSequenceNumber / ENET_PEER_RELIABLE_WINDOW_SIZE,
                        currentWindow = channel->incomingReliableSequenceNumber / ENET_PEER_RELIABLE_WINDOW_SIZE;
            if (incomingCommand->reliableSequenceNumber < channel->incomingReliableSequenceNumber)
                reliableWindow += ENET_PEER_RELIABLE_WINDOWS;
            if (reliableWindow >= currentWindow && reliableWindow < currentWindow + ENET_PEER_FREE_RELIABLE_WINDOWS - 1)
                break;

            droppedCommand = ENetList::next(currentCommand);

            if (startCommand != currentCommand) {
                ENetList::move(dispatchedCommands.end(), startCommand, ENetList::previous(currentCommand));

                if (!needsDispatch) {
                    ENetList::insert(host->dispatchQueue.end(), &dispatchList);

                    needsDispatch = 1;
                }
            }
        }

        startCommand = ENetList::next(currentCommand);
    }

    if (startCommand != currentCommand) {
        ENetList::move(dispatchedCommands.end(), startCommand, ENetList::previous(currentCommand));

        if (!needsDispatch) {
            ENetList::insert(host->dispatchQueue.end(), &dispatchList);

            needsDispatch = 1;
        }

        droppedCommand = currentCommand;
    }

    enet_peer_remove_incoming_commands(
        &channel->incomingUnreliableCommands,
        channel->incomingUnreliableCommands.begin(), droppedCommand);
}

void ENetPeer::dispatch_incoming_reliable_commands(ENetChannel* channel)
{
    ENetListIterator currentCommand;

    for (currentCommand = channel->incomingReliableCommands.begin();
         currentCommand != channel->incomingReliableCommands.end();
         currentCommand = ENetList::next(currentCommand)) {
        ENetIncomingCommand* incomingCommand = (ENetIncomingCommand*)currentCommand;

        if (incomingCommand->fragmentsRemaining > 0 || incomingCommand->reliableSequenceNumber != (enet_uint16)(channel->incomingReliableSequenceNumber + 1))
            break;

        channel->incomingReliableSequenceNumber = incomingCommand->reliableSequenceNumber;

        if (incomingCommand->fragmentCount > 0)
            channel->incomingReliableSequenceNumber += incomingCommand->fragmentCount - 1;
    }

    if (currentCommand == channel->incomingReliableCommands.begin())
        return;

    channel->incomingUnreliableSequenceNumber = 0;

    ENetList::move(dispatchedCommands.end(), channel->incomingReliableCommands.begin(), ENetList::previous(currentCommand));

    if (!needsDispatch) {
        ENetList::insert(host->dispatchQueue.end(), &dispatchList);

        needsDispatch = 1;
    }

    if (!channel->incomingUnreliableCommands.empty())
        dispatch_incoming_unreliable_commands(channel);
}

ENetIncomingCommand* ENetPeer::queue_incoming_command(
    const ENetProtocol* command, const void* data,
    size_t dataLength, enet_uint32 flags, enet_uint32 fragmentCount)
{
    static ENetIncomingCommand dummyCommand;

    ENetChannel* channel = &channels[command->header.channelID];
    enet_uint32 unreliableSequenceNumber = 0, reliableSequenceNumber = 0;
    enet_uint16 reliableWindow, currentWindow;
    ENetIncomingCommand* incomingCommand;
    ENetListIterator currentCommand;
    ENetPacket* packet = NULL;

    if (state == ENET_PEER_STATE_DISCONNECT_LATER)
        goto discardCommand;

    if ((command->header.command & ENET_PROTOCOL_COMMAND_MASK) != ENET_PROTOCOL_COMMAND_SEND_UNSEQUENCED) {
        reliableSequenceNumber = command->header.reliableSequenceNumber;
        reliableWindow = reliableSequenceNumber / ENET_PEER_RELIABLE_WINDOW_SIZE;
        currentWindow = channel->incomingReliableSequenceNumber / ENET_PEER_RELIABLE_WINDOW_SIZE;

        if (reliableSequenceNumber < channel->incomingReliableSequenceNumber)
            reliableWindow += ENET_PEER_RELIABLE_WINDOWS;

        if (reliableWindow < currentWindow || reliableWindow >= currentWindow + ENET_PEER_FREE_RELIABLE_WINDOWS - 1)
            goto discardCommand;
    }

    switch (command->header.command & ENET_PROTOCOL_COMMAND_MASK) {
    case ENET_PROTOCOL_COMMAND_SEND_FRAGMENT:
    case ENET_PROTOCOL_COMMAND_SEND_RELIABLE:
        if (reliableSequenceNumber == channel->incomingReliableSequenceNumber)
            goto discardCommand;

        for (currentCommand = ENetList::previous(channel->incomingReliableCommands.end());
             currentCommand != channel->incomingReliableCommands.end();
             currentCommand = ENetList::previous(currentCommand)) {
            incomingCommand = (ENetIncomingCommand*)currentCommand;

            if (reliableSequenceNumber >= channel->incomingReliableSequenceNumber) {
                if (incomingCommand->reliableSequenceNumber < channel->incomingReliableSequenceNumber)
                    continue;
            }
            else if (incomingCommand->reliableSequenceNumber >= channel->incomingReliableSequenceNumber)
                break;

            if (incomingCommand->reliableSequenceNumber <= reliableSequenceNumber) {
                if (incomingCommand->reliableSequenceNumber < reliableSequenceNumber)
                    break;

                goto discardCommand;
            }
        }
        break;

    case ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE:
    case ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE_FRAGMENT:
        unreliableSequenceNumber = ENET_NET_TO_HOST_16(command->sendUnreliable.unreliableSequenceNumber);

        if (reliableSequenceNumber == channel->incomingReliableSequenceNumber && unreliableSequenceNumber <= channel->incomingUnreliableSequenceNumber)
            goto discardCommand;

        for (currentCommand = ENetList::previous(channel->incomingUnreliableCommands.end());
             currentCommand != channel->incomingUnreliableCommands.end();
             currentCommand = ENetList::previous(currentCommand)) {
            incomingCommand = (ENetIncomingCommand*)currentCommand;

            if ((command->header.command & ENET_PROTOCOL_COMMAND_MASK) == ENET_PROTOCOL_COMMAND_SEND_UNSEQUENCED)
                continue;

            if (reliableSequenceNumber >= channel->incomingReliableSequenceNumber) {
                if (incomingCommand->reliableSequenceNumber < channel->incomingReliableSequenceNumber)
                    continue;
            }
            else if (incomingCommand->reliableSequenceNumber >= channel->incomingReliableSequenceNumber)
                break;

            if (incomingCommand->reliableSequenceNumber < reliableSequenceNumber)
                break;

            if (incomingCommand->reliableSequenceNumber > reliableSequenceNumber)
                continue;

            if (incomingCommand->unreliableSequenceNumber <= unreliableSequenceNumber) {
                if (incomingCommand->unreliableSequenceNumber < unreliableSequenceNumber)
                    break;

                goto discardCommand;
            }
        }
        break;

    case ENET_PROTOCOL_COMMAND_SEND_UNSEQUENCED:
        currentCommand = channel->incomingUnreliableCommands.end();
        break;

    default:
        goto discardCommand;
    }

    if (totalWaitingData >= host->maximumWaitingData)
        goto notifyError;

    packet = ENetPacket::create(data, dataLength, flags);
    if (packet == NULL)
        goto notifyError;

    incomingCommand = (ENetIncomingCommand*)enet_malloc(sizeof(ENetIncomingCommand));
    if (incomingCommand == NULL)
        goto notifyError;

    incomingCommand->reliableSequenceNumber     = command->header.reliableSequenceNumber;
    incomingCommand->unreliableSequenceNumber   = unreliableSequenceNumber & 0xFFFF;
    incomingCommand->command                    = *command;
    incomingCommand->fragmentCount              = fragmentCount;
    incomingCommand->fragmentsRemaining         = fragmentCount;
    incomingCommand->packet                     = packet;
    incomingCommand->fragments                  = NULL;

    if (fragmentCount > 0) {
        if (fragmentCount <= ENET_PROTOCOL_MAXIMUM_FRAGMENT_COUNT)
            incomingCommand->fragments = (enet_uint32*)enet_malloc((fragmentCount + 31) / 32 * sizeof(enet_uint32));
        if (incomingCommand->fragments == NULL) {
            enet_free(incomingCommand);

            goto notifyError;
        }
        memset(incomingCommand->fragments, 0, (fragmentCount + 31) / 32 * sizeof(enet_uint32));
    }

    if (packet != NULL) {
        ++packet->referenceCount;

        totalWaitingData += packet->dataLength;
    }

    ENetList::insert(ENetList::next(currentCommand), incomingCommand);

    switch (command->header.command & ENET_PROTOCOL_COMMAND_MASK) {
    case ENET_PROTOCOL_COMMAND_SEND_FRAGMENT:
    case ENET_PROTOCOL_COMMAND_SEND_RELIABLE:
        dispatch_incoming_reliable_commands(channel);
        break;

    default:
        dispatch_incoming_unreliable_commands(channel);
        break;
    }

    return incomingCommand;

discardCommand:
    if (fragmentCount > 0)
        goto notifyError;

    if (packet != NULL && packet->referenceCount == 0)
        packet->destroy();

    return &dummyCommand;

notifyError:
    if (packet != NULL && packet->referenceCount == 0)
        packet->destroy();

    return NULL;
}
