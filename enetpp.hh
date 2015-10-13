
#include <stdint.h>
#include <inttypes.h>

typedef int8_t      enet_int8;
typedef int16_t     enet_int16;
typedef int32_t     enet_int32;
typedef int64_t     enet_int64;

typedef uint8_t     enet_uint8;
typedef uint16_t    enet_uint16;
typedef uint32_t    enet_uint32;
typedef uint64_t    enet_uint64;

enum
{
    ENET_VERSION_MAJOR = 1,
    ENET_VERSION_MINOR = 3,
    ENET_VERSION_PATCH = 13
};

#ifdef _MSC_VER
#define ENET_INLINE __forceinline

#ifdef ENET_DLL
#ifdef ENET_BUILDING_LIB
#define ENET_API __declspec(dllexport)
#else
#define ENET_API __declspec(dllimport)
#endif /* ENET_BUILDING_LIB */
#else /* !ENET_DLL */
#define ENET_API
#endif /* ENET_DLL */

#else
#define ENET_INLINE __attribute__((always_inline))
#endif

//-----------------------------------------------------------------------------
// enumerations
enum ENetSocketType
{
    ENET_SOCKET_TYPE_STREAM                         = 1,
    ENET_SOCKET_TYPE_DATAGRAM                       = 2
};

enum ENetSocketWait
{
    ENET_SOCKET_WAIT_NONE                           = 0,
    ENET_SOCKET_WAIT_SEND                           = (1 << 0),
    ENET_SOCKET_WAIT_RECEIVE                        = (1 << 1),
    ENET_SOCKET_WAIT_INTERRUPT                      = (1 << 2)
};

enum ENetSocketOption
{
    ENET_SOCKOPT_NONBLOCK                           = 1,
    ENET_SOCKOPT_BROADCAST                          = 2,
    ENET_SOCKOPT_RCVBUF                             = 3,
    ENET_SOCKOPT_SNDBUF                             = 4,
    ENET_SOCKOPT_REUSEADDR                          = 5,
    ENET_SOCKOPT_RCVTIMEO                           = 6,
    ENET_SOCKOPT_SNDTIMEO                           = 7,
    ENET_SOCKOPT_ERROR                              = 8,
    ENET_SOCKOPT_NODELAY                            = 9
};

enum ENetSocketShutdown
{
    ENET_SOCKET_SHUTDOWN_READ                       = 0,
    ENET_SOCKET_SHUTDOWN_WRITE                      = 1,
    ENET_SOCKET_SHUTDOWN_READ_WRITE                 = 2
};

enum
{
    ENET_PROTOCOL_MINIMUM_MTU                       = 576,
    ENET_PROTOCOL_MAXIMUM_MTU                       = 4096,
    ENET_PROTOCOL_MAXIMUM_PACKET_COMMANDS           = 32,
    ENET_PROTOCOL_MINIMUM_WINDOW_SIZE               = 4096,
    ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE               = 65536,
    ENET_PROTOCOL_MINIMUM_CHANNEL_COUNT             = 1,
    ENET_PROTOCOL_MAXIMUM_CHANNEL_COUNT             = 255,
    ENET_PROTOCOL_MAXIMUM_PEER_ID                   = 0xFFF,
    ENET_PROTOCOL_MAXIMUM_FRAGMENT_COUNT            = 1024 * 1024
};

enum ENetProtocolCommand
{
    ENET_PROTOCOL_COMMAND_NONE                      = 0,
    ENET_PROTOCOL_COMMAND_ACKNOWLEDGE               = 1,
    ENET_PROTOCOL_COMMAND_CONNECT                   = 2,
    ENET_PROTOCOL_COMMAND_VERIFY_CONNECT            = 3,
    ENET_PROTOCOL_COMMAND_DISCONNECT                = 4,
    ENET_PROTOCOL_COMMAND_PING                      = 5,
    ENET_PROTOCOL_COMMAND_SEND_RELIABLE             = 6,
    ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE           = 7,
    ENET_PROTOCOL_COMMAND_SEND_FRAGMENT             = 8,
    ENET_PROTOCOL_COMMAND_SEND_UNSEQUENCED          = 9,
    ENET_PROTOCOL_COMMAND_BANDWIDTH_LIMIT           = 10,
    ENET_PROTOCOL_COMMAND_THROTTLE_CONFIGURE        = 11,
    ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE_FRAGMENT  = 12,
    ENET_PROTOCOL_COMMAND_COUNT                     = 13,

    ENET_PROTOCOL_COMMAND_MASK                      = 0x0F
};

enum ENetProtocolFlag
{
    ENET_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE          = (1 << 7),
    ENET_PROTOCOL_COMMAND_FLAG_UNSEQUENCED          = (1 << 6),

    ENET_PROTOCOL_HEADER_FLAG_COMPRESSED            = (1 << 14),
    ENET_PROTOCOL_HEADER_FLAG_SENT_TIME             = (1 << 15),
    ENET_PROTOCOL_HEADER_FLAG_MASK                  = ENET_PROTOCOL_HEADER_FLAG_COMPRESSED | ENET_PROTOCOL_HEADER_FLAG_SENT_TIME,

    ENET_PROTOCOL_HEADER_SESSION_MASK               = (3 << 12),
    ENET_PROTOCOL_HEADER_SESSION_SHIFT              = 12
};

enum ENetPeerState
{
    ENET_PEER_STATE_DISCONNECTED                    = 0,
    ENET_PEER_STATE_CONNECTING                      = 1,
    ENET_PEER_STATE_ACKNOWLEDGING_CONNECT           = 2,
    ENET_PEER_STATE_CONNECTION_PENDING              = 3,
    ENET_PEER_STATE_CONNECTION_SUCCEEDED            = 4,
    ENET_PEER_STATE_CONNECTED                       = 5,
    ENET_PEER_STATE_DISCONNECT_LATER                = 6,
    ENET_PEER_STATE_DISCONNECTING                   = 7,
    ENET_PEER_STATE_ACKNOWLEDGING_DISCONNECT        = 8,
    ENET_PEER_STATE_ZOMBIE                          = 9
};

enum
{
    ENET_HOST_RECEIVE_BUFFER_SIZE                   = 256 * 1024,
    ENET_HOST_SEND_BUFFER_SIZE                      = 256 * 1024,
    ENET_HOST_BANDWIDTH_THROTTLE_INTERVAL           = 1000,
    ENET_HOST_DEFAULT_MTU                           = 1400,
    ENET_HOST_DEFAULT_MAXIMUM_PACKET_SIZE           = 32 * 1024 * 1024,
    ENET_HOST_DEFAULT_MAXIMUM_WAITING_DATA          = 32 * 1024 * 1024,

    ENET_PEER_DEFAULT_ROUND_TRIP_TIME               = 500,
    ENET_PEER_DEFAULT_PACKET_THROTTLE               = 32,
    ENET_PEER_PACKET_THROTTLE_SCALE                 = 32,
    ENET_PEER_PACKET_THROTTLE_COUNTER               = 7,
    ENET_PEER_PACKET_THROTTLE_ACCELERATION          = 2,
    ENET_PEER_PACKET_THROTTLE_DECELERATION          = 2,
    ENET_PEER_PACKET_THROTTLE_INTERVAL              = 5000,
    ENET_PEER_PACKET_LOSS_SCALE                     = (1 << 16),
    ENET_PEER_PACKET_LOSS_INTERVAL                  = 10000,
    ENET_PEER_WINDOW_SIZE_SCALE                     = 64 * 1024,
    ENET_PEER_TIMEOUT_LIMIT                         = 32,
    ENET_PEER_TIMEOUT_MINIMUM                       = 5000,
    ENET_PEER_TIMEOUT_MAXIMUM                       = 30000,
    ENET_PEER_PING_INTERVAL                         = 500,
    ENET_PEER_UNSEQUENCED_WINDOWS                   = 64,
    ENET_PEER_UNSEQUENCED_WINDOW_SIZE               = 1024,
    ENET_PEER_FREE_UNSEQUENCED_WINDOWS              = 32,
    ENET_PEER_RELIABLE_WINDOWS                      = 16,
    ENET_PEER_RELIABLE_WINDOW_SIZE                  = 0x1000,
    ENET_PEER_FREE_RELIABLE_WINDOWS                 = 8
};

enum ENetEventType
{
    /** no event occurred within the specified time limit */
    ENET_EVENT_TYPE_NONE                            = 0,

    /** a connection request initiated by enet_host_connect has completed.
    * The peer field contains the peer which successfully connected.
    */
    ENET_EVENT_TYPE_CONNECT                         = 1,

    /** a peer has disconnected.  This event is generated on a successful
    * completion of a disconnect initiated by enet_pper_disconnect, if
    * a peer has timed out, or if a connection request intialized by
    * enet_host_connect has timed out.  The peer field contains the peer
    * which disconnected. The data field contains user supplied data
    * describing the disconnection, or 0, if none is available.
    */
    ENET_EVENT_TYPE_DISCONNECT                      = 2,

    /** a packet has been received from a peer.  The peer field specifies the
    * peer which sent the packet.  The channelID field specifies the channel
    * number upon which the packet was received.  The packet field contains
    * the packet that was received; this packet must be destroyed with
    * enet_packet_destroy after use.
    */
    ENET_EVENT_TYPE_RECEIVE                         = 3
};

enum
{
    ENET_HOST_ANY                                   = 0,
    ENET_HOST_BROADCAST                             = 0xFFFFFFFFU,
    ENET_PORT_ANY                                   = 0,

    ENET_BUFFER_MAXIMUM                             = (1 + 2 * ENET_PROTOCOL_MAXIMUM_PACKET_COMMANDS)
};

#ifdef _WIN32
#include <stdlib.h>
#include <winsock2.h>

#define ENET_CALLBACK __cdecl

typedef fd_set ENetSocketSet;

struct ENetAddress;

struct ENetBuffer final
{
    size_t  dataLength;
    void*   data;
};

struct ENET_API ENetSocket final
{
    SOCKET socket = INVALID_SOCKET;

    static ENET_INLINE SOCKET null_socket() { return INVALID_SOCKET; }

    ENET_INLINE ENetSocket() {}
    ENET_INLINE ENetSocket(SOCKET sock)
        : socket(sock)
    {
    }

    ENET_INLINE ENetSocket& operator=(SOCKET sock)
    {
        socket = sock;
        return *this;
    }

    ENET_INLINE operator        SOCKET()        { return socket; }
    ENET_INLINE operator const  SOCKET() const  { return socket; }

    static ENetSocket create(ENetSocketType);

    // socket functions
    int         bind(const ENetAddress*);
    int         get_address(ENetAddress*);
    int         listen(int);
    ENetSocket  accept(ENetAddress*);
    int         connect(const ENetAddress*);
    int         send(const ENetAddress*, const ENetBuffer*, size_t);
    int         receive(ENetAddress*, ENetBuffer*, size_t);
    int         wait(enet_uint32*, enet_uint32);
    int         set_option(ENetSocketOption, int);
    int         get_option(ENetSocketOption, int*);
    int         shutdown(ENetSocketShutdown);
    void        destroy();
    int         select(ENetSocketSet*, ENetSocketSet*, enet_uint32);
};

static_assert(sizeof(ENetSocket) == sizeof(SOCKET), "Error: wrong size!");

#endif

#ifdef _UNIX
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#ifdef MSG_MAXIOVLEN
#define ENET_BUFFER_MAXIMUM MSG_MAXIOVLEN
#endif

typedef int ENetSocket;

#define ENET_SOCKET_NULL -1

#define ENET_HOST_TO_NET_16(value) (htons(value)) /**< macro that converts host to net byte-order of a 16-bit value */
#define ENET_HOST_TO_NET_32(value) (htonl(value)) /**< macro that converts host to net byte-order of a 32-bit value */

#define ENET_NET_TO_HOST_16(value) (ntohs(value)) /**< macro that converts net to host byte-order of a 16-bit value */
#define ENET_NET_TO_HOST_32(value) (ntohl(value)) /**< macro that converts net to host byte-order of a 32-bit value */

struct ENetBuffer {
    void* data;
    size_t dataLength;
};

#define ENET_CALLBACK

#define ENET_API extern

typedef fd_set ENetSocketSet;

#define ENET_SOCKETSET_EMPTY(sockset) FD_ZERO(&(sockset))
#define ENET_SOCKETSET_ADD(sockset, socket) FD_SET(socket, &(sockset))
#define ENET_SOCKETSET_REMOVE(sockset, socket) FD_CLR(socket, &(sockset))
#define ENET_SOCKETSET_CHECK(sockset, socket) FD_ISSET(socket, &(sockset))
#endif

#ifdef _MSC_VER
#pragma pack(push, 1)
#define ENET_PACKED
#elif defined(__GNUC__) || defined(__clang__)
#define ENET_PACKED __attribute__((packed))
#else
#define ENET_PACKED
#endif

ENET_PACKED struct ENetProtocolHeader
{
    enet_uint16                 peerID;
    enet_uint16                 sentTime;
};

ENET_PACKED struct ENetProtocolCommandHeader
{
    enet_uint8                  command;
    enet_uint8                  channelID;
    enet_uint16                 reliableSequenceNumber;
};

ENET_PACKED struct ENetProtocolAcknowledge
{
    ENetProtocolCommandHeader   header;
    enet_uint16                 receivedReliableSequenceNumber;
    enet_uint16                 receivedSentTime;
};

ENET_PACKED struct ENetProtocolConnect
{
    ENetProtocolCommandHeader   header;
    enet_uint16                 outgoingPeerID;
    enet_uint8                  incomingSessionID;
    enet_uint8                  outgoingSessionID;
    enet_uint32                 mtu;
    enet_uint32                 windowSize;
    enet_uint32                 channelCount;
    enet_uint32                 incomingBandwidth;
    enet_uint32                 outgoingBandwidth;
    enet_uint32                 packetThrottleInterval;
    enet_uint32                 packetThrottleAcceleration;
    enet_uint32                 packetThrottleDeceleration;
    enet_uint32                 connectID;
    enet_uint32                 data;
};

ENET_PACKED struct ENetProtocolVerifyConnect
{
    ENetProtocolCommandHeader   header;
    enet_uint16                 outgoingPeerID;
    enet_uint8                  incomingSessionID;
    enet_uint8                  outgoingSessionID;
    enet_uint32                 mtu;
    enet_uint32                 windowSize;
    enet_uint32                 channelCount;
    enet_uint32                 incomingBandwidth;
    enet_uint32                 outgoingBandwidth;
    enet_uint32                 packetThrottleInterval;
    enet_uint32                 packetThrottleAcceleration;
    enet_uint32                 packetThrottleDeceleration;
    enet_uint32                 connectID;
};

ENET_PACKED struct ENetProtocolBandwidthLimit
{
    ENetProtocolCommandHeader   header;
    enet_uint32                 incomingBandwidth;
    enet_uint32                 outgoingBandwidth;
};

ENET_PACKED struct ENetProtocolThrottleConfigure
{
    ENetProtocolCommandHeader   header;
    enet_uint32                 packetThrottleInterval;
    enet_uint32                 packetThrottleAcceleration;
    enet_uint32                 packetThrottleDeceleration;
};

ENET_PACKED struct ENetProtocolDisconnect
{
    ENetProtocolCommandHeader   header;
    enet_uint32                 data;
};

ENET_PACKED struct ENetProtocolPing
{
    ENetProtocolCommandHeader   header;
};

ENET_PACKED struct ENetProtocolSendReliable
{
    ENetProtocolCommandHeader   header;
    enet_uint16                 dataLength;
};

ENET_PACKED struct ENetProtocolSendUnreliable
{
    ENetProtocolCommandHeader   header;
    enet_uint16                 unreliableSequenceNumber;
    enet_uint16                 dataLength;
};

ENET_PACKED struct ENetProtocolSendUnsequenced
{
    ENetProtocolCommandHeader   header;
    enet_uint16                 unsequencedGroup;
    enet_uint16                 dataLength;
};

ENET_PACKED struct ENetProtocolSendFragment
{
    ENetProtocolCommandHeader   header;
    enet_uint16                 startSequenceNumber;
    enet_uint16                 dataLength;
    enet_uint32                 fragmentCount;
    enet_uint32                 fragmentNumber;
    enet_uint32                 totalLength;
    enet_uint32                 fragmentOffset;
};

ENET_PACKED union ENetProtocol
{
    ENetProtocolCommandHeader   header;
    ENetProtocolAcknowledge     acknowledge;
    ENetProtocolConnect         connect;
    ENetProtocolVerifyConnect   verifyConnect;
    ENetProtocolDisconnect      disconnect;
    ENetProtocolPing            ping;
    ENetProtocolSendReliable    sendReliable;
    ENetProtocolSendUnreliable  sendUnreliable;
    ENetProtocolSendUnsequenced sendUnsequenced;
    ENetProtocolSendFragment    sendFragment;
    ENetProtocolBandwidthLimit  bandwidthLimit;
    ENetProtocolThrottleConfigure throttleConfigure;
};

#ifdef _MSC_VER
#pragma pack(pop)
#endif

// list.h

struct ENetListNode final
{
    ENetListNode* next;
    ENetListNode* previous;
};

typedef ENetListNode* ENetListIterator;

struct ENetList final
{
    ENetListNode sentinel;

    ENET_INLINE ENetListIterator    begin()     { return sentinel.next; }
    ENET_INLINE ENetListIterator    end()       { return &sentinel; }

    ENET_INLINE ENetListIterator    front()     { return sentinel.next; }
    ENET_INLINE ENetListIterator    back()      { return sentinel.previous; }

    ENET_INLINE bool                empty()     { return begin() == end(); }

    static ENET_INLINE ENetListIterator next(ENetListIterator iterator)     { return iterator->next; }
    static ENET_INLINE ENetListIterator previous(ENetListIterator iterator) { return iterator->previous; }

    ENET_INLINE void clear()
    {
        sentinel.next = &sentinel;
        sentinel.previous = &sentinel;
    }

    static ENET_INLINE ENetListIterator insert(ENetListIterator position, void* data)
    {
        ENetListIterator result = (ENetListIterator)data;

        result->previous        = position->previous;
        result->next            = position;

        result->previous->next  = result;
        position->previous      = result;

        return result;
    }

    static ENET_INLINE void* remove(ENetListIterator position)
    {
        position->previous->next = position->next;
        position->next->previous = position->previous;

        return position;
    }

    static ENET_INLINE ENetListIterator move(ENetListIterator position, void* dataFirst, void* dataLast)
    {
        ENetListIterator first  = (ENetListIterator)dataFirst;
        ENetListIterator last   = (ENetListIterator)dataLast;

        first->previous->next   = last->next;
        last->next->previous    = first->previous;

        first->previous         = position->previous;
        last->next              = position;

        first->previous->next   = first;
        position->previous      = last;

        return first;
    }

    ENET_INLINE size_t size()
    {
        size_t size = 0;

        for (ENetListIterator position = begin(); position != end(); ++position)
            ++size;

        return size;
    }
};

struct ENetCallbacks
{
    void*   (ENET_CALLBACK* malloc)(size_t size);
    void    (ENET_CALLBACK* free)(void* memory);
    void    (ENET_CALLBACK* no_memory)(void);
};

extern void* enet_malloc(size_t);
extern void enet_free(void*);

// enet
typedef enet_uint32 ENetVersion;

struct ENetHost;
struct ENetEvent;
struct ENetPacket;

/**
 * Portable internet address structure.
 *
 * The host must be specified in network byte-order, and the port must be in host
 * byte-order. The constant ENET_HOST_ANY may be used to specify the default
 * server host. The constant ENET_HOST_BROADCAST may be used to specify the
 * broadcast address (255.255.255.255).  This makes sense for enet_host_connect,
 * but not for enet_host_create.  Once a server responds to a broadcast, the
 * address is updated from ENET_HOST_BROADCAST to the server's actual IP address.
 */
struct ENET_API ENetAddress
{
    enet_uint32 host;
    enet_uint16 port;

    /** Attempts to resolve the host named by the parameter hostName and sets
        the host field in the address parameter if successful.
        @param hostName host name to lookup
        @retval 0 on success
        @retval < 0 on failure
        @returns the address of the given hostName in address on success
    */
    int set_host(const char* hostName);

    /** Gives the printable form of the IP address specified in the address parameter.
        @param hostName   destination for name, must not be NULL
        @param nameLength maximum length of hostName.
        @returns the null-terminated name of the host in hostName on success
        @retval 0 on success
        @retval < 0 on failure
    */
    int get_host_ip(char* hostName, size_t nameLength);

    /** Attempts to do a reverse lookup of the host field in the address parameter.
        @param hostName   destination for name, must not be NULL
        @param nameLength maximum length of hostName.
        @returns the null-terminated name of the host in hostName on success
        @retval 0 on success
        @retval < 0 on failure
    */
    int get_host(char* hostName, size_t nameLength);
};

/**
 * Packet flag bit constants.
 *
 * The host must be specified in network byte-order, and the port must be in
 * host byte-order. The constant ENET_HOST_ANY may be used to specify the
 * default server host.

 @sa ENetPacket
 */
enum ENetPacketFlag
{
    /** packet must be received by the target peer and resend attempts should be
    * made until the packet is delivered */
    ENET_PACKET_FLAG_RELIABLE = (1 << 0),

    /** packet will not be sequenced with other packets
    * not supported for reliable packets
    */
    ENET_PACKET_FLAG_UNSEQUENCED = (1 << 1),

    /** packet will not allocate data, and user must supply it instead */
    ENET_PACKET_FLAG_NO_ALLOCATE = (1 << 2),

    /** packet will be fragmented using unreliable (instead of reliable) sends
    * if it exceeds the MTU */
    ENET_PACKET_FLAG_UNRELIABLE_FRAGMENT = (1 << 3),

    /** whether the packet has been sent from all queues it has been entered into */
    ENET_PACKET_FLAG_SENT = (1 << 8)
};

typedef void(ENET_CALLBACK* ENetPacketFreeCallback)(ENetPacket*);

/**
 * ENet packet structure.
 *
 * An ENet data packet that may be sent to or received from a peer. The shown
 * fields should only be read and never modified. The data field contains the
 * allocated data for the packet. The dataLength fields specifies the length
 * of the allocated data.  The flags field is either 0 (specifying no flags),
 * or a bitwise-or of any combination of the following flags:
 *
 *    ENET_PACKET_FLAG_RELIABLE - packet must be received by the target peer
 *    and resend attempts should be made until the packet is delivered
 *
 *    ENET_PACKET_FLAG_UNSEQUENCED - packet will not be sequenced with other packets
 *    (not supported for reliable packets)
 *
 *    ENET_PACKET_FLAG_NO_ALLOCATE - packet will not allocate data, and user must supply it instead

 @sa ENetPacketFlag
 */
struct ENET_API ENetPacket
{
    size_t                  referenceCount; /**< internal use only */
    enet_uint32             flags; /**< bitwise-or of ENetPacketFlag constants */
    enet_uint8*             data; /**< allocated data for packet */
    size_t                  dataLength; /**< length of data */
    ENetPacketFreeCallback  freeCallback; /**< function to be called when the packet is no longer in use */
    void*                   userData; /**< application private data, may be freely modified */

    /** Creates a packet that may be sent to a peer.
        @param data         initial contents of the packet's data; the packet's data will remain uninitialized if data is NULL.
        @param dataLength   size of the data allocated for this packet
        @param flags        flags for this packet as described for the ENetPacket structure.
        @returns the packet on success, NULL on failure
    */
    static ENetPacket* create(const void*, size_t, enet_uint32);
    static enet_uint32 crc32(const ENetBuffer*, size_t);

    /** Destroys the packet and deallocates its data.
    */
    void destroy(void);

    /** Attempts to resize the data in the packet to length specified in the dataLength parameter
        @param dataLength new size for the packet data
        @returns 0 on success, < 0 on failure
    */
    int resize(size_t);
};

struct ENetAcknowledgement
{
    ENetListNode    acknowledgementList;
    enet_uint32     sentTime;
    ENetProtocol    command;
};

struct ENetOutgoingCommand
{
    ENetListNode    outgoingCommandList;
    enet_uint16     reliableSequenceNumber;
    enet_uint16     unreliableSequenceNumber;
    enet_uint32     sentTime;
    enet_uint32     roundTripTimeout;
    enet_uint32     roundTripTimeoutLimit;
    enet_uint32     fragmentOffset;
    enet_uint16     fragmentLength;
    enet_uint16     sendAttempts;
    ENetProtocol    command;
    ENetPacket*     packet;
};

struct ENetIncomingCommand
{
    ENetListNode    incomingCommandList;
    enet_uint16     reliableSequenceNumber;
    enet_uint16     unreliableSequenceNumber;
    ENetProtocol    command;
    enet_uint32     fragmentCount;
    enet_uint32     fragmentsRemaining;
    enet_uint32*    fragments;
    ENetPacket*     packet;
};

struct ENetChannel
{
    enet_uint16     outgoingReliableSequenceNumber;
    enet_uint16     outgoingUnreliableSequenceNumber;
    enet_uint16     usedReliableWindows;
    enet_uint16     reliableWindows[ENET_PEER_RELIABLE_WINDOWS];
    enet_uint16     incomingReliableSequenceNumber;
    enet_uint16     incomingUnreliableSequenceNumber;
    ENetList        incomingReliableCommands;
    ENetList        incomingUnreliableCommands;
};

/**
 * An ENet peer which data packets may be sent or received from.
 *
 * No fields should be modified unless otherwise specified.
 */
struct ENET_API ENetPeer
{
    ENetListNode    dispatchList;
    ENetHost*       host;
    enet_uint16     outgoingPeerID;
    enet_uint16     incomingPeerID;
    enet_uint32     connectID;
    enet_uint8      outgoingSessionID;
    enet_uint8      incomingSessionID;
    ENetAddress     address; /**< Internet address of the peer */
    void*           data; /**< Application private data, may be freely modified */
    ENetPeerState   state;
    ENetChannel*    channels;
    size_t          channelCount; /**< Number of channels allocated for communication with peer */
    enet_uint32     incomingBandwidth; /**< Downstream bandwidth of the client in bytes/second */
    enet_uint32     outgoingBandwidth; /**< Upstream bandwidth of the client in bytes/second */
    enet_uint32     incomingBandwidthThrottleEpoch;
    enet_uint32     outgoingBandwidthThrottleEpoch;
    enet_uint32     incomingDataTotal;
    enet_uint32     outgoingDataTotal;
    enet_uint32     lastSendTime;
    enet_uint32     lastReceiveTime;
    enet_uint32     nextTimeout;
    enet_uint32     earliestTimeout;
    enet_uint32     packetLossEpoch;
    enet_uint32     packetsSent;
    enet_uint32     packetsLost;
    enet_uint32     packetLoss; /**< mean packet loss of reliable packets as a ratio with respect to the constant ENET_PEER_PACKET_LOSS_SCALE */
    enet_uint32     packetLossVariance;
    enet_uint32     packetThrottle;
    enet_uint32     packetThrottleLimit;
    enet_uint32     packetThrottleCounter;
    enet_uint32     packetThrottleEpoch;
    enet_uint32     packetThrottleAcceleration;
    enet_uint32     packetThrottleDeceleration;
    enet_uint32     packetThrottleInterval;
    enet_uint32     pingInterval;
    enet_uint32     timeoutLimit;
    enet_uint32     timeoutMinimum;
    enet_uint32     timeoutMaximum;
    enet_uint32     lastRoundTripTime;
    enet_uint32     lowestRoundTripTime;
    enet_uint32     lastRoundTripTimeVariance;
    enet_uint32     highestRoundTripTimeVariance;
    enet_uint32     roundTripTime; /**< mean round trip time (RTT), in milliseconds, between sending a reliable packet and receiving its acknowledgement */
    enet_uint32     roundTripTimeVariance;
    enet_uint32     mtu;
    enet_uint32     windowSize;
    enet_uint32     reliableDataInTransit;
    enet_uint16     outgoingReliableSequenceNumber;
    ENetList        acknowledgements;
    ENetList        sentReliableCommands;
    ENetList        sentUnreliableCommands;
    ENetList        outgoingReliableCommands;
    ENetList        outgoingUnreliableCommands;
    ENetList        dispatchedCommands;
    int             needsDispatch;
    enet_uint16     incomingUnsequencedGroup;
    enet_uint16     outgoingUnsequencedGroup;
    enet_uint32     unsequencedWindow[ENET_PEER_UNSEQUENCED_WINDOW_SIZE / 32];
    enet_uint32     eventData;
    size_t          totalWaitingData;

    /** Queues a packet to be sent.
        @param channelID channel on which to send
        @param packet packet to send
        @retval 0 on success
        @retval < 0 on failure
    */
    int                     send(enet_uint8, ENetPacket*);

    /** Attempts to dequeue any incoming queued packet.
        @param channelID holds the channel ID of the channel the packet was received on success
        @returns a pointer to the packet, or NULL if there are no available incoming queued packets
    */
    ENetPacket*             receive(enet_uint8* channelID);

    /** Sends a ping request to a peer.
        @remarks ping requests factor into the mean round trip time as designated by the
        roundTripTime field in the ENetPeer structure.  ENet automatically pings all connected
        peers at regular intervals, however, this function may be called to ensure
        more frequent ping requests.
    */
    void                    ping();

    /** Sets the interval at which pings will be sent to a peer.
        Pings are used both to monitor the liveness of the connection and also to dynamically
        adjust the throttle during periods of low traffic so that the throttle has
        reasonable responsiveness during traffic spikes.

        @param pingInterval the interval at which to send pings; defaults to ENET_PEER_PING_INTERVAL if 0
    */
    void                    ping_interval(enet_uint32);

    /** Sets the timeout parameters for a peer.

        The timeout parameter control how and when a peer will timeout from a failure to acknowledge
        reliable traffic. Timeout values use an exponential backoff mechanism, where if a reliable
        packet is not acknowledge within some multiple of the average RTT plus a variance tolerance,
        the timeout will be doubled until it reaches a set limit. If the timeout is thus at this
        limit and reliable packets have been sent but not acknowledged within a certain minimum time
        period, the peer will be disconnected. Alternatively, if reliable packets have been sent
        but not acknowledged for a certain maximum time period, the peer will be disconnected regardless
        of the current timeout limit value.

        @param timeoutLimit the timeout limit; defaults to ENET_PEER_TIMEOUT_LIMIT if 0
        @param timeoutMinimum the timeout minimum; defaults to ENET_PEER_TIMEOUT_MINIMUM if 0
        @param timeoutMaximum the timeout maximum; defaults to ENET_PEER_TIMEOUT_MAXIMUM if 0
    */
    void                    timeout(enet_uint32, enet_uint32, enet_uint32);

    /** Forcefully disconnects a peer.
        @remarks The foreign host represented by the peer is not notified of the
        disconnection and will timeout on its connection to the local host.
    */
    void                    reset();

    /** Request a disconnection from a peer.
        @param data data describing the disconnection
        @remarks An ENET_EVENT_DISCONNECT event will be generated by enet_host_service() once the disconnection is complete.
    */
    void                    disconnect(enet_uint32);

    /** Force an immediate disconnection from a peer.
        @param data data describing the disconnection
        @remarks No ENET_EVENT_DISCONNECT event will be generated. The foreign peer is not
        guaranteed to receive the disconnect notification, and is reset immediately
        upon return from this function.
    */
    void                    disconnect_now(enet_uint32);

    /** Request a disconnection from a peer, but only after all queued outgoing packets are sent.
        @param data data describing the disconnection
        @remarks An ENET_EVENT_DISCONNECT event will be generated by enet_host_service() once the disconnection is complete.
    */
    void                    disconnect_later(enet_uint32);

    /** Configures throttle parameter for a peer.

        Unreliable packets are dropped by ENet in response to the varying conditions
        of the Internet connection to the peer.  The throttle represents a probability
        that an unreliable packet should not be dropped and thus sent by ENet to the peer.

        The lowest mean round trip time from the sending of a reliable packet to the
        receipt of its acknowledgement is measured over an amount of time specified by
        the interval parameter in milliseconds.  If a measured round trip time happens to
        be significantly less than the mean round trip time measured over the interval,
        then the throttle probability is increased to allow more traffic by an amount
        specified in the acceleration parameter, which is a ratio to the ENET_PEER_PACKET_THROTTLE_SCALE
        constant.  If a measured round trip time happens to be significantly greater than
        the mean round trip time measured over the interval, then the throttle probability
        is decreased to limit traffic by an amount specified in the deceleration parameter, which
        is a ratio to the ENET_PEER_PACKET_THROTTLE_SCALE constant.  When the throttle has
        a value of ENET_PEER_PACKET_THROTTLE_SCALE, no unreliable packets are dropped by
        ENet, and so 100% of all unreliable packets will be sent.  When the throttle has a
        value of 0, all unreliable packets are dropped by ENet, and so 0% of all unreliable
        packets will be sent.  Intermediate values for the throttle represent intermediate
        probabilities between 0% and 100% of unreliable packets being sent.  The bandwidth
        limits of the local and foreign hosts are taken into account to determine a
        sensible limit for the throttle probability above which it should not raise
        even in the best of conditions.

        @param interval interval, in milliseconds, over which to measure lowest mean RTT; the default value is ENET_PEER_PACKET_THROTTLE_INTERVAL.
        @param acceleration rate at which to increase the throttle probability as mean RTT declines
        @param deceleration rate at which to decrease the throttle probability as mean RTT increases
    */
    void                    throttle_configure(enet_uint32, enet_uint32, enet_uint32);
    int                     throttle(enet_uint32);

    void                    reset_queues();
    void                    setup_outgoing_command(ENetOutgoingCommand*);
    ENetOutgoingCommand*    queue_outgoing_command(const ENetProtocol*, ENetPacket*, enet_uint32, enet_uint16);
    ENetIncomingCommand*    queue_incoming_command(const ENetProtocol*, const void*, size_t, enet_uint32, enet_uint32);
    ENetAcknowledgement*    queue_acknowledgement(const ENetProtocol*, enet_uint16);
    void                    dispatch_incoming_unreliable_commands(ENetChannel*);
    void                    dispatch_incoming_reliable_commands(ENetChannel*);
    void                    on_connect();
    void                    on_disconnect();
};

/** An ENet packet compressor for compressing UDP packets before socket sends or receives.
 */
struct ENetCompressor
{
    /** Context data for the compressor. Must be non-NULL. */
    void* context;
    /** Compresses from inBuffers[0:inBufferCount-1], containing inLimit bytes, to outData, outputting at most outLimit bytes. Should return 0 on failure. */
    size_t(ENET_CALLBACK* compress)(void* context, const ENetBuffer* inBuffers, size_t inBufferCount, size_t inLimit, enet_uint8* outData, size_t outLimit);
    /** Decompresses from inData, containing inLimit bytes, to outData, outputting at most outLimit bytes. Should return 0 on failure. */
    size_t(ENET_CALLBACK* decompress)(void* context, const enet_uint8* inData, size_t inLimit, enet_uint8* outData, size_t outLimit);
    /** Destroys the context when compression is disabled or the host is destroyed. May be NULL. */
    void(ENET_CALLBACK* destroy)(void* context);
};

/** Callback that computes the checksum of the data held in buffers[0:bufferCount-1] */
typedef enet_uint32(ENET_CALLBACK* ENetChecksumCallback)(const ENetBuffer* buffers, size_t bufferCount);

/** Callback for intercepting received raw UDP packets. Should return 1 to intercept, 0 to ignore, or -1 to propagate an error. */
typedef int(ENET_CALLBACK* ENetInterceptCallback)(ENetHost* host, ENetEvent* event);

/** An ENet host for communicating with peers.
  *
  * No fields should be modified unless otherwise stated.
  @sa enet_host_create()
  @sa enet_host_destroy()
  @sa enet_host_connect()
  @sa enet_host_service()
  @sa enet_host_flush()
  @sa enet_host_broadcast()
  @sa enet_host_compress()
  @sa enet_host_compress_with_range_coder()
  @sa enet_host_channel_limit()
  @sa enet_host_bandwidth_limit()
  @sa enet_host_bandwidth_throttle()
  */
struct ENET_API ENetHost {
    ENetSocket              socket;
    ENetAddress             address; /**< Internet address of the host */
    enet_uint32             incomingBandwidth; /**< downstream bandwidth of the host */
    enet_uint32             outgoingBandwidth; /**< upstream bandwidth of the host */
    enet_uint32             bandwidthThrottleEpoch;
    enet_uint32             mtu;
    enet_uint32             randomSeed;
    int                     recalculateBandwidthLimits;
    ENetPeer*               peers; /**< array of peers allocated for this host */
    size_t                  peerCount; /**< number of peers allocated for this host */
    size_t                  channelLimit; /**< maximum number of channels allowed for connected peers */
    enet_uint32             serviceTime;
    ENetList                dispatchQueue;
    int                     continueSending;
    size_t                  packetSize;
    enet_uint16             headerFlags;
    ENetProtocol            commands[ENET_PROTOCOL_MAXIMUM_PACKET_COMMANDS];
    size_t                  commandCount;
    ENetBuffer              buffers[ENET_BUFFER_MAXIMUM];
    size_t                  bufferCount;
    ENetChecksumCallback    checksum; /**< callback the user can set to enable packet checksums for this host */
    ENetCompressor          compressor;
    enet_uint8              packetData[2][ENET_PROTOCOL_MAXIMUM_MTU];
    ENetAddress             receivedAddress;
    enet_uint8*             receivedData;
    size_t                  receivedDataLength;
    enet_uint32             totalSentData; /**< total data sent, user should reset to 0 as needed to prevent overflow */
    enet_uint32             totalSentPackets; /**< total UDP packets sent, user should reset to 0 as needed to prevent overflow */
    enet_uint32             totalReceivedData; /**< total data received, user should reset to 0 as needed to prevent overflow */
    enet_uint32             totalReceivedPackets; /**< total UDP packets received, user should reset to 0 as needed to prevent overflow */
    ENetInterceptCallback   intercept; /**< callback the user can set to intercept received raw UDP packets */
    size_t                  connectedPeers;
    size_t                  bandwidthLimitedPeers;
    size_t                  duplicatePeers; /**< optional number of allowed peers from duplicate IPs, defaults to ENET_PROTOCOL_MAXIMUM_PEER_ID */
    size_t                  maximumPacketSize; /**< the maximum allowable packet size that may be sent or received on a peer */
    size_t                  maximumWaitingData; /**< the maximum aggregate amount of buffer space a peer may use waiting for packets to be delivered */

    /** Creates a host for communicating to peers.
        @param address   the address at which other peers may connect to this host.  If NULL, then no peers may connect to the host.
        @param peerCount the maximum number of peers that should be allocated for the host.
        @param channelLimit the maximum number of channels allowed; if 0, then this is equivalent to ENET_PROTOCOL_MAXIMUM_CHANNEL_COUNT
        @param incomingBandwidth downstream bandwidth of the host in bytes/second; if 0, ENet will assume unlimited bandwidth.
        @param outgoingBandwidth upstream bandwidth of the host in bytes/second; if 0, ENet will assume unlimited bandwidth.
        @returns the host on success and NULL on failure
        @remarks ENet will strategically drop packets on specific sides of a connection between hosts
        to ensure the host's bandwidth is not overwhelmed.  The bandwidth parameters also determine
        the window size of a connection which limits the amount of reliable packets that may be in transit
        at any given time.
    */
    static ENetHost* create(const ENetAddress*, size_t, size_t, enet_uint32, enet_uint32);

    /** Destroys the host and all resources associated with it.
    */
    void destroy();

    /** Initiates a connection to a foreign host.
        @param address destination for the connection
        @param channelCount number of channels to allocate
        @param data user data supplied to the receiving host 
        @returns a peer representing the foreign host on success, NULL on failure
        @remarks The peer returned will have not completed the connection until enet_host_service()
        notifies of an ENET_EVENT_TYPE_CONNECT event for the peer.
    */
    ENetPeer* connect(const ENetAddress*, size_t, enet_uint32);

    /** Queues a packet to be sent to all peers associated with the host.
        @param channelID channel on which to broadcast
        @param packet packet to broadcast
    */
    void broadcast(enet_uint8, ENetPacket*);

    /** Checks for any queued events on the host and dispatches one if available.
        @param event   an event structure where event details will be placed if available
        @retval > 0 if an event was dispatched
        @retval 0 if no events are available
        @retval < 0 on failure
        @ingroup host
    */
    int check_events(ENetEvent*);

    /** Waits for events on the host specified and shuttles packets between the host and its peers.
        @param event   an event structure where event details will be placed if one occurs
        if event == NULL then no events will be delivered
        @param timeout number of milliseconds that ENet should wait for events
        @retval > 0 if an event occurred within the specified time limit
        @retval 0 if no event occurred
        @retval < 0 on failure
        @remarks enet_host_service should be called fairly regularly for adequate performance
        @ingroup host
    */
    int service(ENetEvent*, enet_uint32);

    /** Sends any queued packets on the host specified to its designated peers.
        @remarks this function need only be used in circumstances where one wishes to send queued packets earlier than in a call to enet_host_service().
        @ingroup host
    */
    void flush(void);

    /** Sets the packet compressor the host should use to compress and decompress packets.
        @param compressor callbacks for for the packet compressor; if NULL, then compression is disabled
    */
    void compress(const ENetCompressor*);

    /** Limits the maximum allowed channels of future incoming connections.
        @param channelLimit the maximum number of channels allowed; if 0, then this is equivalent to ENET_PROTOCOL_MAXIMUM_CHANNEL_COUNT
        */
    void channel_limit(size_t);

    /** Adjusts the bandwidth limits of a host.
        @param incomingBandwidth new incoming bandwidth
        @param outgoingBandwidth new outgoing bandwidth
        @remarks the incoming and outgoing bandwidth parameters are identical in function to those
        specified in enet_host_create().
    */
    void bandwidth_limit(enet_uint32, enet_uint32);

    void bandwidth_throttle(void);
    static enet_uint32 random_seed(void);
};

struct ENetEvent
{
    ENetEventType   type; /**< type of the event */
    ENetPeer*       peer; /**< peer that generated a connect, disconnect or receive event */
    enet_uint8      channelID; /**< channel on the peer that generated the event, if appropriate */
    enet_uint32     data; /**< data associated with the event, if appropriate */
    ENetPacket*     packet; /**< packet associated with the event, if appropriate */
};


ENET_API int            enet_initialize(void);
ENET_API int            enet_initialize_with_callbacks(ENetVersion version, const ENetCallbacks* inits);
ENET_API void           enet_deinitialize(void);
ENET_API ENetVersion    enet_linked_version(void);

ENET_API enet_uint32    enet_time_get(void);
ENET_API void           enet_time_set(enet_uint32);

ENET_API size_t         enet_protocol_command_size(enet_uint8);

#undef ENET_API
#undef ENET_CALLBACK
#undef ENET_INLINE
#undef ENET_PACKED
