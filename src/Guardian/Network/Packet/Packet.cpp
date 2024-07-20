#include "gdpch.h"

#include "Guardian/Network/Packet/Packet.h"

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/in.h>

std::map<uint64_t, TcpConnection> Packet::s_Connections;

Packet::Packet(nfq_q_handle* queueHandle, nfq_data* packetHandle, nfqnl_msg_packet_hdr* packetMessageHandle)
    : m_QueueHandle(queueHandle), m_PacketHandle(packetHandle), m_PacketMessageHandle(packetMessageHandle), m_Verdict(0), m_HasSetVerdict(false) {

    m_Id = ntohl(packetMessageHandle->packet_id);

    uint8_t* payload;
    if (const uint32_t payloadLength = nfq_get_payload(m_PacketHandle, &payload); payloadLength > 0) {
        m_Payload = Buffer(payload, payloadLength);
        m_IpPacket = CreateRef<IpPacket>(m_Payload);
    }
}

uint64_t Packet::GetTcpConnectionId() {
    return (static_cast<uint64_t>(GetIpPacket()->GetSourceIp()) << 32) | GetIpPacket()->GetDestinationIp();
}

[[nodiscard]] Ref<TcpConnection> Packet::GetTcpConnection() {
    if (const auto it = s_Connections.find(GetTcpConnectionId()); it != s_Connections.end()) {
        return CreateRef<TcpConnection>(it->second);
    }
    return nullptr;
}

int32_t Packet::SetVerdict(const PacketAction verdict) {
    if (m_HasSetVerdict)
        return m_Verdict;

    m_Verdict = nfq_set_verdict(m_QueueHandle, m_Id, verdict, m_Payload.Size, m_Payload.Data);
    m_HasSetVerdict = true;
    return m_Verdict;
}