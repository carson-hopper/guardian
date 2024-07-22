#include "gdpch.h"

#include "Guardian/Network/Packet/Packet.h"

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/in.h>

std::map<uint64_t, TcpConnection> Packet::s_Connections;

Packet::Packet(OptionalRefWrapper<nfq_q_handle> queueHandle, OptionalRefWrapper<nfq_data> packetHandle, OptionalRefWrapper<nfqnl_msg_packet_hdr> packetMessageHandle)
    : m_QueueHandle(queueHandle), m_PacketHandle(packetHandle), m_PacketMessageHandle(packetMessageHandle), m_Verdict(0), m_HasSetVerdict(false) {

    if (packetMessageHandle.has_value())
        m_Id = ntohl(packetMessageHandle->get().packet_id);
}

Buffer& Packet::GetBuffer() {
    if (m_PacketHandle.has_value() && m_Payload.Size == 0) {
        uint8_t* payload;
        if (const uint32_t payloadLength = nfq_get_payload(&m_PacketHandle->get(), &payload); payloadLength > 0) {
            m_Payload = Buffer(payload, payloadLength);
            m_IpPacket = CreateRef<IpPacket>(m_Payload);
        }
    }
    return m_Payload;
}
Ref<IpPacket> Packet::GetIpPacket() {
    if (m_IpPacket == nullptr) {
        GetBuffer();
    }
    return m_IpPacket;
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

    if (m_QueueHandle.has_value()) {
        m_Verdict = nfq_set_verdict(&m_QueueHandle->get(), m_Id, verdict, GetBuffer().Size, GetBuffer().Data);
        m_HasSetVerdict = true;
    }
    return m_Verdict;
}