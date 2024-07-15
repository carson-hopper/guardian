#include "gdpch.h"
#include "Layer/NfqLayer.h"

#include "Guardian/Network/Packet/IpPacket.h"

#include "Network/Detection/ICMP/IcmpScan.h"
#include "Network/Detection/TCP/ConnectionTracking.h"
#include "Network/Detection/TCP/SynFlood.h"
#include "Network/Detection/TCP/SynStealthScan.h"

#include <pcap.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>

int NfqLayer::packet_handler(nfq_q_handle *queueHandle, nfgenmsg *packetMessage, nfq_data *packetHandle, void *data) {
    auto* layer = static_cast<NfqLayer*>(data);

    const nfqnl_msg_packet_hdr* packet_message_handle = nfq_get_msg_packet_hdr(packetHandle);
    if (!packet_message_handle)
        return nfq_set_verdict(queueHandle, 0, NF_ACCEPT, 0, nullptr);

    uint32_t packetId = ntohl(packet_message_handle->packet_id);

    unsigned char *packetData;
    int packetLength = nfq_get_payload(packetHandle, &packetData);
    if (packetLength >= 0) {
        const auto ipPacket = Guardian::CreateRef<IpPacket>(packetData, packetLength);

        for (const auto& detection : layer->m_Detections) {
            if ((ipPacket->GetProtocol() == detection->GetProtocol() || detection->GetProtocol() == -1)
                && !detection->OnUpdate(ipPacket, &packetData, packetLength))
                    return nfq_set_verdict(queueHandle, packetId, NF_DROP, packetLength, packetData);
        }
    }
    return nfq_set_verdict(queueHandle, packetId, NF_ACCEPT, packetLength, packetData);
}

bool NfqLayer::OnAttach() {
    m_Handle = nfq_open();

    if (!m_Handle) {
        std::cerr << "Error during nfq_open(): " << strerror(errno) << std::endl;
        return false;
    }

    if (nfq_unbind_pf(m_Handle, AF_INET) < 0) {
        std::cerr << "Error during nfq_unbind_pf(): " << strerror(errno) << std::endl;
        nfq_close(m_Handle);
        return false;
    }

    if (nfq_bind_pf(m_Handle, AF_INET) < 0) {
        std::cerr << "Error during nfq_bind_pf(): " << strerror(errno) << std::endl;
        nfq_close(m_Handle);
        return false;
    }

    constexpr int queueNumber = 0;
    m_QueueHandle = nfq_create_queue(m_Handle, queueNumber, &packet_handler, this);

    if (!m_QueueHandle) {
        std::cerr << "Error during nfq_create_queue(): " << strerror(errno) << std::endl;
        nfq_close(m_Handle);
        return false;
    }

    if (nfq_set_mode(m_QueueHandle, NFQNL_COPY_PACKET, 0x5EE) < 0) {
        std::cerr << "Can't set packet_copy mode: " << strerror(errno) << std::endl;
        nfq_destroy_queue(m_QueueHandle);
        nfq_close(m_Handle);
        return false;
    }

    m_fd = nfq_fd(m_Handle);
    if (m_fd < 0) {
        std::cerr << "Failed to get file descriptor for NFQUEUE: " << strerror(errno) << std::endl;
        nfq_destroy_queue(m_QueueHandle);
        nfq_close(m_Handle);
        return false;
    }

    PushDetection<IcmpScan>(IPPROTO_ICMP);

    PushDetection<ConnectionTracking>(IPPROTO_TCP);
    PushDetection<SynFlood>(IPPROTO_TCP);
    PushDetection<SynStealthScan>(IPPROTO_TCP);

    return true;
}

bool NfqLayer::OnDetach() {
    for (const auto& detection : m_Detections)
        detection->OnDetach();

    if (m_QueueHandle)
        nfq_destroy_queue(m_QueueHandle);

    if (m_Handle)
        nfq_close(m_Handle);

    return true;
}

void NfqLayer::OnUpdate(Guardian::Timestep ts) {
    char buffer[0x1000] __attribute__((aligned));
    int rv = recv(m_fd, buffer, sizeof(buffer), 0);
    if (rv >= 0)
        nfq_handle_packet(m_Handle, buffer, rv);
}