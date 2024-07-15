#pragma once

#include "Guardian/Guardian.h"
#include "Guardian/Network/Packet/IpPacket.h"
#include "Network/Detection/Detection.h"

#include <libnetfilter_queue/libnetfilter_queue.h>

class NfqLayer : public Layer {
public:

    bool OnAttach() override;
    bool OnDetach() override;
    void OnUpdate(Timestep ts) override;

    template<typename T>
        bool PushDetection(short protocol) {
        static_assert(std::is_base_of<Detection, T>::value, "Pushed type is not subclass of Detection!");

        const auto detection = CreateRef<T>(protocol);
        m_Detections.emplace_back(detection);
        return detection->OnAttach();
    }

    static int packet_handler(struct nfq_q_handle *queueHandle, struct nfgenmsg *packetMessage, struct nfq_data *packetHandle, void *packetData);

private:

    nfq_handle* m_Handle = nullptr;
    nfq_q_handle* m_QueueHandle = nullptr;
    int m_fd = 0;

    std::vector<Guardian::Ref<Detection>> m_Detections;
};
