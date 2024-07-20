#pragma once

#include "Guardian/Guardian.h"
#include "Network/Detection/Mitigation.h"

#include <libnetfilter_queue/libnetfilter_queue.h>

class NfqLayer : public Layer {
public:
    bool OnAttach() override;
    bool OnDetach() override;
    void OnUpdate(Timestep ts) override;

    template<typename T>
    bool PushMitigation() {
        static_assert(std::is_base_of_v<Mitigation, T>, "Pushed type is not subclass of Mitigation!");

        const auto mitigation = CreateRef<T>();
        m_Mitigations.emplace_back(mitigation);
        return mitigation->OnAttach();
    }

    static int PacketCallback(nfq_q_handle* queueHandle, nfgenmsg* packetMessage, nfq_data* packetHandle, void* data);

private:
    nfq_handle* m_Handle = nullptr;
    nfq_q_handle* m_QueueHandle = nullptr;
    int m_fd = 0;

    std::vector<Ref<Mitigation>> m_Mitigations;
};
