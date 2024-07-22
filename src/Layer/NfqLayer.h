#pragma once

#include "Guardian/Guardian.h"
#include "Network/Detection/Mitigation.h"

#include <libnetfilter_queue/libnetfilter_queue.h>

class NfqLayer : public Layer {
public:
    bool OnAttach() override;
    bool OnDetach() override;
    void OnUpdate(Timestep ts) override;

    [[nodiscard]] virtual OptionalRefWrapper<nfq_handle> GetHandle() const { return m_Handle; }
    [[nodiscard]] virtual OptionalRefWrapper<nfq_q_handle> GetQueueHandle() const { return m_QueueHandle; }
    virtual std::vector<Ref<Mitigation>> GetMitigation() { return m_Mitigations; }
    [[nodiscard]] virtual int GetFD() const { return m_fd; }

    template<typename T>
    bool PushMitigation() {
        static_assert(std::is_base_of_v<Mitigation, T>, "Pushed type is not subclass of Mitigation!");
        const auto mitigation = CreateRef<T>();
        m_Mitigations.emplace_back(mitigation);

        GD_INFO("Loading {}", typeid(T).name());

        const bool r = mitigation->OnAttach();
        GD_ASSERT(r, std::format("Failed to load {}", typeid(T).name()));
        GD_INFO("Loaded {}", typeid(T).name());
        return r;
    }

    static int PacketCallback(nfq_q_handle* queueHandle, nfgenmsg* packetMessage, nfq_data* packetHandle, void* data);

private:
    OptionalRefWrapper<nfq_handle> m_Handle;
    OptionalRefWrapper<nfq_q_handle> m_QueueHandle;
    int m_fd = 0;

    std::vector<Ref<Mitigation>> m_Mitigations;
};
