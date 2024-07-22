#include "gdpch.h"
#include "Guardian/Network/Http.h"

Http::Http(std::string  url)
    : m_Client(url), m_Status(httplib::StatusCode::InternalServerError_500), m_Url(std::move(url)) {
}

Http::~Http() = default;

void Http::GET(const std::string& document) {
    auto request = m_Client.Get(document);
    m_Buffer = request->body;
    m_Status = static_cast<httplib::StatusCode>(request->status);
    m_Error = request->reason;
}
