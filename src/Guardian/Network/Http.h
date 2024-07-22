#pragma once

#include "Guardian/Core/Base.h"
#include "httplib.h"

class Http {
public:
    explicit Http(std::string url);
    ~Http();

    void GET(const std::string& document);

    virtual std::string& GetBuffer() { return m_Buffer; }
    virtual httplib::StatusCode& GetStatus() { return m_Status; }
    virtual std::string& GetError() { return m_Error; }

private:
    httplib::Client m_Client;
    httplib::StatusCode m_Status;
    std::string m_Error;

    std::string m_Url;
    std::string m_Buffer;

};