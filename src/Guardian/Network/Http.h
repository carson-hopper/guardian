#pragma once

#include "Guardian/Core/Base.h"
#include <curl/curl.h>

class Http {
public:
    Http(std::string  url);
    ~Http();

    void GET(const std::string& document);

    virtual std::string& GetBuffer() { return m_Buffer; }
    virtual CURLcode& GetCode() { return m_Code; }

private:
    CURL* m_Curl;
    CURLcode m_Code;

    std::string m_Url;
    std::string m_Buffer;

};