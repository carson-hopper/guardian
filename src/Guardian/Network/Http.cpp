#include "gdpch.h"
#include "Guardian/Network/Http.h"

#include <utility>
#include <curl/curl.h>

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

Http::Http(std::string  url)
    : m_Code(CURLE_NO_CONNECTION_AVAILABLE), m_Url(std::move(url)) {

    curl_global_init(CURL_GLOBAL_DEFAULT);

    m_Curl = curl_easy_init();
    curl_easy_setopt(m_Curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(m_Curl, CURLOPT_WRITEDATA, &m_Buffer);
}

Http::~Http() {
    curl_easy_cleanup(m_Curl);
    curl_global_cleanup();
}

void Http::GET(const std::string& document) {
    curl_easy_setopt(m_Curl, CURLOPT_URL, std::format("{}{}", m_Url, document).c_str());

    m_Code = curl_easy_perform(m_Curl);
}
