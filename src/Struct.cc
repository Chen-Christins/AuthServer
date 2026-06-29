#include "Struct.hpp"

#include <chen/util/util.h>

#include <ctime>

namespace auth {

Result::Result(int32_t c, const std::string& m)
    : code_(c)
    , used_(chen::GetCurrentUs())
    , message_(m) {
}

void Result::setResult(int32_t c, const std::string& message) {
    code_ = c;
    message_ = message;
}

std::string Result::toJsonString() const {
    Json::Value v;
    v["code"] = std::to_string(code_);
    v["message"] = message_;
    v["used"] = ((chen::GetCurrentUs() - used_) / 1000.0);
    if (!jsondata_.isNull()) {
        v["data"] = jsondata_;
    }
    return chen::JsonUtil::ToString(v);
}

AuthServlet::AuthServlet(const std::string& name) : chen::http::Servlet(name) {}

int32_t AuthServlet::handle(chen::http::HttpRequest::ptr request
        , chen::http::HttpResponse::ptr response, chen::http::HttpSession::ptr session) {
    uint64_t ts = chen::GetCurrentUs();
    
    Result::ptr result = std::make_shared<Result>();
    int32_t ret = handle(request, response, session, result);

    uint64_t used = chen::GetCurrentUs() - ts;
    response->setHeader("used", std::to_string((used * 1.0 / 1000)) + "ms");
    return ret;
}

} // namespace auth