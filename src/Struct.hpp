/**
 * @file Struct.hpp
 * @brief 结构体定义
 * @author Christins (chen.christins@qq.com)
 * @date 2026-05-30
 * @copyright Apache 2.0
 */
#pragma once

#include <chen/util/json_util.h>
#include <chen/http/servlet.h>

namespace auth {

struct Result {
    typedef std::shared_ptr<Result> ptr;

    Result(int32_t c = 200, const std::string& message = "ok");

    int32_t code_;
    int64_t used_;
    std::string message_;
    Json::Value jsondata_;

    template <class T>
    void set(const std::string& key, const T& v) {
        jsondata_[key] = v;
    }
    void set(const std::string& key, const char* v) {
        jsondata_[key] = v;
    }
    void set(const std::string& key, const std::string& v) {
        jsondata_[key] = v;
    }

    template <class T>
    void append(const std::string& key, const T& v) {
        jsondata_[key].append(v);
    }

    void setResult(int32_t c, const std::string& message);

    std::string toJsonString() const;
};

class AuthServlet : public chen::http::Servlet {
public:
    AuthServlet(const std::string& name);

    virtual int32_t handle(chen::http::HttpRequest::ptr request, 
                           chen::http::HttpResponse::ptr response, 
                           chen::http::HttpSession::ptr session) override;

    virtual int32_t handle(chen::http::HttpRequest::ptr request, 
                           chen::http::HttpResponse::ptr response, 
                           chen::http::HttpSession::ptr session,
                           Result::ptr result) = 0;
};

} // namespace auth