/**
 * @file LoginServlet.hpp
 * @brief 登录页面 /login
 * @author Christins (chen.christins@qq.com)
 * @date 2026-06-29
 * @copyright Apache 2.0
 */
#pragma once

#include "../Struct.hpp"

namespace auth {

class LoginServlet : public AuthServlet {
public:
    LoginServlet();

    virtual int32_t handle(chen::http::HttpRequest::ptr request, 
                           chen::http::HttpResponse::ptr response,
                           chen::http::HttpSession::ptr session, 
                           Result::ptr result) override;

private:
    int32_t handleGet(chen::http::HttpRequest::ptr request, chen::http::HttpResponse::ptr response);
    
    int32_t handlePost(chen::http::HttpRequest::ptr request, chen::http::HttpResponse::ptr response);
};

} // namespace auth
