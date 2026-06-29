/**
 * @file UserInfoServlet.hpp
 * @brief OIDC UserInfo 端点 /userinfo
 * @author Christins (chen.christins@qq.com)
 * @date 2026-06-29
 * @copyright Apache 2.0
 */
#pragma once

#include "../Struct.hpp"

namespace auth {

class UserInfoServlet : public AuthServlet {
public:
    UserInfoServlet();

    virtual int32_t handle(chen::http::HttpRequest::ptr request,
                           chen::http::HttpResponse::ptr response,
                           chen::http::HttpSession::ptr session,
                           Result::ptr result) override;
};

} // namespace auth
