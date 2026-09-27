/**
 * @file TokenServlet.hpp
 * @brief OIDC Token 端点 /token
 * @author Christins (chen.christins@qq.com)
 * @date 2026-06-29
 * @copyright Apache 2.0
 */
#pragma once

#include "../Struct.hpp"

namespace auth {

class TokenServlet : public AuthServlet {
public:
    TokenServlet();

    virtual int32_t handle(chen::http::HttpRequest::ptr request,
                           chen::http::HttpResponse::ptr response,
                           chen::http::HttpSession::ptr session,
                           Result::ptr result) override;

private:
    int32_t handleAuthCodeGrant(chen::http::HttpRequest::ptr request, 
                                chen::http::HttpResponse::ptr response, 
                                Result::ptr result);

    int32_t handleRefreshTokenGrant(chen::http::HttpRequest::ptr request, 
                                    chen::http::HttpResponse::ptr response, 
                                    Result::ptr result);

    int32_t handleTotpGrant(chen::http::HttpRequest::ptr request,
                            chen::http::HttpResponse::ptr response,
                            Result::ptr result);

    int32_t handleTotpRecoveryGrant(chen::http::HttpRequest::ptr request,
                                    chen::http::HttpResponse::ptr response,
                                    Result::ptr result);
};

} // namespace auth
