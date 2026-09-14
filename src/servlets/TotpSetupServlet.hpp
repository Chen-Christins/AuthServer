/**
 * @file TotpSetupServlet.hpp
 * @brief 生成 TOTP 密钥 /totp/setup
 * @author Christins
 * @date 2026-09-14
 * @copyright Apache 2.0
 */
#pragma once

#include "../Struct.hpp"

namespace auth {

class TotpSetupServlet : public AuthServlet {
public:
    TotpSetupServlet();

    virtual int32_t handle(chen::http::HttpRequest::ptr request,
                           chen::http::HttpResponse::ptr response,
                           chen::http::HttpSession::ptr session,
                           Result::ptr result) override;
};

} // namespace auth
