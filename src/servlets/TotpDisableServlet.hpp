/**
 * @file TotpDisableServlet.hpp
 * @brief 禁用 2FA /totp/disable
 * @author Christins
 * @date 2026-09-14
 * @copyright Apache 2.0
 */
#pragma once

#include "../Struct.hpp"

namespace auth {

class TotpDisableServlet : public AuthServlet {
public:
    TotpDisableServlet();

    virtual int32_t handle(chen::http::HttpRequest::ptr request,
                           chen::http::HttpResponse::ptr response,
                           chen::http::HttpSession::ptr session,
                           Result::ptr result) override;
};

} // namespace auth
