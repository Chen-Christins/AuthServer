/**
 * @file TotpConfirmServlet.hpp
 * @brief 确认 TOTP 码并启用 2FA /totp/confirm
 * @author Christins
 * @date 2026-09-14
 * @copyright Apache 2.0
 */
#pragma once

#include "../Struct.hpp"

namespace auth {

class TotpConfirmServlet : public AuthServlet {
public:
    TotpConfirmServlet();

    virtual int32_t handle(chen::http::HttpRequest::ptr request,
                           chen::http::HttpResponse::ptr response,
                           chen::http::HttpSession::ptr session,
                           Result::ptr result) override;
};

} // namespace auth
