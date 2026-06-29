#include "AuthModule.hpp"

#include <chen/log/log.h>
#include <chen/application.h>
#include <chen/http/http_server.h>

#include "OidcConfig.hpp"
#include "servlets/OidcDiscoveryServlet.hpp"
#include "servlets/JwksServlet.hpp"
#include "servlets/AuthorizationServlet.hpp"
#include "servlets/LoginServlet.hpp"
#include "servlets/TokenServlet.hpp"
#include "servlets/UserInfoServlet.hpp"

namespace auth {

static chen::Logger::ptr logger = LOG_NAME("auth");

AuthModule::AuthModule() 
    : chen::Module("AuthModule", "1.0.0", "") {
}

void AuthModule::onBeforeArgsParse(int argc, char** argv) {
    INFO(logger) << "onBeforeArgsParse";
}

void AuthModule::onAfterArgsParse(int argc, char** argv) {
    INFO(logger) << "onAfterArgsParse";
}

bool AuthModule::onLoad() {
    INFO(logger) << "onLoad";
    return true;
}

bool AuthModule::onUnload() {
    INFO(logger) << "onUnload";
    return true;
}

bool AuthModule::onServerReady() {
    INFO(logger) << "onServerReady";

    // 初始化 OIDC 配置（加载密钥和配置项）
    OidcConfig::init();

    std::vector<chen::TcpServer::ptr> servers;
    if (chen::Application::GetInstance()->getServer("http", servers)) {
        registerServlets(servers);
    } else {
        ERROR(logger) << "http_server not open";
        return false;
    }

    return true;
}

bool AuthModule::onServerUp() {
    INFO(logger) << "onServerUp";
    return true;
}

bool AuthModule::onDrain() {
    INFO(logger) << "onDrain";
    return true;
}

bool AuthModule::onGracefulUnload() {
    INFO(logger) << "onGracefulUnload";
    return true;
}

void AuthModule::onTick() {
    INFO(logger) << "onTick";
}

uint64_t AuthModule::getTickIntervalMs() {
    return 0;
}

void AuthModule::registerServlets(std::vector<chen::TcpServer::ptr>& servers) {
    INFO(logger) << "registerServlets";

    for (auto& i : servers) {
        auto hs = std::dynamic_pointer_cast<chen::http::HttpServer>(i);
        auto dp = hs->getServletDispatch();

#define XX(clazz) chen::http::Servlet::ptr(new clazz)

        // OIDC 端点
        dp->addServlet("/.well-known/openid-configuration",
                       XX(OidcDiscoveryServlet));
        dp->addServlet("/jwks.json", XX(JwksServlet));
        dp->addServlet("/authorize", XX(AuthorizationServlet));
        dp->addServlet("/login", XX(LoginServlet));
        dp->addServlet("/token", XX(TokenServlet));
        dp->addServlet("/userinfo", XX(UserInfoServlet));

        INFO(logger) << "OIDC endpoints registered";

#undef XX
    }
}

} // namespace auth

extern "C" {

chen::Module* CreateModule() {
    chen::Module* module = new auth::AuthModule;
    return module;
}

void DestroyModule(chen::Module* module) {
    delete module;
}
}