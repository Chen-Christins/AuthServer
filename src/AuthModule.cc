#include "AuthModule.hpp"

#include <memory>
#include <ranges>

#include <chen/module/module.h>
#include <chen/log/log.h>
#include <chen/application.h>
#include <chen/http/http_server.h>
#include <chen/db/mysql.h>

#include "OidcConfig.hpp"
#include "auth/data/oauth_users_info.h"
#include "auth/data/oauth_clients_info.h"
#include "auth/data/oauth_recovery_codes_info.h"
#include "servlets/OidcDiscoveryServlet.hpp"
#include "servlets/JwksServlet.hpp"
#include "servlets/AuthorizationServlet.hpp"
#include "servlets/LoginServlet.hpp"
#include "servlets/TokenServlet.hpp"
#include "servlets/UserInfoServlet.hpp"
#include "servlets/TotpSetupServlet.hpp"
#include "servlets/TotpConfirmServlet.hpp"
#include "servlets/TotpDisableServlet.hpp"

namespace auth {

static chen::Logger::ptr logger = LOG_NAME("auth");

static chen::ConfigVar<std::map<std::string, std::map<std::string, std::string>>>::ptr g_mysql_dbs =
    chen::Config::Lookup("mysql.dbs", std::map<std::string, std::map<std::string, std::string>>(), "mysql dbs");

AuthModule::AuthModule() 
    : Module("AuthModule", "1.0.0", "") {
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

    if (!initMySQL()) {
        ERROR(logger) << "initDB failed";
        return false;
    }

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

bool AuthModule::onActivate() {
    INFO(logger) << "onActivate";
    return true;
}

bool AuthModule::onDeactivate() {
    INFO(logger) << "onDeactivate";
    return true;
}

void AuthModule::onTick() {
    INFO(logger) << "onTick";
}

uint64_t AuthModule::getTickIntervalMs() {
    return 0;
}

bool AuthModule::initMySQL() {
    const auto& mysql_dbs = g_mysql_dbs->getValue();
    for (const auto& params : mysql_dbs | std::views::values) {
        auto mysql = std::make_shared<chen::MySQL>(params);
        if (!mysql->connect()) {
            ERROR(logger) << "connect mysql failed";
            return false;
        }

#define XX(class_name, table_name)                             \
    if (auth::data::class_name::CreateTableMySQL(mysql)) {     \
        ERROR(logger) << "create " table_name " table failed"; \
        return false;                                          \
    }
    XX(OauthClientsInfoDao, "oauth_clients_info")
    XX(OauthUsersInfoDao, "oauth_users_info")
    XX(OauthRecoveryCodesInfoDao, "oauth_recovery_codes")
#undef XX

    // 数据库迁移：为已有表补充新增列
    {
        INFO(logger) << "migrate database begin";
#define XX(clazz) auth::data::clazz::MigrateTableMySQL(mysql);
        XX(OauthClientsInfoDao)
        XX(OauthUsersInfoDao)
        XX(OauthRecoveryCodesInfoDao)
#undef XX
        INFO(logger) << "migrate database end";
    }

    }

    return true;
}

void AuthModule::registerServlets(const std::vector<chen::TcpServer::ptr>& servers) {
    INFO(logger) << "registerServlets";

    for (auto& i : servers) {
        const auto hs = std::dynamic_pointer_cast<chen::http::HttpServer>(i);
        ASSERT_RET(hs);

        const auto dp = hs->getServletDispatch();
        ASSERT_RET(dp);

#define XX(clazz) chen::http::Servlet::ptr(new clazz)

        // OIDC 端点
        dp->addServlet("/.well-known/openid-configuration", XX(OidcDiscoveryServlet));
        dp->addServlet("/jwks.json", XX(JwksServlet));
        dp->addServlet("/authorize", XX(AuthorizationServlet));
        dp->addServlet("/login", XX(LoginServlet));
        dp->addServlet("/token", XX(TokenServlet));
        dp->addServlet("/userinfo", XX(UserInfoServlet));

        // 2FA TOTP 端点
        dp->addServlet("/totp/setup", XX(TotpSetupServlet));
        dp->addServlet("/totp/confirm", XX(TotpConfirmServlet));
        dp->addServlet("/totp/disable", XX(TotpDisableServlet));

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