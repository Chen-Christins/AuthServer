/**
 * @file AuthModule.hpp
 * @brief 认证服务模块
 * @author Christins (chen.christins@qq.com)
 * @date 2026-05-30
 * @copyright Apache 2.0
 */
#pragma once

#include <chen/module/module.h>
#include <chen/tcp/tcp_server.h>

namespace auth {

class AuthModule : public chen::Module {
public:
    /**
     * @brief 构造函数
     */
    AuthModule();

    /**
     * @brief 模块初始化前调用
     * @param argc 命令行参数数量
     * @param argv 命令行参数数组
     */
    void onBeforeArgsParse(int argc, char** argv) override;

    /**
     * @brief 模块初始化后调用
     * @param argc 命令行参数数量
     * @param argv 命令行参数数组
     */
    void onAfterArgsParse(int argc, char** argv) override;

    /**
     * @brief 模块加载时调用
     * @return bool 是否成功
     */
    bool onLoad() override;

    /**
     * @brief 模块卸载时调用
     * @return bool 是否成功
     */
    bool onUnload() override;

    /**
     * @brief 服务器准备就绪时调用
     * @return bool 是否成功
     */
    bool onServerReady() override;

    /**
     * @brief 服务器启动完成时调用
     * @return bool 是否成功
     */
    bool onServerUp() override;

    /**
     * @brief 热重载排空阶段（蓝绿部署）：关闭 WS 连接、停止定时器
     * @return bool
     */
    bool onDrain() override;

    /**
     * @brief 热重载排空完成（蓝绿部署）：释放非 dispatch 资源
     * @return bool
     */
    bool onGracefulUnload() override;

    /**
     * @brief 模块每个 Tick 调用一次
     */
    void onTick() override;

    /**
     * @brief 获取 Tick 间隔时间（毫秒）默认 0 表示不使用 Tick
     * @return uint64_t
     */
    uint64_t getTickIntervalMs() override;

private:
    /**
     * @brief 注册Servlets
     */
    void registerServlets(std::vector<chen::TcpServer::ptr>& servers);
};

} // namespace auth