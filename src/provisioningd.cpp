#include "bmcresponder.hpp"
#include "provisioning_object.hpp"
#include "spdmwatcher.hpp"
#include "ssl_functions.hpp"

#include <unistd.h>

#include <nlohmann/json.hpp>
#include <reactor/command_line_parser.hpp>
#include <reactor/tcp_client.hpp>
#include <reactor/tcp_server.hpp>

#include <fstream>
#include <iostream>

net::awaitable<void> waitFor(net::io_context& io_context,
                             std::chrono::seconds duration)
{
    net::steady_timer timer(io_context, duration);
    co_await timer.async_wait(net::use_awaitable);
}

net::awaitable<bool> monitorBmc(net::io_context& io_context, TcpClient& client)
{
    std::string message("Hello");
    auto [ec, bytes] = co_await client.write(net::buffer(message));
    if (ec)
    {
        LOG_ERROR("Connect error: {}", ec.message());
        co_return false;
    }
    std::array<char, 1024> data{0};
    while (true)
    {
        auto [ec, bytes] = co_await client.read(net::buffer(data));
        if (ec)
        {
            if (ec == net::error::operation_aborted)
            {
                continue;
            }
            LOG_ERROR("Receive error: {}", ec.message());
            co_return false;
        }
        std::string ping("ping");
        auto [ecw, bytesw] = co_await client.write(net::buffer(ping));
        if (ecw)
        {
            LOG_ERROR("Send error: {}", ecw.message());
            co_return false;
        }
        co_await waitFor(io_context, 1s);
    }
    co_return false;
}

net::awaitable<void> tryConnect(net::io_context& io_context,
                                const std::string& ip, short port,
                                ProvisioningController& controller)
{
    LOG_DEBUG("Trying peer connection");
    auto sslCtx = getClientContext();
    if (!sslCtx)
    {
        LOG_ERROR("ssl context is not available");
        co_await controller.setPeerConnected(false);
        co_return;
    }
    TcpClient client(io_context.get_executor(), *sslCtx);
    auto ec = co_await client.connect(ip, std::to_string(port));
    if (ec)
    {
        co_await controller.setPeerConnected(false);
        LOG_ERROR("Connect error: {} {}", ip, ec.message());
        co_return;
    }
    bool bmcNotResponding = co_await monitorBmc(io_context, client);
    co_await controller.setPeerConnected(bmcNotResponding);
}

std::shared_ptr<BmcResponder> makeBmcResponder(net::io_context& ctx,
                                               ssl::context sslCtx, short port)
{
    auto bmcResponder =
        std::make_shared<BmcResponder>(ctx, std::move(sslCtx), port);

    bmcResponder->onConnectionChange([&](bool connected) {
        if (connected)
        {
            LOG_INFO("BMC watcher connected");
        }
        else
        {
            LOG_ERROR("BMC watcher disconnected");
        }
    });
    return bmcResponder;
}
net::awaitable<void> onSpdmStateChange(
    net::io_context& io_context, const std::string& ip, short sport,
    ProvisioningController& controller,
    std::shared_ptr<BmcResponder>& bmcResponder, short rport,
    const boost::system::error_code& ec, bool val)
{
    if (ec)
    {
        co_return;
    }
    if (val)
    {
        LOG_INFO("SPDM provisioning completed successfully");
        if (bmcResponder)
        {
            bmcResponder.reset();
        }
        auto sslContext = getServerContext();
        if (sslContext)
        {
            bmcResponder =
                makeBmcResponder(io_context, std::move(*sslContext), sport);
        }

        co_await tryConnect(io_context, ip, rport, controller);
        co_return;
    }
}
net::awaitable<void> startSpdm(
    sdbusplus::asio::connection& conn, std::shared_ptr<SpdmWatcher> watcher,
    net::io_context& ioc, const std::string& ip, short port,
    ProvisioningController& controller,
    std::shared_ptr<BmcResponder>& bmcResponder, short bmcport)
{
    try
    {
        // This method would start the SPDM provisioning process.
        // Implementation would depend on the specific requirements.
        LOG_INFO("Starting SPDM provisioning");
        auto [ec, msg] =
            co_await awaitable_dbus_method_call<sdbusplus::message_t>(
                conn, SPDM_SVC, SPDM_PATH, SPDM_INTF, "attest");
        if (ec)
        {
            LOG_ERROR("Failed to start spdm: {}", ec.message());
        }
    }
    catch (std::exception& e)
    {
        LOG_ERROR("SPDM provisioning failed {}", e.what());
    }
}

int main(int argc, const char* argv[])
{
    try
    {
        auto& logger = getLogger();
        logger.setLogLevel(LogLevel::DEBUG);
        auto [conf, start] =
            getArgs(parseCommandline(argc, argv), "--conf,-c", "--start,-s");
        net::io_context io_context;

        if (!conf)
        {
            LOG_ERROR(
                "Configuration file not provided eg: provisioningd --conf /path/to/conf");
            return 1;
        }
        std::ifstream confFile(conf.value().data());
        auto confJson = nlohmann::json::parse(confFile);
        auto rport = confJson.value("rport", 8090);
        auto sport = confJson.value("port", 8091);
        auto ip = confJson.value("rip", std::string{"127.0.0.1"});
        cert_root = confJson.value("cert_root", std::string{"/tmp/1222/"});
        auto sslCtx = getServerContext();
        std::shared_ptr<BmcResponder> bmcResponder;
        if (sslCtx)
        {
            bmcResponder =
                makeBmcResponder(io_context, std::move(*sslCtx), sport);
        }

        auto conn = std::make_shared<sdbusplus::asio::connection>(io_context);
        ProvisioningController controller(io_context, conn);
        conn->request_name(ProvisioningController::busName);
        controller.setProvisionHandler([&]() {
            LOG_INFO("Provisioning started");
            auto watcherPtr = std::make_shared<SpdmWatcher>(conn, "device1");
            net::co_spawn(io_context,
                          std::bind_front(startSpdm, std::ref(*conn),
                                          watcherPtr, std::ref(io_context), ip,
                                          rport, std::ref(controller),
                                          std::ref(bmcResponder), sport),
                          net::detached);
        });
        controller.setChekpeerHandler([&]() {
            LOG_INFO("Checking peer BMC connection");
            net::co_spawn(io_context,
                          std::bind_front(tryConnect, std::ref(io_context), ip,
                                          rport, std::ref(controller)),
                          net::detached);
        });
        if (!bmcResponder)
        {
            LOG_INFO("Starting provisioning process");
            auto watcherPtr = std::make_shared<SpdmWatcher>(conn, "device1");
            net::co_spawn(io_context,
                          std::bind_front(tryConnect, std::ref(io_context), ip,
                                          rport, std::ref(controller)),
                          net::detached);
        }
        SpdmWatcher::watch(
            io_context, conn, "device1",
            std::bind_front(onSpdmStateChange, std::ref(io_context), ip, sport,
                            std::ref(controller), std::ref(bmcResponder),
                            rport));
        // controller.provision();
        io_context.run();
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Exception: {}", e.what());
        return 1;
    }
}
