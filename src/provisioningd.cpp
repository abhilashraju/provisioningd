#include "bmcwatcher.hpp"
#include "provisioning_object.hpp"
#include "spdmwatcher.hpp"

#include <unistd.h>

#include <command_line_parser.hpp>
#include <nlohmann/json.hpp>
#include <tcp_client.hpp>
#include <tcp_server.hpp>

#include <fstream>
#include <iostream>
static std::string cert_root = "/tmp/1222";
using namespace reactor;
inline std::string trusStorePath()
{
    return std::format("{}etc/ssl/certs/ca.pem", cert_root);
}
inline std::string ENTITY_CLIENT_CERT_PATH()
{
    return std::format("{}etc/ssl/certs/https/client_cert.pem", cert_root);
}
inline std::string CLIENT_PKEY_PATH()
{
    return std::format("{}etc/ssl/private/client_pkey.pem", cert_root);
}
inline std::string ENTITY_SERVER_CERT_PATH()
{
    return std::format("{}etc/ssl/certs/https/server_cert.pem", cert_root);
}
inline std::string SERVER_PKEY_PATH()
{
    return std::format("{}etc/ssl/private/server_pkey.pem", cert_root);
}
net::awaitable<void> waitFor(net::io_context& io_context,
                             std::chrono::seconds duration)
{
    net::steady_timer timer(io_context, duration);
    co_await timer.async_wait(net::use_awaitable);
}
net::awaitable<void> tryConnect(net::io_context& io_context,
                                const std::string& ip, short port,
                                ProvisioningController& controller)
{
    ssl::context ssl_context(ssl::context::sslv23_client);
    ssl_context.set_options(boost::asio::ssl::context::default_workarounds |
                            boost::asio::ssl::context::no_sslv2 |
                            boost::asio::ssl::context::single_dh_use);
    ssl_context.load_verify_file(trusStorePath());
    ssl_context.set_verify_mode(boost::asio::ssl::verify_peer);
    ssl_context.use_certificate_chain_file(ENTITY_CLIENT_CERT_PATH());
    ssl_context.use_private_key_file(CLIENT_PKEY_PATH(),
                                     boost::asio::ssl::context::pem);
    TcpClient client(io_context.get_executor(), ssl_context);
    auto ec = co_await client.connect(ip, std::to_string(port));
    if (ec)
    {
        controller.setTrustedConnectionState(false);
        LOG_ERROR("Connect error: {}", ec.message());
        co_return;
    }
    std::string message("Hello");
    size_t bytes{0};
    std::tie(ec, bytes) = co_await client.write(net::buffer(message));
    if (ec)
    {
        controller.setTrustedConnectionState(false);
        LOG_ERROR("Connect error: {}", ec.message());
        co_return;
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
            else
            {
                controller.setTrustedConnectionState(false);
                LOG_ERROR("Receive error: {}", ec.message());
                co_return;
            }
            co_return;
        }
        std::string ping("ping");
        auto [ecw, bytesw] = co_await client.write(net::buffer(ping));
        if (ecw)
        {
            controller.setTrustedConnectionState(false);
            LOG_ERROR("Send error: {}", ecw.message());
            co_return;
        }
        co_await waitFor(io_context, 1s);
    }
}

net::awaitable<void> startSpdm(sdbusplus::asio::connection& conn,
                               std::shared_ptr<SpdmWatcher> watcher,
                               net::io_context& ioc, const std::string& ip,
                               short port, ProvisioningController& controller)
{
    // This method would start the SPDM provisioning process.
    // Implementation would depend on the specific requirements.
    LOG_INFO("Starting SPDM provisioning");
    auto [ec, msg] = co_await awaitable_dbus_method_call<sdbusplus::message_t>(
        conn, SPDM_SVC, SPDM_PATH, SPDM_INTF, "attest");
    if (ec)
    {
        LOG_ERROR("Failed to start spdm: {}", ec.message());
    }

    bool prop = co_await watcher->watch();
    if (prop)
    {
        LOG_INFO("SPDM provisioning completed successfully");
        co_await tryConnect(ioc, ip, port, controller);
    }
    else
    {
        LOG_ERROR("SPDM provisioning failed");
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
        ssl::context ssl_context(ssl::context::sslv23_server);
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
        // Load server certificate and private key
        ssl_context.set_options(boost::asio::ssl::context::default_workarounds |
                                boost::asio::ssl::context::no_sslv2 |
                                boost::asio::ssl::context::single_dh_use);

        ssl_context.use_certificate_chain_file(ENTITY_SERVER_CERT_PATH());
        ssl_context.use_private_key_file(SERVER_PKEY_PATH(),
                                         boost::asio::ssl::context::pem);
        ssl_context.load_verify_file(trusStorePath());
        ssl_context.set_verify_mode(boost::asio::ssl::verify_peer);
        BmcWatcher watcher(io_context, ssl_context, sport);

        watcher.onConnectionChange([&](bool connected) {
            if (connected)
            {
                LOG_INFO("BMC watcher connected");
            }
            else
            {
                LOG_ERROR("BMC watcher disconnected");
            }
        });
        auto conn = std::make_shared<sdbusplus::asio::connection>(io_context);
        ProvisioningController controller(io_context, conn);
        conn->request_name(ProvisioningController::busName);
        controller.setProvisioningStateHandler([&]() {
            LOG_INFO("Provisioning started");
            auto watcherPtr = std::make_shared<SpdmWatcher>(conn, "device1");
            net::co_spawn(io_context,
                          std::bind_front(startSpdm, std::ref(*conn),
                                          watcherPtr, std::ref(io_context), ip,
                                          rport, std::ref(controller)),
                          net::detached);
        });
        if (start)
        {
            LOG_INFO("Starting provisioning process");
            auto watcherPtr = std::make_shared<SpdmWatcher>(conn, "device1");
            // net::co_spawn(io_context,
            //               std::bind_front(startSpdm, std::ref(*conn),
            //                               watcherPtr, std::ref(io_context),
            //                               ip, rport, std::ref(controller)),
            //               net::detached);
            net::co_spawn(io_context,
                          std::bind_front(tryConnect, std::ref(io_context), ip,
                                          rport, std::ref(controller)),
                          net::detached);
        }
        io_context.run();
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Exception: {}", e.what());
        return 1;
    }
}
