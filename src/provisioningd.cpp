#include "bmcwatcher.hpp"
#include "provisioning_object.hpp"

#include <unistd.h>

#include <command_line_parser.hpp>
#include <nlohmann/json.hpp>
#include <tcp_client.hpp>
#include <tcp_server.hpp>

#include <fstream>
#include <iostream>
using namespace reactor;
inline std::string trusStorePath()
{
    return std::format("{}etc/ssl/certs/ca.pem", "/tmp/3273986/");
}
inline std::string ENTITY_CLIENT_CERT_PATH()
{
    return std::format("{}etc/ssl/certs/https/client_cert.pem",
                       "/tmp/3273986/");
}
inline std::string CLIENT_PKEY_PATH()
{
    return std::format("{}etc/ssl/private/client_pkey.pem", "/tmp/3273986/");
}
inline std::string ENTITY_SERVER_CERT_PATH()
{
    return std::format("{}etc/ssl/certs/https/server_cert.pem",
                       "/tmp/3273986/");
}
inline std::string SERVER_PKEY_PATH()
{
    return std::format("{}etc/ssl/private/server_pkey.pem", "/tmp/3273986/");
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
    }
}
static constexpr auto SPDM_SVC = "xyz.openbmc_project.spdm";
static constexpr auto SPDM_PATH = "/xyz/openbmc_project/spdm/device1";
static constexpr auto SPDM_INTF = "xyz.openbmc_project.SpdmDevice";
using PropertyWatchType = bool;
AwaitableResult<PropertyWatchType> propertyWatch(
    sdbusplus::asio::connection& conn, const std::string& path,
    const std::string& interface, const std::string& property)
{
    std::unique_ptr<sdbusplus::bus::match::match> match;
    auto h = make_awaitable_handler<PropertyWatchType>([path, interface,
                                                        property, &match,
                                                        &conn](auto promise) {
        std::string matchRule = sdbusplus::bus::match::rules::propertiesChanged(
            path.c_str(), interface.c_str());
        auto promise_ptr =
            std::make_shared<decltype(promise)>(std::move(promise));
        auto propcallback = [property,
                             promise_ptr](sdbusplus::message::message& msg) {
            std::string interfaceName;
            std::map<std::string, std::variant<PropertyWatchType>>
                changedProperties;
            std::vector<std::string> invalidatedProperties;

            msg.read(interfaceName, changedProperties, invalidatedProperties);

            LOG_INFO("Properties changed on interface: {}", interfaceName);

            changedProperties | std::ranges::views::filter([&](const auto& p) {
                return p.first == property;
            });
            if (changedProperties.empty())
            {
                LOG_ERROR("Property {} not found in changed properties",
                          property);
                promise_ptr->setValues(
                    boost::system::error_code{
                        boost::system::errc::make_error_code(
                            boost::system::errc::no_such_file_or_directory)},
                    PropertyWatchType{});
                return;
            }
            auto it = changedProperties.begin();
            if (!std::holds_alternative<PropertyWatchType>(it->second))
            {
                LOG_ERROR("Property {} is not of type string", property);
                promise_ptr->setValues(
                    boost::system::error_code{
                        boost::system::errc::make_error_code(
                            boost::system::errc::invalid_argument)},
                    PropertyWatchType{});
                return;
            }
            auto result = std::get<PropertyWatchType>(it->second);
            LOG_DEBUG("Property {} changed: {}", property, result);

            promise_ptr->setValues(boost::system::error_code{},
                                   std::move(result));
        };
        match = std::make_unique<sdbusplus::bus::match::match>(
            conn, matchRule.c_str(), std::move(propcallback));
    });
    co_return co_await h();
}
net::awaitable<void> startSpdm(
    sdbusplus::asio::connection& conn, net::io_context& io_context,
    const std::string& ip, short port, ProvisioningController& controller)
{
    // This method would start the SPDM provisioning process.
    // Implementation would depend on the specific requirements.
    LOG_INFO("Starting SPDM provisioning");
    auto [ec, msg] = co_await awaitable_dbus_method_call<sdbusplus::message_t>(
        conn, SPDM_SVC, SPDM_PATH, SPDM_INTF, "attest");
    if (ec)
    {
        LOG_ERROR("Failed to start spdm: {}", ec.message());
        co_return;
    }
    auto [ec2, property] =
        co_await propertyWatch(conn, SPDM_PATH, SPDM_INTF, "Status");

    if (ec2)
    {
        LOG_ERROR("Failed to watch property: {}", ec2.message());
        co_return;
    }
    if (property)
    {
        co_await tryConnect(io_context, ip, port, controller);
    }

    co_return;
}

int main(int argc, const char* argv[])
{
    auto [conf] = getArgs(parseCommandline(argc, argv), "--conf,-c");
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
        net::co_spawn(
            io_context,
            std::bind_front(startSpdm, std::ref(*conn), std::ref(io_context),
                            ip, rport, std::ref(controller)),
            net::detached);
    });
    io_context.run();
}
