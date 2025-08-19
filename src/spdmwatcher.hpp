#pragma once
#include <sdbus_calls.hpp>

#include <chrono>
#include <string>
static constexpr auto SPDM_SVC = "xyz.openbmc_project.spdm";
static constexpr auto SPDM_PATH = "/xyz/openbmc_project/spdm/device1";
static constexpr auto SPDM_INTF = "xyz.openbmc_project.SpdmDevice";
static constexpr auto SPDM_PROP = "Status";
struct SpdmWatcher
{
    std::shared_ptr<sdbusplus::asio::connection> conn;
    std::optional<sdbusplus::bus::match::match> match;
    std::string id;
    using SPDM_WATCHER_HANDLER = std::function<void(bool)>;
    SPDM_WATCHER_HANDLER spdmWatcherHandler;

    SpdmWatcher(std::shared_ptr<sdbusplus::asio::connection> conn,
                const std::string& id) : conn(conn), id(id)
    {
        std::string matchRule = sdbusplus::bus::match::rules::propertiesChanged(
            SPDM_PATH, SPDM_INTF);
        match.emplace(
            *conn, matchRule,
            std::bind_front(&SpdmWatcher::handlePropertyChange, this));
    }
    void handlePropertyChange(sdbusplus::message_t& msg)
    {
        std::string interfaceName;
        std::map<std::string, std::variant<bool>> changedProperties;
        std::vector<std::string> invalidatedProperties;

        msg.read(interfaceName, changedProperties, invalidatedProperties);

        LOG_INFO("Properties changed on interface: {}", interfaceName);

        changedProperties | std::ranges::views::filter([&](const auto& p) {
            return p.first == SPDM_PROP;
        });
        if (changedProperties.empty())
        {
            LOG_ERROR("Property {} not found in changed properties", SPDM_PROP);
            spdmWatcherHandler(false);
            return;
        }
        auto it = changedProperties.begin();
        if (!std::holds_alternative<bool>(it->second))
        {
            LOG_ERROR("Property {} is not of type string", SPDM_PROP);
            spdmWatcherHandler(false);
            return;
        }
        auto result = std::get<bool>(it->second);
        LOG_DEBUG("Property {} changed: {}", SPDM_PROP, result);

        spdmWatcherHandler(result);
    }
    void setSpdmWatcherHandler(SPDM_WATCHER_HANDLER handler)
    {
        spdmWatcherHandler = std::move(handler);
    }
    void startTimeout(net::steady_timer& timer,
                      std::chrono::milliseconds timeout)
    {
        timer.expires_after(timeout);
        timer.async_wait([this](const boost::system::error_code& ec) {
            if (!ec)
            {
                spdmWatcherHandler(false); // Timeout occurred
                LOG_ERROR(
                    "Timeout occurred while waiting for SPDM property change");
            }
        });
    }
    net::awaitable<bool> watch(
        std::chrono::milliseconds timeout = std::chrono::milliseconds(5000))
    {
        if (!match)
        {
            LOG_ERROR("Match object is not initialized");
            co_return false;
        }
        bool result = false;
        auto h = make_awaitable_handler<bool>([this, &result](auto promise) {
            auto promise_ptr =
                std::make_shared<decltype(promise)>(std::move(promise));
            spdmWatcherHandler = [promise_ptr, &result](bool status) {
                result = status;
                promise_ptr->setValues(boost::system::error_code{}, result);
            };
        });
        net::steady_timer timer(conn->get_io_context());
        startTimeout(timer, timeout);
        auto [ec, res] = co_await h();
        timer.cancel(); // Cancel the timer if we got a response
        if (ec)
        {
            LOG_ERROR("Error in watching SPDM property: {}", ec.message());
            co_return false;
        }
        co_return res;
    }
};

using PropertyWatchType = bool;
inline AwaitableResult<PropertyWatchType,
                       std::shared_ptr<sdbusplus::bus::match::match>>
    propertyWatch(sdbusplus::asio::connection& conn, const std::string& path,
                  const std::string& interface, const std::string& property)
{
    std::shared_ptr<sdbusplus::bus::match::match> match;
    std::string matchRule =
        sdbusplus::bus::match::rules::propertiesChanged(path, interface);
    auto h = make_awaitable_handler<PropertyWatchType>([matchRule, property,
                                                        &match,
                                                        &conn](auto promise) {
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
        match = std::make_shared<sdbusplus::bus::match::match>(
            conn, matchRule, std::move(propcallback));
    });
    auto [ec, prop] = co_await h();
    co_return std::make_tuple(
        ec, prop,
        std::move(match)); // Return the property value and match object
}
