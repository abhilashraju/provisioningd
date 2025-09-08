#pragma once

#include <reactor/sdbus_calls.hpp>

#include <chrono>
#include <string>
static constexpr auto SPDM_SVC = "xyz.openbmc_project.spdm";
static constexpr auto SPDM_PATH = "/xyz/openbmc_project/spdm/device1";
static constexpr auto SPDM_INTF = "xyz.openbmc_project.SpdmDevice";
static constexpr auto SPDM_PROP = "Status";
template <typename Handler>
concept WatchHandler =
    requires(Handler handler, const boost::system::error_code& ec,
             bool result) {
        { handler(ec, result) } -> std::same_as<boost::asio::awaitable<void>>;
    };
struct SpdmWatcher
{
    std::shared_ptr<sdbusplus::asio::connection> conn;
    std::optional<sdbusplus::bus::match::match> sigMatch;
    std::optional<sdbusplus::bus::match::match> propMatch;
    std::string id;
    using SPDM_WATCHER_HANDLER = std::function<void(bool)>;
    SPDM_WATCHER_HANDLER spdmPropWatcherHandler;
    SPDM_WATCHER_HANDLER spdmSigWatcherHandler;

    SpdmWatcher(std::shared_ptr<sdbusplus::asio::connection> conn,
                const std::string& id) : conn(conn), id(id)
    {}
    void hanleSignalChange(sdbusplus::message_t& msg)
    {
        bool value;
        msg.read(value);
        LOG_DEBUG("Recieved Signal value {}", value);
        spdmSigWatcherHandler(value);
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
            spdmPropWatcherHandler(false);
            return;
        }
        auto it = changedProperties.begin();
        if (!std::holds_alternative<bool>(it->second))
        {
            LOG_ERROR("Property {} is not of type string", SPDM_PROP);
            spdmPropWatcherHandler(false);
            return;
        }
        auto result = std::get<bool>(it->second);
        LOG_DEBUG("Property {} changed: {}", SPDM_PROP, result);

        spdmPropWatcherHandler(result);
    }
    void setSpdmPropWatcherHandler(SPDM_WATCHER_HANDLER handler)
    {
        spdmPropWatcherHandler = std::move(handler);
    }
    void setSpdmSigWatcherHandler(SPDM_WATCHER_HANDLER handler)
    {
        spdmSigWatcherHandler = std::move(handler);
    }
    void startTimeout(net::steady_timer& timer, std::chrono::seconds timeout,
                      bool prop)
    {
        timer.expires_after(timeout);
        timer.async_wait([this, prop](const boost::system::error_code& ec) {
            if (!ec)
            {
                if (prop)
                {
                    spdmPropWatcherHandler(false);
                }
                else
                {
                    spdmSigWatcherHandler(false);
                }
                LOG_ERROR(
                    "Timeout occurred while waiting for SPDM property change");
            }
        });
    }
    auto makeWatchHandler(bool prop)
    {
        return make_awaitable_handler<bool>([this, prop](auto promise) {
            auto promise_ptr =
                std::make_shared<decltype(promise)>(std::move(promise));
            if (prop)
            {
                spdmPropWatcherHandler = [promise_ptr](bool status) {
                    promise_ptr->setValues(boost::system::error_code{}, status);
                };
            }
            else
            {
                spdmSigWatcherHandler = [promise_ptr](bool status) {
                    promise_ptr->setValues(boost::system::error_code{}, status);
                };
            }
        });
    }
    template <bool prop>
    bool ensureMatchObject()
    {
        if constexpr (prop)
        {
            if (!propMatch)
            {
                std::string propMatchRule =
                    sdbusplus::bus::match::rules::propertiesChanged(SPDM_PATH,
                                                                    SPDM_INTF);
                propMatch.emplace(
                    *conn, propMatchRule,
                    std::bind_front(&SpdmWatcher::handlePropertyChange, this));
            }
        }
        else
        {
            if (!sigMatch)
            {
                std::string sigmatchRule =
                    std::format("type='signal',interface='{}',member='{}'",
                                SPDM_INTF, "Attested");

                sigMatch.emplace(
                    *conn, sigmatchRule,
                    std::bind_front(&SpdmWatcher::hanleSignalChange, this));
            }
        }
        return true;
    }
    template <bool prop>
    net::awaitable<void> watch(auto callback)
    {
        if (!ensureMatchObject<prop>())
        {
            LOG_ERROR("Match object is not initialized");
            co_await callback(std::nullopt);
        }
        boost::system::error_code ec{};
        while (!ec)
        {
            auto h = makeWatchHandler(prop);
            bool res{false};
            std::tie(ec, res) = co_await h();
            LOG_DEBUG("after  watch");
            co_await callback(std::optional(res));
        }
        LOG_ERROR("Error in watching SPDM property: {}", ec.message());
        co_await callback(std::nullopt);
        co_return;
    }
    template <bool prop>
    net::awaitable<std::optional<bool>> watchOnce(
        std::chrono::seconds timeout = 1s)
    {
        if (!ensureMatchObject<prop>())
        {
            LOG_ERROR("Match object is not initialized");
            co_return std::nullopt;
        }
        auto h = makeWatchHandler(prop);
        net::steady_timer timer(conn->get_io_context());
        startTimeout(timer, timeout, prop);
        auto [ec, res] = co_await h();
        timer.cancel(); // Cancel the timer if we got a response
        if (ec)
        {
            LOG_ERROR("Error in watching SPDM property: {}", ec.message());
            co_return std::nullopt;
        }
        co_return std::optional(res);
    }
    template <bool prop>
    static void watch(net::io_context& ctx,
                      std::shared_ptr<sdbusplus::asio::connection> conn,
                      const std::string& device, WatchHandler auto callback)
    {
        net::co_spawn(
            ctx,
            [spdmWatcher = std::make_shared<SpdmWatcher>(conn, device),
             callback = std::move(callback)]() -> net::awaitable<void> {
                co_await spdmWatcher->watch<prop>(
                    [callback = std::move(callback)](
                        std::optional<bool> val) -> net::awaitable<void> {
                        if (val)
                        {
                            LOG_DEBUG("Calling prop change with value {}",
                                      *val);
                            co_await callback(boost::system::error_code{},
                                              *val);
                            co_return;
                        }
                        LOG_DEBUG("Calling prop change with value {}", "error");
                        co_await callback(
                            boost::system::errc::make_error_code(
                                boost::system::errc::operation_canceled),
                            false);
                    });
            },
            net::detached);
    }
};
