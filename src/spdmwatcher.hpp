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
    auto makeWatchHandler()
    {
        return make_awaitable_handler<bool>([this](auto promise) {
            auto promise_ptr =
                std::make_shared<decltype(promise)>(std::move(promise));
            spdmWatcherHandler = [promise_ptr](bool status) {
                promise_ptr->setValues(boost::system::error_code{}, status);
            };
        });
    }
    net::awaitable<void> watch(auto callback)
    {
        if (!match)
        {
            LOG_ERROR("Match object is not initialized");
            co_await callback(std::nullopt);
            co_return;
        }
        auto h = makeWatchHandler();
        boost::system::error_code ec{};
        while (!ec)
        {
            bool res{false};
            std::tie(ec, res) = co_await h();
            co_await callback(std::optional(res));
        }
        LOG_ERROR("Error in watching SPDM property: {}", ec.message());
        co_await callback(std::nullopt);
        co_return;
    }
    net::awaitable<std::optional<bool>> watchOnce(
        std::chrono::milliseconds timeout = std::chrono::milliseconds(5000))
    {
        if (!match)
        {
            LOG_ERROR("Match object is not initialized");
            co_return std::nullopt;
        }
        auto h = makeWatchHandler();
        net::steady_timer timer(conn->get_io_context());
        startTimeout(timer, timeout);
        auto [ec, res] = co_await h();
        timer.cancel(); // Cancel the timer if we got a response
        if (ec)
        {
            LOG_ERROR("Error in watching SPDM property: {}", ec.message());
            co_return std::nullopt;
        }
        co_return std::optional(res);
    }

    static void watch(net::io_context& ctx,
                      std::shared_ptr<sdbusplus::asio::connection> conn,
                      const std::string& device, WatchHandler auto callback)
    {
        net::co_spawn(
            ctx,
            [spdmWatcher = std::make_shared<SpdmWatcher>(conn, device),
             callback = std::move(callback)]() -> net::awaitable<void> {
                co_await spdmWatcher->watch(
                    [callback = std::move(callback)](
                        std::optional<bool> val) -> net::awaitable<void> {
                        if (val)
                        {
                            co_await callback(boost::system::error_code{},
                                              *val);
                            co_return;
                        }
                        co_await callback(
                            boost::system::errc::make_error_code(
                                boost::system::errc::operation_canceled),
                            false);
                    });
            },
            net::detached);
    }
};
