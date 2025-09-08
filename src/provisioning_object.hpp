#pragma once
#include "xyz/openbmc_project/Provisioning/Provisioning/server.hpp"

#include <reactor/sdbus_calls.hpp>
using namespace reactor;

using namespace sdbusplus::server::xyz::openbmc_project::provisioning;
using ProvisioningIface =
    sdbusplus::server::xyz::openbmc_project::provisioning::Provisioning;
using Ifaces = sdbusplus::server::object_t<ProvisioningIface>;
struct ProvisioningController : Ifaces
{
    net::io_context& ioContext;
    std::shared_ptr<sdbusplus::asio::connection> conn;
    // sdbusplus::asio::object_server dbusServer;
    // std::shared_ptr<sdbusplus::asio::dbus_interface> iface;
    bool trustedConnectionState{false};
    bool provState{false};
    using PROVISIONING_HANDLER = std::function<void()>;
    PROVISIONING_HANDLER provisionHandler;
    using CHECK_PEER_HANDLER = std::function<void()>;
    CHECK_PEER_HANDLER checkPeerHandler;
    static constexpr auto busName = "xyz.openbmc_project.Provisioning";
    static constexpr auto objPath = "/xyz/openbmc_project/Provisioning";
    static constexpr auto interface = Provisioning::interface;

    ProvisioningController() = delete;
    ~ProvisioningController() = default;
    ProvisioningController(const ProvisioningController&) = delete;
    ProvisioningController& operator=(const ProvisioningController&) = delete;
    ProvisioningController(ProvisioningController&&) = delete;
    ProvisioningController& operator=(ProvisioningController&&) = delete;
    ProvisioningController(net::io_context& ctx,
                           std::shared_ptr<sdbusplus::asio::connection> conn) :
        Ifaces(*conn, "/xyz/openbmc_project/Provisioning",
               Ifaces::action::defer_emit),
        ioContext(ctx), conn(conn)

    {}
    void startProvisioning() override
    {
        provision();
    }
    bool checkPeerBMCConnection() override
    {
        checkPeerHandler();
        return true;
    }

    void setProvisionHandler(PROVISIONING_HANDLER handler)
    {
        provisionHandler = std::move(handler);
    }
    void setChekpeerHandler(CHECK_PEER_HANDLER handler)
    {
        checkPeerHandler = std::move(handler);
    }
    void provision()
    {
        clearProvisionData();
        provisionHandler();
    }
    void checkPeer()
    {
        checkPeerHandler();
    }

    void clearProvisionData()
    {
        // clearCertificates();
        // This method would clear the provisioning data.
        // Implementation would depend on the specific requirements.
        LOG_INFO("Clearing provisioning data");
    }

    bool setPeerConnectionState(bool newstate, bool& currentstate)
    {
        if (trustedConnectionState == newstate)
        {
            LOG_INFO("Peer connection state is already set to {}",
                     trustedConnectionState);
            return false; // No change needed
        }
        trustedConnectionState = newstate;

        return true; // Return true if successful
    }
    bool getPeerConnectionState(bool currentstate)
    {
        return trustedConnectionState; // Return the current state
    }
    bool provisioned() const override
    {
        LOG_DEBUG("Provisioned state {}", provState);
        return provState;
    }
    net::awaitable<void> setPeerConnected(bool connected)
    {
        co_await setProperty(*conn, busName, objPath, interface,
                             "PeerConnected", connected);
    }
    void setProvisioned(bool value)
    {
        LOG_DEBUG("Setting Provisioned state {}", value);
        provState = value;
    }
};
