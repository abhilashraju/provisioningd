#pragma once
#include <reactor/sdbus_calls.hpp>
using namespace reactor;
struct ProvisioningController
{
    net::io_context& ioContext;
    std::shared_ptr<sdbusplus::asio::connection> conn;
    sdbusplus::asio::object_server dbusServer;
    std::shared_ptr<sdbusplus::asio::dbus_interface> iface;
    bool trustedConnectionState{false};
    using PROVISIONING_HANDLER = std::function<void()>;
    PROVISIONING_HANDLER provisionHandler;
    using CHECK_PEER_HANDLER = std::function<void()>;
    CHECK_PEER_HANDLER checkPeerHandler;
    static constexpr auto busName = "xyz.openbmc_project.Provisioning";
    static constexpr auto objPath = "/xyz/openbmc_project/Provisioning";
    static constexpr auto interface = "xyz.openbmc_project.Provisioning.Status";

    ProvisioningController(net::io_context& ctx,
                           std::shared_ptr<sdbusplus::asio::connection> conn) :
        ioContext(ctx), conn(conn), dbusServer(conn)
    {
        iface = dbusServer.add_interface(objPath, interface);
        // test generic properties

        iface->register_method("StartProvisioning", [this]() { provision(); });
        iface->register_method("CheckPeerBMCConnection", [this]() {
            checkPeer();
        });

        iface->register_property(
            "Provisioned", false,
            std::bind_front(&ProvisioningController::setProvisioningState,
                            this),
            std::bind_front(&ProvisioningController::getProvisioningState,
                            this));
        iface->register_property(
            "PeerConnected", false,
            std::bind_front(&ProvisioningController::setProvisioningState,
                            this),
            std::bind_front(&ProvisioningController::getProvisioningState,
                            this));

        iface->initialize();
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

    bool setProvisioningState(bool newstate, bool& currentstate)
    {
        if (currentstate == newstate)
        {
            LOG_INFO("Provisioning state is already set to {}", newstate);
            return false; // No change needed
        }
        currentstate = newstate;

        return true; // Return true if successful
    }
    bool getProvisioningState(bool currentstate)
    {
        return currentstate; // Return the current state
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
    net::awaitable<void> setPeerConnected(bool connected)
    {
        co_await setProperty(*conn, busName, objPath, interface,
                             "PeerConnected", connected);
        co_await setProperty(*conn, busName, objPath, interface, "Provisioned",
                             connected);
    }
};
