#pragma once
#include <sdbus_calls.hpp>
using namespace reactor;
struct ProvisioningController
{
    net::io_context& ioContext;
    std::shared_ptr<sdbusplus::asio::connection> conn;
    sdbusplus::asio::object_server dbusServer;
    std::shared_ptr<sdbusplus::asio::dbus_interface> iface;
    bool trustedConnectionState{false};
    using PROVISIONING_HANDLER = std::function<void()>;
    PROVISIONING_HANDLER provisioningHandler;
    static constexpr auto busName = "xyz.openbmc_project.Provisioning";
    static constexpr auto objPath = "/xyz/openbmc_project/Provisioning";
    static constexpr auto interface = "xyz.openbmc_project.Provisioning.Status";

    ProvisioningController(net::io_context& ctx,
                           std::shared_ptr<sdbusplus::asio::connection> conn) :
        ioContext(ctx), conn(conn), dbusServer(conn)
    {
        iface = dbusServer.add_interface(objPath, interface);
        // test generic properties

        iface->register_method("ClearProvisioningData", [this]() {
            clearProvisioningData();
        });
        iface->register_method("provision", [this]() { provision(); });

        iface->register_property(
            "ProvisioningState", false,
            std::bind_front(&ProvisioningController::setProvisioningState,
                            this),
            std::bind_front(&ProvisioningController::getProvisioningState,
                            this));

        iface->initialize();
    }
    void setProvisioningStateHandler(PROVISIONING_HANDLER handler)
    {
        provisioningHandler = std::move(handler);
    }
    void provision()
    {
        clearProvisioningData();
        provisioningHandler();
    }

    void clearProvisioningData()
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
        // This method would get the current provisioning state.
        // Implementation would depend on the specific requirements.
        LOG_INFO("Getting provisioning state: {}", currentstate);
        return currentstate; // Return the current state
    }
    void setTrustedConnectionState(bool state)
    {
        trustedConnectionState = state;
        LOG_INFO("Setting peer state to {}", state);
    }
};
