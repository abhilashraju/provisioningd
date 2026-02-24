#pragma once
#include "sdbus_calls.hpp"

#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/Provisioning/Provisioning/server.hpp>
using namespace reactor;

using namespace sdbusplus::server::xyz::openbmc_project::provisioning;
using ProvisioningIface =
    sdbusplus::server::xyz::openbmc_project::provisioning::Provisioning;
using Ifaces = sdbusplus::server::object_t<ProvisioningIface>;
using InsufficientPermission =
    sdbusplus::xyz::openbmc_project::Common::Error::InsufficientPermission;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using InvalidArgument =
    sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;

using UnsupportedRequest =
    sdbusplus::xyz::openbmc_project::Common::Error::UnsupportedRequest;
using NotAllowed = sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;

struct ProvisioningController : Ifaces
{
    net::io_context& ioContext;
    std::shared_ptr<sdbusplus::asio::connection> conn;
    enum class ConnectionDirection
    {
        incoming=0,
        outgoing
    };
   
    std::array<PeerConnectionStatus,2> trustedConnectionState{
        PeerConnectionStatus::NotDetermined,PeerConnectionStatus::NotDetermined};
    bool provState{false};
    using PROVISIONING_HANDLER = std::function<void(const std::string&)>;
    PROVISIONING_HANDLER provisionHandler;

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
    void provisionPeer(std::string deviceId) override
    {
        if (deviceId == "self")
        {
            setProvisioned(true);
            return;
        }
        if (!provisioned())
        {
            LOG_ERROR("This BMC is not provisioned");
            throw NotAllowed();
        }
        provisionHandler(deviceId);
    }
    void setProvisionHandler(PROVISIONING_HANDLER handler)
    {
        provisionHandler = std::move(handler);
    }
    PeerConnectionStatus peerConnected() const override
    {
        auto state=getHighestTrustedConnectionState();
        LOG_DEBUG("PeerConnected state {}",
                  convertPeerConnectionStatusToString(state));
        return state;
    }
    bool provisioned() const override
    {
        LOG_DEBUG("Provisioned state {}", provState);
        return provState;
    }
    void setPeerConnected(PeerConnectionStatus value,ConnectionDirection dir)
    {
        LOG_DEBUG("Setting PeerConnected state {}",
                  convertPeerConnectionStatusToString(value));
        trustedConnectionState[static_cast<size_t>(dir)] = value;
        Ifaces::peerConnected(getHighestTrustedConnectionState(), false);
    }
    void setProvisioned(bool value)
    {
        LOG_DEBUG("Setting Provisioned state {}", value);
        provState = value;
        Ifaces::provisioned(value, false);
    }

  private:
    /**
     * @brief Determines the highest value in trustedConnectionState entries
     * @return The highest PeerConnectionStatus value from the array
     */
    PeerConnectionStatus getHighestTrustedConnectionState() const
    {
        auto incomingState = trustedConnectionState[static_cast<size_t>(ConnectionDirection::incoming)];
        auto outgoingState = trustedConnectionState[static_cast<size_t>(ConnectionDirection::outgoing)];
        
        LOG_DEBUG("Incoming connection state: {}",
                  convertPeerConnectionStatusToString(incomingState));
        LOG_DEBUG("Outgoing connection state: {}",
                  convertPeerConnectionStatusToString(outgoingState));
        
        auto highestState = std::max(incomingState, outgoingState);
        LOG_DEBUG("Highest connection state: {}",
                  convertPeerConnectionStatusToString(highestState));
        
        return highestState;
    }
};
