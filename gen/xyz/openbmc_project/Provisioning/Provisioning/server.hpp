#pragma once
#include <systemd/sd-bus.h>

#include <sdbusplus/sdbus.hpp>
#include <sdbusplus/server.hpp>
#include <xyz/openbmc_project/Provisioning/Provisioning/common.hpp>

#include <limits>
#include <map>
#include <string>

namespace sdbusplus::server::xyz::openbmc_project::provisioning
{

class Provisioning :
    public sdbusplus::common::xyz::openbmc_project::provisioning::Provisioning
{
  public:
    /* Define all of the basic class operations:
     *     Not allowed:
     *         - Default constructor to avoid nullptrs.
     *         - Copy operations due to internal unique_ptr.
     *         - Move operations due to 'this' being registered as the
     *           'context' with sdbus.
     *     Allowed:
     *         - Destructor.
     */
    Provisioning() = delete;
    Provisioning(const Provisioning&) = delete;
    Provisioning& operator=(const Provisioning&) = delete;
    Provisioning(Provisioning&&) = delete;
    Provisioning& operator=(Provisioning&&) = delete;
    virtual ~Provisioning() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Path to attach at.
     */
    Provisioning(bus_t& bus, const char* path) :
        _xyz_openbmc_project_provisioning_Provisioning_interface(
            bus, path, interface, _vtable, this),
        _sdbusplus_bus(bus)
    {}

    /** @brief Constructor to initialize the object from a map of
     *         properties.
     *
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Path to attach at.
     *  @param[in] vals - Map of property name to value for initialization.
     */
    Provisioning(bus_t& bus, const char* path,
                 const std::map<std::string, PropertiesVariant>& vals,
                 bool skipSignal = false) : Provisioning(bus, path)
    {
        for (const auto& v : vals)
        {
            setPropertyByName(v.first, v.second, skipSignal);
        }
    }

    /** @brief Implementation for ProvisionPeer
     *  Starts the provisioning process on the peerBmc .
     */
    virtual void provisionPeer() = 0;
    /** @brief Implementation for InitiatePeerConnectionTest
     *  starts an mTLS connection attempt to the peer BMC. This method only
     * initiates the handshake and returns immediately; the result
     * (success/failure) must be reflected by the daemon by updating the
     * PeerConnected property.
     */
    virtual void initiatePeerConnectionTest() = 0;

    /** @brief Send signal 'PeerProvisioned'
     *
     *  Emitted when the ProvisionPeer method completes. The signal carries a
     * boolean indicating whether provisioning on the peer succeeded or failed.
     */
    void peerProvisioned(bool);
    /** Get value of Provisioned */
    virtual bool provisioned() const;
    /** Set value of Provisioned with option to skip sending signal */
    virtual bool provisioned(bool value, bool skipSignal);
    /** Set value of Provisioned */
    virtual bool provisioned(bool value);
    /** Get value of PeerConnected */
    virtual bool peerConnected() const;
    /** Set value of PeerConnected with option to skip sending signal */
    virtual bool peerConnected(bool value, bool skipSignal);
    /** Set value of PeerConnected */
    virtual bool peerConnected(bool value);

    /** @brief Sets a property by name.
     *  @param[in] _name - A string representation of the property name.
     *  @param[in] val - A variant containing the value to set.
     */
    void setPropertyByName(const std::string& _name,
                           const PropertiesVariant& val,
                           bool skipSignal = false);

    /** @brief Gets a property by name.
     *  @param[in] _name - A string representation of the property name.
     *  @return - A variant containing the value of the property.
     */
    PropertiesVariant getPropertyByName(const std::string& _name);

    /** @brief Emit interface added */
    void emit_added()
    {
        _xyz_openbmc_project_provisioning_Provisioning_interface.emit_added();
    }

    /** @brief Emit interface removed */
    void emit_removed()
    {
        _xyz_openbmc_project_provisioning_Provisioning_interface.emit_removed();
    }

    /** @return the bus instance */
    bus_t& get_bus()
    {
        return _sdbusplus_bus;
    }

  private:
    /** @brief sd-bus callback for ProvisionPeer
     */
    static int _callback_ProvisionPeer(sd_bus_message*, void*, sd_bus_error*);
    /** @brief sd-bus callback for InitiatePeerConnectionTest
     */
    static int _callback_InitiatePeerConnectionTest(sd_bus_message*, void*,
                                                    sd_bus_error*);

    /** @brief sd-bus callback for get-property 'Provisioned' */
    static int _callback_get_Provisioned(sd_bus*, const char*, const char*,
                                         const char*, sd_bus_message*, void*,
                                         sd_bus_error*);

    /** @brief sd-bus callback for get-property 'PeerConnected' */
    static int _callback_get_PeerConnected(sd_bus*, const char*, const char*,
                                           const char*, sd_bus_message*, void*,
                                           sd_bus_error*);

    static const vtable_t _vtable[];
    sdbusplus::server::interface_t
        _xyz_openbmc_project_provisioning_Provisioning_interface;
    bus_t& _sdbusplus_bus;

    bool _provisioned = false;
    bool _peerConnected = false;
};

} // namespace sdbusplus::server::xyz::openbmc_project::provisioning

#ifndef SDBUSPP_REMOVE_DEPRECATED_NAMESPACE
namespace sdbusplus::xyz::openbmc_project::Provisioning::server
{

using sdbusplus::server::xyz::openbmc_project::provisioning::Provisioning;

} // namespace sdbusplus::xyz::openbmc_project::Provisioning::server
#endif
