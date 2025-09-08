#pragma once
#include <sdbusplus/async/client.hpp>
#include <type_traits>

#include <xyz/openbmc_project/Provisioning/Provisioning/common.hpp>

namespace sdbusplus::client::xyz::openbmc_project::provisioning
{

namespace details
{
// forward declaration
template <typename Client, typename Proxy>
class Provisioning;
} // namespace details

/** Alias class so we can use the client in both a client_t aggregation
 *  and individually.
 *
 *  sdbusplus::async::client_t<Provisioning>() or
 *  Provisioning() both construct an equivalent instance.
 */
template <typename Client = void, typename Proxy = void>
struct Provisioning :
    public std::conditional_t<std::is_void_v<Client>,
                              sdbusplus::async::client_t<details::Provisioning>,
                              details::Provisioning<Client, Proxy>>
{
    template <typename... Args>
    Provisioning(Args&&... args) :
        std::conditional_t<std::is_void_v<Client>,
                           sdbusplus::async::client_t<details::Provisioning>,
                           details::Provisioning<Client, Proxy>>(
            std::forward<Args>(args)...)
    {}
};

namespace details
{

template <typename Client, typename Proxy>
class Provisioning :
    public sdbusplus::common::xyz::openbmc_project::provisioning::Provisioning,
    private sdbusplus::async::client::details::client_context_friend
{
  public:
    friend Client;
    template <typename, typename>
    friend struct sdbusplus::client::xyz::openbmc_project::provisioning::Provisioning;

    // Delete default constructor as these should only be constructed
    // indirectly through sdbusplus::async::client_t.
    Provisioning() = delete;

    /** @brief StartProvisioning
     *  Starts the provisioning process and updates the ProvisioningState accordingly.
     */
    auto start_provisioning()
    {
        return proxy.template call<>(context(), "StartProvisioning");
    }

    /** @brief CheckPeerBMCConnection
     *  Performs a check to determine if the peer BMC is reachable and and if already provisioned.
     *
     *  @return unnamed[bool] - True if the peer BMC is reachable and provisioned. false if peer BMC is not reachable or not-provisioned.
     */
    auto check_peer_bmc_connection()
    {
        return proxy.template call<bool>(context(), "CheckPeerBMCConnection");
    }

    /** Get value of Provisioned
     *  True means the BMC is in a provisioned state.
     */
    auto provisioned()
    {
        return proxy.template get_property<bool>(context(), "Provisioned");
    }


  private:
    // Conversion constructor from proxy used by client_t.
    explicit constexpr Provisioning(Proxy p) :
        proxy(p.interface(interface))
    {}

    sdbusplus::async::context& context()
    {
        return sdbusplus::async::client::details::client_context_friend::
            context<Client, Provisioning>(this);
    }

    decltype(std::declval<Proxy>().interface(interface)) proxy = {};
};

} // namespace details

} // namespace sdbusplus::client::xyz::openbmc_project::provisioning

