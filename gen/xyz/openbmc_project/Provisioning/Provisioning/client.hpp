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

    /** @brief ProvisionPeer
     *  Starts the provisioning process on the peerBmc .
     */
    auto provision_peer()
    {
        return proxy.template call<>(context(), "ProvisionPeer");
    }

    /** @brief InitiatePeerConnectionTest
     *  starts an mTLS connection attempt to the peer BMC. This method only initiates the handshake and returns immediately; the result (success/failure) must be reflected by the daemon by updating the PeerConnected property.
     */
    auto initiate_peer_connection_test()
    {
        return proxy.template call<>(context(), "InitiatePeerConnectionTest");
    }

    /** Get value of Provisioned
     *  True means the BMC is in a provisioned state.
     */
    auto provisioned()
    {
        return proxy.template get_property<bool>(context(), "Provisioned");
    }


    /** Get value of PeerConnected
     *  True if a peer BMC is present and detected on the network. False if no peer BMC is present or not connected.
     */
    auto peer_connected()
    {
        return proxy.template get_property<bool>(context(), "PeerConnected");
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

