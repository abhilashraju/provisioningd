#include <sdbusplus/sdbus.hpp>
#include <sdbusplus/sdbuspp_support/server.hpp>
#include <sdbusplus/server.hpp>
#include <xyz/openbmc_project/Provisioning/Provisioning/server.hpp>

#include <exception>
#include <map>
#include <string>
#include <tuple>

namespace sdbusplus::server::xyz::openbmc_project::provisioning
{

int Provisioning::_callback_ProvisionPeer(sd_bus_message* msg, void* context,
                                          sd_bus_error* error)
{
    auto o = static_cast<Provisioning*>(context);

    try
    {
        return sdbusplus::sdbuspp::method_callback(
            msg, o->get_bus().getInterface(), error,
            std::function([=]() { return o->provisionPeer(); }));
    }
    catch (const std::exception&)
    {
        o->get_bus().set_current_exception(std::current_exception());
        return 1;
    }
}

namespace details
{
namespace Provisioning
{
static const auto _param_ProvisionPeer =
    utility::tuple_to_array(std::make_tuple('\0'));
static const auto _return_ProvisionPeer =
    utility::tuple_to_array(std::make_tuple('\0'));
} // namespace Provisioning
} // namespace details
int Provisioning::_callback_InitiatePeerConnectionTest(
    sd_bus_message* msg, void* context, sd_bus_error* error)
{
    auto o = static_cast<Provisioning*>(context);

    try
    {
        return sdbusplus::sdbuspp::method_callback(
            msg, o->get_bus().getInterface(), error,
            std::function([=]() { return o->initiatePeerConnectionTest(); }));
    }
    catch (const std::exception&)
    {
        o->get_bus().set_current_exception(std::current_exception());
        return 1;
    }
}

namespace details
{
namespace Provisioning
{
static const auto _param_InitiatePeerConnectionTest =
    utility::tuple_to_array(std::make_tuple('\0'));
static const auto _return_InitiatePeerConnectionTest =
    utility::tuple_to_array(std::make_tuple('\0'));
} // namespace Provisioning
} // namespace details

void Provisioning::peerProvisioned(bool value)
{
    auto& i = _xyz_openbmc_project_provisioning_Provisioning_interface;
    auto m = i.new_signal("PeerProvisioned");

    m.append(value);
    m.signal_send();
}

namespace details
{
namespace Provisioning
{
static const auto _signal_PeerProvisioned =
    utility::tuple_to_array(std::make_tuple('\0'));
}
} // namespace details

auto Provisioning::provisioned() const -> bool
{
    return _provisioned;
}

int Provisioning::_callback_get_Provisioned(
    sd_bus* /*bus*/, const char* /*path*/, const char* /*interface*/,
    const char* /*property*/, sd_bus_message* reply, void* context,
    sd_bus_error* error)
{
    auto o = static_cast<Provisioning*>(context);

    try
    {
        return sdbusplus::sdbuspp::property_callback(
            reply, o->get_bus().getInterface(), error,
            std::function([=]() { return o->provisioned(); }));
    }
    catch (const std::exception&)
    {
        o->get_bus().set_current_exception(std::current_exception());
        return 1;
    }
}

auto Provisioning::provisioned(bool value, bool skipSignal) -> bool
{
    if (_provisioned != value)
    {
        _provisioned = value;
        if (!skipSignal)
        {
            _xyz_openbmc_project_provisioning_Provisioning_interface
                .property_changed("Provisioned");
        }
    }

    return _provisioned;
}

auto Provisioning::provisioned(bool val) -> bool
{
    return provisioned(val, false);
}

namespace details
{
namespace Provisioning
{
static const auto _property_Provisioned =
    utility::tuple_to_array(message::types::type_id<bool>());
}
} // namespace details

auto Provisioning::peerConnected() const -> bool
{
    return _peerConnected;
}

int Provisioning::_callback_get_PeerConnected(
    sd_bus* /*bus*/, const char* /*path*/, const char* /*interface*/,
    const char* /*property*/, sd_bus_message* reply, void* context,
    sd_bus_error* error)
{
    auto o = static_cast<Provisioning*>(context);

    try
    {
        return sdbusplus::sdbuspp::property_callback(
            reply, o->get_bus().getInterface(), error,
            std::function([=]() { return o->peerConnected(); }));
    }
    catch (const std::exception&)
    {
        o->get_bus().set_current_exception(std::current_exception());
        return 1;
    }
}

auto Provisioning::peerConnected(bool value, bool skipSignal) -> bool
{
    if (_peerConnected != value)
    {
        _peerConnected = value;
        if (!skipSignal)
        {
            _xyz_openbmc_project_provisioning_Provisioning_interface
                .property_changed("PeerConnected");
        }
    }

    return _peerConnected;
}

auto Provisioning::peerConnected(bool val) -> bool
{
    return peerConnected(val, false);
}

namespace details
{
namespace Provisioning
{
static const auto _property_PeerConnected =
    utility::tuple_to_array(message::types::type_id<bool>());
}
} // namespace details

void Provisioning::setPropertyByName(
    const std::string& _name, const PropertiesVariant& val, bool skipSignal)
{
    if (_name == "Provisioned")
    {
        auto& v = std::get<bool>(val);
        provisioned(v, skipSignal);
        return;
    }
    if (_name == "PeerConnected")
    {
        auto& v = std::get<bool>(val);
        peerConnected(v, skipSignal);
        return;
    }
}

auto Provisioning::getPropertyByName(const std::string& _name)
    -> PropertiesVariant
{
    if (_name == "Provisioned")
    {
        return provisioned();
    }
    if (_name == "PeerConnected")
    {
        return peerConnected();
    }

    return PropertiesVariant();
}

const vtable_t Provisioning::_vtable[] = {
    vtable::start(),

    vtable::method("ProvisionPeer",
                   details::Provisioning::_param_ProvisionPeer.data(),
                   details::Provisioning::_return_ProvisionPeer.data(),
                   _callback_ProvisionPeer),

    vtable::method(
        "InitiatePeerConnectionTest",
        details::Provisioning::_param_InitiatePeerConnectionTest.data(),
        details::Provisioning::_return_InitiatePeerConnectionTest.data(),
        _callback_InitiatePeerConnectionTest),

    vtable::signal("PeerProvisioned",
                   details::Provisioning::_signal_PeerProvisioned.data()),

    vtable::property(
        "Provisioned", details::Provisioning::_property_Provisioned.data(),
        _callback_get_Provisioned, vtable::property_::emits_change),

    vtable::property(
        "PeerConnected", details::Provisioning::_property_PeerConnected.data(),
        _callback_get_PeerConnected, vtable::property_::emits_change),

    vtable::end()};

} // namespace sdbusplus::server::xyz::openbmc_project::provisioning
