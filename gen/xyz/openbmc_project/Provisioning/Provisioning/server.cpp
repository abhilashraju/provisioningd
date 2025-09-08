#include <exception>
#include <map>
#include <sdbusplus/sdbus.hpp>
#include <sdbusplus/sdbuspp_support/server.hpp>
#include <sdbusplus/server.hpp>
#include <string>
#include <tuple>

#include <xyz/openbmc_project/Provisioning/Provisioning/server.hpp>

namespace sdbusplus::server::xyz::openbmc_project::provisioning
{

int Provisioning::_callback_StartProvisioning(
        sd_bus_message* msg, void* context, sd_bus_error* error)
{
    auto o = static_cast<Provisioning*>(context);

    try
    {
        return sdbusplus::sdbuspp::method_callback(
                msg, o->get_bus().getInterface(), error,
                std::function(
                    [=]()
                    {
                        return o->startProvisioning(
                                );
                    }
                ));
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
static const auto _param_StartProvisioning =
        utility::tuple_to_array(std::make_tuple('\0'));
static const auto _return_StartProvisioning =
        utility::tuple_to_array(std::make_tuple('\0'));
}
}
int Provisioning::_callback_CheckPeerBMCConnection(
        sd_bus_message* msg, void* context, sd_bus_error* error)
{
    auto o = static_cast<Provisioning*>(context);

    try
    {
        return sdbusplus::sdbuspp::method_callback(
                msg, o->get_bus().getInterface(), error,
                std::function(
                    [=]()
                    {
                        return o->checkPeerBMCConnection(
                                );
                    }
                ));
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
static const auto _param_CheckPeerBMCConnection =
        utility::tuple_to_array(std::make_tuple('\0'));
static const auto _return_CheckPeerBMCConnection =
        utility::tuple_to_array(message::types::type_id<
                bool>());
}
}


auto Provisioning::provisioned() const ->
        bool
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
                std::function(
                    [=]()
                    {
                        return o->provisioned();
                    }
                ));
    }
    catch (const std::exception&)
    {
        o->get_bus().set_current_exception(std::current_exception());
        return 1;
    }
}

auto Provisioning::provisioned(bool value,
                                         bool skipSignal) ->
        bool
{
    if (_provisioned != value)
    {
        _provisioned = value;
        if (!skipSignal)
        {
            _xyz_openbmc_project_provisioning_Provisioning_interface.property_changed("Provisioned");
        }
    }

    return _provisioned;
}

auto Provisioning::provisioned(bool val) ->
        bool
{
    return provisioned(val, false);
}


namespace details
{
namespace Provisioning
{
static const auto _property_Provisioned =
    utility::tuple_to_array(message::types::type_id<
            bool>());
}
}


void Provisioning::setPropertyByName(const std::string& _name,
                                     const PropertiesVariant& val,
                                     bool skipSignal)
{
    if (_name == "Provisioned")
    {
        auto& v = std::get<bool>(val);
        provisioned(v, skipSignal);
        return;
    }
}

auto Provisioning::getPropertyByName(const std::string& _name) ->
        PropertiesVariant
{
    if (_name == "Provisioned")
    {
        return provisioned();
    }

    return PropertiesVariant();
}



const vtable_t Provisioning::_vtable[] = {
    vtable::start(),

    vtable::method("StartProvisioning",
                   details::Provisioning::_param_StartProvisioning.data(),
                   details::Provisioning::_return_StartProvisioning.data(),
                   _callback_StartProvisioning),

    vtable::method("CheckPeerBMCConnection",
                   details::Provisioning::_param_CheckPeerBMCConnection.data(),
                   details::Provisioning::_return_CheckPeerBMCConnection.data(),
                   _callback_CheckPeerBMCConnection),

    vtable::property("Provisioned",
                     details::Provisioning::_property_Provisioned.data(),
                     _callback_get_Provisioned,
                     vtable::property_::emits_change),

    vtable::end()
};

} // namespace sdbusplus::server::xyz::openbmc_project::provisioning

