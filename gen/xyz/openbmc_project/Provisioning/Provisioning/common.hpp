#pragma once
#include <algorithm>
#include <array>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>

#include <sdbusplus/exception.hpp>
#include <sdbusplus/message.hpp>
#include <sdbusplus/utility/dedup_variant.hpp>

namespace sdbusplus::common::xyz::openbmc_project::provisioning
{

struct Provisioning
{
    static constexpr auto interface = "xyz.openbmc_project.Provisioning.Provisioning";


    struct properties_t
    {
        bool provisioned = false;
    };

    using PropertiesVariant = sdbusplus::utility::dedup_variant_t<
        bool>;


};



} // sdbusplus::common::xyz::openbmc_project::provisioning

namespace sdbusplus::message::details
{
} // namespace sdbusplus::message::details

