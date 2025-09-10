#pragma once
#include <sdbusplus/async/server.hpp>
#include <sdbusplus/server/interface.hpp>
#include <sdbusplus/server/transaction.hpp>

#include <type_traits>

#include <xyz/openbmc_project/Provisioning/Provisioning/common.hpp>

namespace sdbusplus::aserver::xyz::openbmc_project::provisioning
{

namespace details
{
// forward declaration
template <typename Instance, typename Server>
class Provisioning;
} // namespace details

template <typename Instance, typename Server = void>
struct Provisioning :
    public std::conditional_t<
        std::is_void_v<Server>,
        sdbusplus::async::server_t<Instance, details::Provisioning>,
        details::Provisioning<Instance, Server>>
{
    template <typename... Args>
    Provisioning(Args&&... args) :
        std::conditional_t<
            std::is_void_v<Server>,
            sdbusplus::async::server_t<Instance, details::Provisioning>,
            details::Provisioning<Instance, Server>>(std::forward<Args>(args)...)
    {}
};

namespace details
{

namespace server_details = sdbusplus::async::server::details;

template <typename Instance, typename Server>
class Provisioning :
    public sdbusplus::common::xyz::openbmc_project::provisioning::Provisioning,
    protected server_details::server_context_friend
{
  public:
    explicit Provisioning(const char* path) :
        _xyz_openbmc_project_provisioning_Provisioning_interface(
            _context(), path, interface, _vtable, this)
    {}

    Provisioning(
            const char* path,
            [[maybe_unused]] Provisioning::properties_t props)
        : Provisioning(path)
    {
        provisioned_ = props.provisioned;
        peer_connected_ = props.peer_connected;
    }

    /** @brief Send signal 'PeerProvisioned'
     *
     *  Emitted when the ProvisionPeer method completes. The signal carries a boolean indicating whether provisioning on the peer succeeded or failed.
     *
     */
    void peerProvisioned()
    {
        auto m = _xyz_openbmc_project_provisioning_Provisioning_interface
                     .new_signal("PeerProvisioned");

        m.append();
        m.signal_send();
    }


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

    /* Property access tags. */
    struct provisioned_t
    {
        using value_type = bool;
        provisioned_t() = default;
        explicit provisioned_t(value_type) {}
    };
    struct peer_connected_t
    {
        using value_type = bool;
        peer_connected_t() = default;
        explicit peer_connected_t(value_type) {}
    };

    /* Method tags. */
    struct provision_peer_t
    {
        using value_types = std::tuple<>;
        using return_type = void;
    };
    struct initiate_peer_connection_test_t
    {
        using value_types = std::tuple<>;
        using return_type = void;
    };

    auto provisioned() const
        requires server_details::has_get_property_nomsg<provisioned_t, Instance>
    {
        return static_cast<const Instance*>(this)->get_property(provisioned_t{});
    }
    auto provisioned(sdbusplus::message_t& m) const
        requires server_details::has_get_property_msg<provisioned_t, Instance>
    {
        return static_cast<const Instance*>(this)->get_property(provisioned_t{}, m);
    }
    auto provisioned() const noexcept
        requires (!server_details::has_get_property<provisioned_t, Instance>)
    {
        static_assert(
            !server_details::has_get_property_missing_const<provisioned_t,
                                                            Instance>,
            "Missing const on get_property(provisioned_t)?");
        return provisioned_;
    }

    auto peer_connected() const
        requires server_details::has_get_property_nomsg<peer_connected_t, Instance>
    {
        return static_cast<const Instance*>(this)->get_property(peer_connected_t{});
    }
    auto peer_connected(sdbusplus::message_t& m) const
        requires server_details::has_get_property_msg<peer_connected_t, Instance>
    {
        return static_cast<const Instance*>(this)->get_property(peer_connected_t{}, m);
    }
    auto peer_connected() const noexcept
        requires (!server_details::has_get_property<peer_connected_t, Instance>)
    {
        static_assert(
            !server_details::has_get_property_missing_const<peer_connected_t,
                                                            Instance>,
            "Missing const on get_property(peer_connected_t)?");
        return peer_connected_;
    }

    template <bool EmitSignal = true, typename Arg = bool>
    void provisioned(Arg&& new_value)
        requires server_details::has_set_property_nomsg<provisioned_t, Instance,
                                                        bool>
    {
        bool changed = static_cast<Instance*>(this)->set_property(
            provisioned_t{}, std::forward<Arg>(new_value));

        if (changed && EmitSignal)
        {
            _xyz_openbmc_project_provisioning_Provisioning_interface.property_changed("Provisioned");
        }
    }

    template <bool EmitSignal = true, typename Arg = bool>
    void provisioned(sdbusplus::message_t& m, Arg&& new_value)
        requires server_details::has_set_property_msg<provisioned_t, Instance,
                                                      bool>
    {
        bool changed = static_cast<Instance*>(this)->set_property(
            provisioned_t{}, m, std::forward<Arg>(new_value));

        if (changed && EmitSignal)
        {
            _xyz_openbmc_project_provisioning_Provisioning_interface.property_changed("Provisioned");
        }
    }

    template <bool EmitSignal = true, typename Arg = bool>
    void provisioned(Arg&& new_value)
        requires (!server_details::has_set_property<provisioned_t, Instance,
                                                    bool>)
    {
        static_assert(
            !server_details::has_get_property<provisioned_t, Instance>,
            "Cannot create default set-property for 'provisioned_t' with get-property overload.");

        bool changed = (new_value != provisioned_);
        provisioned_ = std::forward<Arg>(new_value);

        if (changed && EmitSignal)
        {
            _xyz_openbmc_project_provisioning_Provisioning_interface.property_changed("Provisioned");
        }
    }

    template <bool EmitSignal = true, typename Arg = bool>
    void peer_connected(Arg&& new_value)
        requires server_details::has_set_property_nomsg<peer_connected_t, Instance,
                                                        bool>
    {
        bool changed = static_cast<Instance*>(this)->set_property(
            peer_connected_t{}, std::forward<Arg>(new_value));

        if (changed && EmitSignal)
        {
            _xyz_openbmc_project_provisioning_Provisioning_interface.property_changed("PeerConnected");
        }
    }

    template <bool EmitSignal = true, typename Arg = bool>
    void peer_connected(sdbusplus::message_t& m, Arg&& new_value)
        requires server_details::has_set_property_msg<peer_connected_t, Instance,
                                                      bool>
    {
        bool changed = static_cast<Instance*>(this)->set_property(
            peer_connected_t{}, m, std::forward<Arg>(new_value));

        if (changed && EmitSignal)
        {
            _xyz_openbmc_project_provisioning_Provisioning_interface.property_changed("PeerConnected");
        }
    }

    template <bool EmitSignal = true, typename Arg = bool>
    void peer_connected(Arg&& new_value)
        requires (!server_details::has_set_property<peer_connected_t, Instance,
                                                    bool>)
    {
        static_assert(
            !server_details::has_get_property<peer_connected_t, Instance>,
            "Cannot create default set-property for 'peer_connected_t' with get-property overload.");

        bool changed = (new_value != peer_connected_);
        peer_connected_ = std::forward<Arg>(new_value);

        if (changed && EmitSignal)
        {
            _xyz_openbmc_project_provisioning_Provisioning_interface.property_changed("PeerConnected");
        }
    }


  protected:
    bool provisioned_ = false;
    bool peer_connected_ = false;

  private:
    /** @return the async context */
    sdbusplus::async::context& _context()
    {
        return server_details::server_context_friend::
            context<Server, Provisioning>(this);
    }

    sdbusplus::server::interface_t
        _xyz_openbmc_project_provisioning_Provisioning_interface;

    static constexpr auto _property_typeid_provisioned =
        utility::tuple_to_array(message::types::type_id<bool>());
    static constexpr auto _property_typeid_peer_connected =
        utility::tuple_to_array(message::types::type_id<bool>());
    static constexpr auto _method_typeid_p_provision_peer =
        utility::tuple_to_array(std::make_tuple('\0'));

    static constexpr auto _method_typeid_r_provision_peer =
        utility::tuple_to_array(std::make_tuple('\0'));
    static constexpr auto _method_typeid_p_initiate_peer_connection_test =
        utility::tuple_to_array(std::make_tuple('\0'));

    static constexpr auto _method_typeid_r_initiate_peer_connection_test =
        utility::tuple_to_array(std::make_tuple('\0'));
    static constexpr auto _signal_typeid_peer_provisioned =
        utility::tuple_to_array(message::types::type_id<>());

    static int _callback_get_provisioned(
        sd_bus*, const char*, const char*, const char*,
        sd_bus_message* reply, void* context,
        sd_bus_error* error [[maybe_unused]])
    {
        auto self = static_cast<Provisioning*>(context);

        try
        {
            auto m = sdbusplus::message_t{reply};

            // Set up the transaction.
            sdbusplus::server::transaction::set_id(m);

            // Get property value and add to message.
            if constexpr (server_details::has_get_property_msg<provisioned_t,
                                                               Instance>)
            {
                auto v = self->provisioned(m);
                static_assert(std::is_convertible_v<decltype(v), bool>,
                              "Property doesn't convert to 'bool'.");
                m.append<bool>(std::move(v));
            }
            else
            {
                auto v = self->provisioned();
                static_assert(std::is_convertible_v<decltype(v), bool>,
                              "Property doesn't convert to 'bool'.");
                m.append<bool>(std::move(v));
            }
        }
        catch (const std::exception&)
        {
            self->_context().get_bus().set_current_exception(
                std::current_exception());
            return -EINVAL;
        }

        return 1;
    }


    static int _callback_get_peer_connected(
        sd_bus*, const char*, const char*, const char*,
        sd_bus_message* reply, void* context,
        sd_bus_error* error [[maybe_unused]])
    {
        auto self = static_cast<Provisioning*>(context);

        try
        {
            auto m = sdbusplus::message_t{reply};

            // Set up the transaction.
            sdbusplus::server::transaction::set_id(m);

            // Get property value and add to message.
            if constexpr (server_details::has_get_property_msg<peer_connected_t,
                                                               Instance>)
            {
                auto v = self->peer_connected(m);
                static_assert(std::is_convertible_v<decltype(v), bool>,
                              "Property doesn't convert to 'bool'.");
                m.append<bool>(std::move(v));
            }
            else
            {
                auto v = self->peer_connected();
                static_assert(std::is_convertible_v<decltype(v), bool>,
                              "Property doesn't convert to 'bool'.");
                m.append<bool>(std::move(v));
            }
        }
        catch (const std::exception&)
        {
            self->_context().get_bus().set_current_exception(
                std::current_exception());
            return -EINVAL;
        }

        return 1;
    }



    static int _callback_m_provision_peer(sd_bus_message* msg, void* context,
                                     sd_bus_error* error [[maybe_unused]])
        requires (server_details::has_method<
                            provision_peer_t, Instance>)
    {
        auto self = static_cast<Provisioning*>(context);
        auto self_i = static_cast<Instance*>(self);

        try
        {
            auto m = sdbusplus::message_t{msg};

            constexpr auto has_method_msg =
                server_details::has_method_msg<
                    provision_peer_t, Instance>;

            if constexpr (has_method_msg)
            {
                constexpr auto is_async = std::is_same_v<
                    sdbusplus::async::task<void>,
                    decltype(self_i->method_call(provision_peer_t{}, m))>;

                if constexpr (!is_async)
                {
                    auto r = m.new_method_return();
                    self_i->method_call(provision_peer_t{}, m);
                    r.method_return();
                }
                else
                {
                    auto fn = [](auto self, auto self_i,
                                 sdbusplus::message_t m)
                            -> sdbusplus::async::task<>
                    {
                        try
                        {

                            auto r = m.new_method_return();
                            co_await self_i->method_call(
                                provision_peer_t{}, m);

                            r.method_return();
                            co_return;
                        }
                        catch(const std::exception&)
                        {
                            self->_context().get_bus().set_current_exception(
                                std::current_exception());
                            co_return;
                        }
                    };

                    self->_context().spawn(
                        std::move(fn(self, self_i, m)));
                }
            }
            else
            {
                constexpr auto is_async [[maybe_unused]] = std::is_same_v<
                    sdbusplus::async::task<void>,
                    decltype(self_i->method_call(provision_peer_t{}))>;

                if constexpr (!is_async)
                {
                    auto r = m.new_method_return();
                    self_i->method_call(provision_peer_t{});
                    r.method_return();
                }
                else
                {
                    auto fn = [](auto self, auto self_i,
                                 sdbusplus::message_t m)
                            -> sdbusplus::async::task<>
                    {
                        try
                        {

                            auto r = m.new_method_return();
                            co_await self_i->method_call(
                                provision_peer_t{});

                            r.method_return();
                            co_return;
                        }
                        catch(const std::exception&)
                        {
                            self->_context().get_bus().set_current_exception(
                                std::current_exception());
                            co_return;
                        }
                    };

                    self->_context().spawn(
                        std::move(fn(self, self_i, m)));
                }
            }
        }
        catch(const std::exception&)
        {
            self->_context().get_bus().set_current_exception(
                std::current_exception());
            return -EINVAL;
        }

        return 1;
    }
    static int _callback_m_initiate_peer_connection_test(sd_bus_message* msg, void* context,
                                     sd_bus_error* error [[maybe_unused]])
        requires (server_details::has_method<
                            initiate_peer_connection_test_t, Instance>)
    {
        auto self = static_cast<Provisioning*>(context);
        auto self_i = static_cast<Instance*>(self);

        try
        {
            auto m = sdbusplus::message_t{msg};

            constexpr auto has_method_msg =
                server_details::has_method_msg<
                    initiate_peer_connection_test_t, Instance>;

            if constexpr (has_method_msg)
            {
                constexpr auto is_async = std::is_same_v<
                    sdbusplus::async::task<void>,
                    decltype(self_i->method_call(initiate_peer_connection_test_t{}, m))>;

                if constexpr (!is_async)
                {
                    auto r = m.new_method_return();
                    self_i->method_call(initiate_peer_connection_test_t{}, m);
                    r.method_return();
                }
                else
                {
                    auto fn = [](auto self, auto self_i,
                                 sdbusplus::message_t m)
                            -> sdbusplus::async::task<>
                    {
                        try
                        {

                            auto r = m.new_method_return();
                            co_await self_i->method_call(
                                initiate_peer_connection_test_t{}, m);

                            r.method_return();
                            co_return;
                        }
                        catch(const std::exception&)
                        {
                            self->_context().get_bus().set_current_exception(
                                std::current_exception());
                            co_return;
                        }
                    };

                    self->_context().spawn(
                        std::move(fn(self, self_i, m)));
                }
            }
            else
            {
                constexpr auto is_async [[maybe_unused]] = std::is_same_v<
                    sdbusplus::async::task<void>,
                    decltype(self_i->method_call(initiate_peer_connection_test_t{}))>;

                if constexpr (!is_async)
                {
                    auto r = m.new_method_return();
                    self_i->method_call(initiate_peer_connection_test_t{});
                    r.method_return();
                }
                else
                {
                    auto fn = [](auto self, auto self_i,
                                 sdbusplus::message_t m)
                            -> sdbusplus::async::task<>
                    {
                        try
                        {

                            auto r = m.new_method_return();
                            co_await self_i->method_call(
                                initiate_peer_connection_test_t{});

                            r.method_return();
                            co_return;
                        }
                        catch(const std::exception&)
                        {
                            self->_context().get_bus().set_current_exception(
                                std::current_exception());
                            co_return;
                        }
                    };

                    self->_context().spawn(
                        std::move(fn(self, self_i, m)));
                }
            }
        }
        catch(const std::exception&)
        {
            self->_context().get_bus().set_current_exception(
                std::current_exception());
            return -EINVAL;
        }

        return 1;
    }

    static constexpr sdbusplus::vtable_t _vtable[] = {
        vtable::start(),

        vtable::property("Provisioned",
                         _property_typeid_provisioned.data(),
                         _callback_get_provisioned,
                         vtable::property_::emits_change),
        vtable::property("PeerConnected",
                         _property_typeid_peer_connected.data(),
                         _callback_get_peer_connected,
                         vtable::property_::emits_change),
        vtable::method("ProvisionPeer",
                       _method_typeid_p_provision_peer.data(),
                       _method_typeid_r_provision_peer.data(),
                       _callback_m_provision_peer),
        vtable::method("InitiatePeerConnectionTest",
                       _method_typeid_p_initiate_peer_connection_test.data(),
                       _method_typeid_r_initiate_peer_connection_test.data(),
                       _callback_m_initiate_peer_connection_test),
        vtable::signal(
            "PeerProvisioned",
            _signal_typeid_peer_provisioned.data()),

        vtable::end(),
    };
};

} // namespace details
} // namespace sdbusplus::aserver::xyz::openbmc_project::provisioning

