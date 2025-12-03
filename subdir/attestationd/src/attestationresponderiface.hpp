#pragma once
#include "sdbus_calls.hpp"

#include <format>
class AttestationResponderIface
{
    std::shared_ptr<sdbusplus::asio::connection> conn;
    static constexpr auto objPath =
        "/xyz/openbmc_project/attestation_responder/tcp/{}";
    static constexpr auto interface =
        "xyz.openbmc_project.AttestationResponder";
    constexpr static auto signal = "Attested";
    sdbusplus::asio::object_server& dbusServer;
    bool attested{false};
    const std::string id;

  public:
    explicit AttestationResponderIface(
        const std::shared_ptr<sdbusplus::asio::connection>& conn,
        sdbusplus::asio::object_server& objectServer, const std::string& id) :
        conn(conn), dbusServer(objectServer), id(id)
    {
        auto path = std::format(objPath, id);
        auto intf = dbusServer.add_interface(path.c_str(), interface);

        intf->register_signal<bool>(signal);
        intf->initialize();
    }

    virtual ~AttestationResponderIface() = default;
    // Non-copyable to avoid accidental shared state
    AttestationResponderIface(const AttestationResponderIface&) = delete;
    AttestationResponderIface& operator=(const AttestationResponderIface&) =
        delete;

    // Movable
    AttestationResponderIface(AttestationResponderIface&&) noexcept = default;
    AttestationResponderIface& operator=(AttestationResponderIface&&) noexcept =
        default;
    void emitStatus(bool status)
    {
        LOG_DEBUG("Emitting Responder status {}", status);
        std::string path = std::format(objPath, id);
        auto msg = conn->new_signal(path.data(), interface, signal);
        bool value = status;
        msg.append(value);
        msg.signal_send();
    }
};
