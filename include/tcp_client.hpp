#pragma once
#include "make_awaitable.hpp"
#include "socket_streams.hpp"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast.hpp>
#include <boost/system/error_code.hpp>

#include <iostream>
#include <string>
#include <utility>

#ifdef __linux__
#include <netinet/tcp.h>
#include <sys/socket.h>
#endif
namespace NSNAME
{
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

template <typename Socket>
inline void configureSocketKeepalive(Socket& socket)
{
    boost::system::error_code ec;

    // Enable TCP keepalive to detect dead connections
    boost::asio::socket_base::keep_alive keepalive_option(true);
    socket.set_option(keepalive_option, ec);
    if (ec)
    {
        LOG_ERROR("Failed to set keepalive option: {}", ec.message());
        return;
    }

#ifdef __linux__
    // Configure aggressive TCP keepalive parameters for faster dead connection
    // detection
    int native_fd = socket.native_handle();

    // Start sending keepalive probes after 10 seconds of idle time
    int keepalive_time = 10;
    if (setsockopt(native_fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepalive_time,
                   sizeof(keepalive_time)) < 0)
    {
        LOG_ERROR("Failed to set TCP_KEEPIDLE");
    }

    // Send keepalive probes every 5 seconds
    int keepalive_interval = 5;
    if (setsockopt(native_fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepalive_interval,
                   sizeof(keepalive_interval)) < 0)
    {
        LOG_ERROR("Failed to set TCP_KEEPINTVL");
    }

    // Close connection after 3 failed probes (total ~25 seconds to detect dead
    // connection)
    int keepalive_count = 3;
    if (setsockopt(native_fd, IPPROTO_TCP, TCP_KEEPCNT, &keepalive_count,
                   sizeof(keepalive_count)) < 0)
    {
        LOG_ERROR("Failed to set TCP_KEEPCNT");
    }
#endif
}

inline AwaitableResult<net::ip::tcp::resolver::results_type> awaitable_resolve(
    typename net::ip::tcp::resolver& resolver, const std::string& host,
    const std::string& port)
{
    auto h = make_awaitable_handler<net::ip::tcp::resolver::results_type>(
        [&](auto promise) {
            // resolver.async_resolve(
            //     host, port,
            //     [handler = std::move(handler)](
            //         boost::system::error_code ec,
            //         net::ip::tcp::resolver::results_type results) mutable {
            //         handler(ec, std::move(results));
            //     });
            boost::system::error_code ec;
            auto results = resolver.resolve(host, port, ec);
            promise.setValues(ec, results);
        });
    co_return co_await h();
}
class TcpClient
{
  public:
    TcpClient(net::any_io_executor io_context, ssl::context& ssl_context) :
        resolver_(io_context),
        stream_(std::make_shared<ssl::stream<tcp::socket>>(io_context,
                                                           ssl_context)),
        timer_(std::make_shared<net::steady_timer>(io_context))
    {}
    ~TcpClient()
    {
        timer_->cancel();
    }

    net::awaitable<boost::system::error_code> connect(const std::string& host,
                                                      const std::string& port)
    {
        auto [ec, results] = co_await awaitable_resolve(resolver_, host, port);
        if (ec)
        {
            LOG_ERROR("Error resolving {}:{}. Error: {}", host, port,
                      ec.message());
            co_return ec;
        }

        TimedStreamer streamer(stream_, timer_);
        streamer.setTimeout(30s);
        co_await net::async_connect(
            stream_->next_layer(), results,
            net::redirect_error(net::use_awaitable, ec));
        if (ec)
        {
            LOG_ERROR("Error connecting to {}:{}. Error: {}", host, port,
                      ec.message());
            co_return ec;
        }

        // Configure TCP keepalive to detect dead connections quickly
        configureSocketKeepalive(stream_->lowest_layer());
        streamer.setTimeout(30s);
        co_await stream_->async_handshake(
            ssl::stream_base::client,
            net::redirect_error(net::use_awaitable, ec));
        if (ec)
        {
            LOG_ERROR("Error during SSL handshake with {}:{}. Error: {}", host,
                      port, ec.message());
        }
        co_return ec;
    }

    AwaitableResult<std::size_t> write(net::const_buffer data)
    {
        co_return co_await streamer().write(data);
    }

    AwaitableResult<std::size_t> read(net::mutable_buffer buffer)
    {
        co_return co_await streamer().read(buffer);
    }
    ssl::stream<tcp::socket>& stream()
    {
        return *stream_;
    }
    TimedStreamer<ssl::stream<tcp::socket>> streamer()
    {
        return TimedStreamer(stream_, timer_);
    }
    void close()
    {
        boost::system::error_code ec;
        stream_->next_layer().close(ec);
        if (ec)
        {
            LOG_ERROR("Error closing socket: {}", ec.message());
        }
    }
    bool isOpen() const
    {
        return stream_->lowest_layer().is_open();
    }

  private:
    tcp::resolver resolver_;
    std::shared_ptr<ssl::stream<tcp::socket>> stream_;
    std::shared_ptr<net::steady_timer> timer_;
};
} // namespace NSNAME
