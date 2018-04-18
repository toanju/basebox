/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <rofl/common/cthread.hpp>

#include "tap_manager.hpp"

namespace basebox {

class tap_io : public rofl::cthread_env {
public:
  struct tap_io_details {
    tap_io_details() : fd(-1), port_id(0), cb(nullptr), mtu(1500) {}
    tap_io_details(int fd, uint32_t port_id, switch_callback *cb, unsigned mtu)
        : fd(fd), port_id(port_id), cb(cb), mtu(mtu) {}
    int fd;
    uint32_t port_id;
    switch_callback *cb;
    unsigned mtu;
  };

  tap_io();
  virtual ~tap_io();

  // port_id should be removed at some point and be rather data
  void register_tap(tap_io_details td);
  void unregister_tap(int fd, uint32_t port_id);
  void enqueue(int fd, packet *pkt);
  void update_mtu(int fd, unsigned mtu);

private:
  enum tap_io_event {
    TAP_IO_ADD,
    TAP_IO_REM,
  };

  rofl::cthread thread;
  std::deque<std::pair<int, packet *>> pout_queue;
  std::mutex pout_queue_mutex;

  std::deque<std::pair<enum tap_io_event, tap_io_details>> events;
  std::mutex events_mutex;

  std::deque<std::pair<int, packet *>> pin_queue;
  std::vector<tap_io_details> sw_cbs;

  void tx();
  void handle_events();

protected:
  void handle_read_event(rofl::cthread &thread, int fd);
  void handle_write_event(rofl::cthread &thread, int fd);
  void handle_wakeup(rofl::cthread &thread) {
    handle_events();
    tx();
  }
  void handle_timeout(rofl::cthread &thread, uint32_t timer_id) {}
};

} // namespace basebox
