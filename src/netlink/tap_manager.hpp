/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <deque>
#include <string>
#include <vector>
#include <map>
#include <mutex>

#include <rofl/common/cpacket.h>

#include "netlink/ctapdev.hpp"
#include "sai.hpp"

namespace basebox {

class cnetlink;
class tap_io;
class tap_manager;

class switch_callback {
public:
  virtual int enqueue_to_switch(uint32_t port_id, basebox::packet *) = 0;
};

class tap_io : public rofl::cthread_env {
public:
  struct tap_io_details {
    tap_io_details() : fd(-1), port_id(0), cb(nullptr), mtu(0) {}
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
  void enqueue(int fd, basebox::packet *pkt);
  void update_mtu(int fd, unsigned mtu);

private:
  enum tap_io_event {
    TAP_IO_ADD,
    TAP_IO_REM,
  };

  rofl::cthread thread;
  std::deque<std::pair<int, basebox::packet *>> pout_queue;
  std::mutex pout_queue_mutex;

  std::deque<std::pair<enum tap_io_event, tap_io_details>> events;
  std::mutex events_mutex;

  std::deque<std::pair<int, basebox::packet *>> pin_queue;
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

class tap_manager final {

public:
  tap_manager(cnetlink *nl) : nl(nl) {}
  ~tap_manager();

  int create_tapdev(uint32_t port_id, const std::string &port_name,
                    switch_callback &callback);

  int destroy_tapdev(uint32_t port_id, const std::string &port_name);

  void destroy_tapdevs();

  int enqueue(uint32_t port_id, basebox::packet *pkt);

  std::map<std::string, uint32_t> get_registered_ports() const {
    std::lock_guard<std::mutex> lock(rp_mutex);
    return tap_names;
  }

  uint32_t get_port_id(int ifindex) const noexcept {
    auto it = ifindex_to_id.find(ifindex);
    if (it == ifindex_to_id.end()) {
      return 0;
    } else {
      return it->second;
    }
  }

  int get_ifindex(uint32_t port_id) const noexcept {
    auto it = id_to_ifindex.find(port_id);
    if (it == id_to_ifindex.end()) {
      return 0;
    } else {
      return it->second;
    }
  }

  void tap_dev_ready(int ifindex, const std::string &name);
  void tap_dev_removed(int ifindex);

private:
  tap_manager(const tap_manager &other) = delete; // non construction-copyable
  tap_manager &operator=(const tap_manager &) = delete; // non copyable

  std::map<uint32_t, ctapdev *> tap_devs; // southbound id:tap_device
  mutable std::mutex rp_mutex;
  std::map<std::string, uint32_t> tap_names;

  std::map<int, uint32_t> ifindex_to_id;
  std::map<uint32_t, int> id_to_ifindex;
  std::deque<uint32_t> port_deleted;

  basebox::tap_io io;
  cnetlink *nl;
};

} // namespace basebox
