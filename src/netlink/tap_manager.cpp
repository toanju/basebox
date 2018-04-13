/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <glog/logging.h>
#include "netlink/tap_manager.hpp"
#include "utils.hpp"

namespace basebox {

static inline void
release_packets(std::deque<std::pair<int, basebox::packet *>> &q) {
  for (auto i : q) {
    std::free(i.second);
  }
}

tap_io::~tap_io() { thread.stop(); }

void tap_io::register_tap(int fd, uint32_t port_id, switch_callback &cb) {
  {
    std::lock_guard<std::mutex> guard(events_mutex);
    events.emplace_back(std::make_tuple(TAP_IO_ADD, fd, port_id, &cb));
  }

  thread.wakeup();
}

void tap_io::unregister_tap(int fd, uint32_t port_id) {
  {
    std::lock_guard<std::mutex> guard(events_mutex);
    events.emplace_back(std::make_tuple(TAP_IO_REM, fd, port_id, nullptr));
  }

  thread.wakeup();
}

void tap_io::enqueue(int fd, basebox::packet *pkt) {
  if (fd == -1) {
    std::free(pkt);
    return;
  }

  {
    // store pkt in outgoing queue
    std::lock_guard<std::mutex> guard(pout_queue_mutex);
    pout_queue.emplace_back(std::make_pair(fd, pkt));
  }
  thread.wakeup();
}

void tap_io::handle_read_event(rofl::cthread &thread, int fd) {
  basebox::packet *pkt = (basebox::packet *)std::malloc(sizeof(std::size_t) +
                                                        1528); // TODO use mtu

  if (pkt == nullptr) {
    LOG(ERROR) << __FUNCTION__ << ": no mem left";
    return;
  }

  pkt->len = read(fd, pkt->data, 1528);

  if (pkt->len > 0) {
    VLOG(3) << __FUNCTION__ << ": read " << pkt->len << " bytes from fd=" << fd
            << " into pkt=" << pkt << " tid=" << pthread_self();
    std::pair<uint32_t, switch_callback *> &cb = sw_cbs.at(fd);
    cb.second->enqueue_to_switch(cb.first, pkt);
  } else {
    // error occured (or non-blocking)
    switch (errno) {
    case EAGAIN:
      LOG(ERROR) << __FUNCTION__
                 << ": EAGAIN XXX not implemented packet is dropped";
      std::free(pkt);
      break;
    default:
      LOG(ERROR) << __FUNCTION__ << ": unknown error occured";
      std::free(pkt);
      break;
    }
  }
}

void tap_io::handle_write_event(rofl::cthread &thread, int fd) {
  thread.drop_write_fd(fd);
  tx();
}

void tap_io::tx() {
  std::pair<int, basebox::packet *> pkt;
  std::deque<std::pair<int, basebox::packet *>> out_queue;

  {
    std::lock_guard<std::mutex> guard(pout_queue_mutex);
    std::swap(out_queue, pout_queue);
  }

  while (not out_queue.empty()) {

    pkt = out_queue.front();
    int rc = 0;
    if ((rc = write(pkt.first, pkt.second->data, pkt.second->len)) < 0) {
      switch (errno) {
      case EAGAIN:
        VLOG(1) << __FUNCTION__ << ": EAGAIN";
        {
          std::lock_guard<std::mutex> guard(pout_queue_mutex);
          std::move(out_queue.rbegin(), out_queue.rend(),
                    std::front_inserter(pout_queue));
        }
        thread.add_write_fd(pkt.first, true, false);
        return;
      case EIO:
        // tap not enabled drop packet
        VLOG(1) << __FUNCTION__ << ": EIO";
        release_packets(out_queue);
        return;
      default:
        // will drop packets
        release_packets(out_queue);
        LOG(ERROR) << __FUNCTION__ << ": unknown error occurred rc=" << rc
                   << " errno=" << errno << " '" << strerror(errno);
        return;
      }
    }
    std::free(pkt.second);
    out_queue.pop_front();
  }
}

void tap_io::handle_events() {
  std::lock_guard<std::mutex> guard(events_mutex);

  // register fds
  for (auto ev : events) {
    int fd = std::get<1>(ev);
    switch (std::get<0>(ev)) {

    case TAP_IO_ADD:
      sw_cbs.emplace(
          std::make_pair(fd, std::make_pair(std::get<2>(ev), std::get<3>(ev))));
      thread.add_read_fd(fd, true, false);
      break;
    case TAP_IO_REM:
      thread.drop_fd(fd, false);
      sw_cbs.erase(fd);
      break;
    default:
      break;
    }
  }
  events.clear();
}

tap_manager::~tap_manager() { destroy_tapdevs(); }

int tap_manager::create_tapdev(uint32_t port_id, const std::string &port_name,
                               switch_callback &cb) {
  int r = 0;
  bool dev_exists = false;
  bool dev_name_exists = false;
  auto dev_it = tap_devs.find(port_id);

  if (dev_it != tap_devs.end())
    dev_exists = true;

  {
    std::lock_guard<std::mutex> lock{rp_mutex};
    auto dev_name_it = tap_names.find(port_name);

    if (dev_name_it != tap_names.end())
      dev_name_exists = true;
  }

  if (!dev_exists && !dev_name_exists) {
    // create a new tap device

    ctapdev *dev;
    try {
      dev = new ctapdev(port_name);
      tap_devs.insert(std::make_pair(port_id, dev));
      {
        std::lock_guard<std::mutex> lock{rp_mutex};
        tap_names.insert(std::make_pair(port_name, port_id));
      }

      // create the port
      dev->tap_open();
      int fd = dev->get_fd();

      LOG(INFO) << __FUNCTION__ << ": port_id=" << port_id
                << " portname=" << port_name << " fd=" << fd << " ptr=" << dev;

      // start reading from port
      io.register_tap(fd, port_id, cb);

    } catch (std::exception &e) {
      LOG(ERROR) << __FUNCTION__ << ": failed to create tapdev " << port_name;
      r = -EINVAL;
    }
  } else {
    LOG(INFO) << __FUNCTION__ << ": " << port_name
              << " with port_id=" << port_id << " already existing";
  }
  return r;
}

int tap_manager::destroy_tapdev(uint32_t port_id,
                                const std::string &port_name) {
  auto it = tap_devs.find(port_id);
  if (it == tap_devs.end()) {
    LOG(WARNING) << __FUNCTION__ << ": called for invalid port_id=" << port_id
                 << " port_name=" << port_name;
    return 0;
  }

  // drop port from name mapping
  std::lock_guard<std::mutex> lock{rp_mutex};
  port_deleted.push_back(port_id);
  auto tap_names_it = tap_names.find(port_name);

  if (tap_names_it != tap_names.end()) {
    tap_names.erase(tap_names_it);
  }

  // drop port from port mapping
  auto dev = it->second;
  int fd = dev->get_fd();
  tap_devs.erase(it);
  delete dev;

  // XXX check if previous to delete
  io.unregister_tap(fd, port_id);

  return 0;
}

void tap_manager::destroy_tapdevs() {
  std::map<uint32_t, ctapdev *> ddevs;
  ddevs.swap(tap_devs);
  for (auto &dev : ddevs) {
    delete dev.second;
  }
  tap_names.clear();
}

int tap_manager::enqueue(uint32_t port_id, basebox::packet *pkt) {
  try {
    int fd = tap_devs.at(port_id)->get_fd();
    io.enqueue(fd, pkt);
  } catch (std::exception &e) {
    LOG(ERROR) << __FUNCTION__ << ": failed to enqueue packet " << pkt
               << " to port_id=" << port_id;
    std::free(pkt);
  }
  return 0;
}

void tap_manager::tap_dev_ready(int ifindex, const std::string &name) {
  auto it = ifindex_to_id.find(ifindex);
  if (it != ifindex_to_id.end())
    return;

  std::lock_guard<std::mutex> lock{rp_mutex};
  auto tn_it = tap_names.find(name);

  if (tn_it == tap_names.end()) {
    LOG(WARNING) << __FUNCTION__ << "invalid port name " << name;
    return;
  }

  // update maps
  auto id2ifi_it = id_to_ifindex.insert(std::make_pair(tn_it->second, ifindex));
  if (!id2ifi_it.second && id2ifi_it.first->second != ifindex) {
    // update only if the ifindex has changed
    LOG(WARNING) << __FUNCTION__
                 << ": enforced update of id:ifindex mapping id="
                 << id2ifi_it.first->first
                 << " ifindex(old) = " << id2ifi_it.first->second
                 << " ifindex(new)=" << ifindex;

    // remove overwritten index in ifindex_to_id map
    auto it = ifindex_to_id.find(id2ifi_it.first->second);
    if (it != ifindex_to_id.end()) {
      ifindex_to_id.erase(it);
    }

    // update the old one
    id2ifi_it.first->second = ifindex;
  }

  auto rv1 = ifindex_to_id.insert(std::make_pair(ifindex, tn_it->second));
  if (!rv1.second && rv1.first->second != tn_it->second) {
    // update only if the id has changed
    LOG(WARNING) << __FUNCTION__
                 << ": enforced update of ifindex:id mapping ifindex="
                 << ifindex << " id(old)=" << rv1.first->second
                 << " id(new)=" << tn_it->second;
    rv1.first->second = tn_it->second;
  }

  // XXX FIXME get mtu
  (void)nl;
}

void tap_manager::tap_dev_removed(int ifindex) {
  std::lock_guard<std::mutex> lock{rp_mutex};

  auto ifi2id_it = ifindex_to_id.find(ifindex);
  if (ifi2id_it == ifindex_to_id.end()) {
    VLOG(2) << __FUNCTION__
            << ": ignore removal of tap device with ifindex=" << ifindex;
    return;
  }

  // check if this port was scheduled for deletion
  auto pd_it =
      std::find(port_deleted.begin(), port_deleted.end(), ifi2id_it->second);
  if (pd_it == port_deleted.end()) {
    auto pn_it = tap_devs.find(ifi2id_it->second);
    LOG(FATAL) << __FUNCTION__ << ": illegal removal of port "
               << pn_it->second->get_devname() << " with ifindex=" << ifindex;
  }

  auto id2ifi_it = id_to_ifindex.find(ifi2id_it->second);
  if (id2ifi_it == id_to_ifindex.end()) {
    auto pn_it = tap_devs.find(ifi2id_it->second);
    LOG(FATAL) << __FUNCTION__ << ": illegal removal of port "
               << pn_it->second->get_devname() << " with ifindex=" << ifindex;
  }

  ifindex_to_id.erase(ifi2id_it);
  port_deleted.erase(pd_it);
  id_to_ifindex.erase(id2ifi_it);
}

} // namespace basebox
