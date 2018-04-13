/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <glog/logging.h>
#include <netlink/route/link.h>

#include "cnetlink.hpp"
#include "ctapdev.hpp"
#include "tap_io.hpp"
#include "tap_manager.hpp"

namespace basebox {

tap_manager::tap_manager(cnetlink *nl) : io(new tap_io()), nl(nl) {}

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
    std::lock_guard<std::mutex> lock{tn_mutex};
    auto dev_name_it = tap_names2id.find(port_name);

    if (dev_name_it != tap_names2id.end())
      dev_name_exists = true;
  }

  if (!dev_exists && !dev_name_exists) {
    // create a new tap device
    ctapdev *dev;

    try {
      dev = new ctapdev(port_name);
      tap_devs.insert(std::make_pair(port_id, dev));
      {
        std::lock_guard<std::mutex> lock{tn_mutex};
        tap_names2id.emplace(std::make_pair(port_name, port_id));
      }

      // create the port
      dev->tap_open();

      int fd = dev->get_fd();

      LOG(INFO) << __FUNCTION__ << ": port_id=" << port_id
                << " portname=" << port_name << " fd=" << fd << " ptr=" << dev;

      {
        std::lock_guard<std::mutex> lock{tn_mutex};
        tap_names2fds.emplace(std::make_pair(port_name, fd));
      }

      // start reading from port
      tap_io::tap_io_details td(fd, port_id, &cb, 0);
      io->register_tap(td);
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
  std::lock_guard<std::mutex> lock{tn_mutex};
  port_deleted.push_back(port_id);
  auto tap_names_it = tap_names2id.find(port_name);

  if (tap_names_it != tap_names2id.end()) {
    tap_names2id.erase(tap_names_it);
  }

  // drop port from port mapping
  auto dev = it->second;
  int fd = dev->get_fd();
  tap_devs.erase(it);
  delete dev;

  io->unregister_tap(fd, port_id);

  return 0;
}

void tap_manager::destroy_tapdevs() {
  std::map<uint32_t, ctapdev *> ddevs;
  ddevs.swap(tap_devs);
  for (auto &dev : ddevs) {
    delete dev.second;
  }
  tap_names2id.clear();
}

int tap_manager::enqueue(uint32_t port_id, basebox::packet *pkt) {
  try {
    int fd = tap_devs.at(port_id)->get_fd();
    io->enqueue(fd, pkt);
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

  std::lock_guard<std::mutex> lock{tn_mutex};
  auto tn_it = tap_names2id.find(name);

  if (tn_it == tap_names2id.end()) {
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

  std::unique_ptr<rtnl_link, void (*)(rtnl_link *)> l(
      nl->get_link_by_ifindex(ifindex), &rtnl_link_put);

  if (!l) {
    LOG(ERROR) << __FUNCTION__ << ": invalid link ifindex=" << ifindex;
    return;
  }

  int mtu = rtnl_link_get_mtu(l.get());
  auto fd_it = tap_names2fds.find(name);

  if (fd_it == tap_names2fds.end()) {
    LOG(ERROR) << __FUNCTION__ << ": tap_dev not found";
    return;
  }

  io->update_mtu(fd_it->second, mtu);
}

void tap_manager::tap_dev_removed(int ifindex) {
  std::lock_guard<std::mutex> lock{tn_mutex};

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
