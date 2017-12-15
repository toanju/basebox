/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <cstdint>
#include <memory>

extern "C" {
struct nl_addr;
struct rtnl_addr;
struct rtnl_neigh;
struct rtnl_route;
struct rtnl_nexthop;
}

namespace rofl {
class caddress_ll;
class caddress_in4;
}

namespace basebox {

class cnetlink;
class switch_interface;
class tap_manager;

class nl_l3 {
public:
  nl_l3(switch_interface *sw, std::shared_ptr<tap_manager> tap_man,
        cnetlink *nl);
  ~nl_l3() {}

  int add_l3_termination(struct rtnl_addr *a);
  int del_l3_termination(struct rtnl_addr *a);

  int add_l3_neigh(struct rtnl_neigh *n);
  int update_l3_neigh(struct rtnl_neigh *n_old, struct rtnl_neigh *n_new);
  int del_l3_neigh(struct rtnl_neigh *n);

  int del_l3_egress(int ifindex, const struct nl_addr *s_mac,
                    const struct nl_addr *d_mac);

  int add_l3_route(struct rtnl_route *r);
  int del_l3_route(struct rtnl_route *r);

  void register_switch_interface(switch_interface *sw);

private:
  int add_l3_egress(const uint32_t port_id, const uint16_t vid,
                    const rofl::caddress_ll &dst_mac,
                    const rofl::caddress_ll &src_mac,
                    uint32_t *l3_interface_id);
  int add_l3_unicast_host(const rofl::caddress_in4 &ipv4_dst,
                          uint32_t l3_interface_id) const;

  int port_vid_ingess(int ifindex, uint16_t vid = 1);
  int port_vid_egress(int ifindex, uint16_t vid = 1);

  struct rtnl_neigh *nexthop_resolution(struct rtnl_nexthop *nh, void *arg);

  switch_interface *sw;
  std::shared_ptr<tap_manager> tap_man;
  cnetlink *nl;
};

} // namespace basebox
