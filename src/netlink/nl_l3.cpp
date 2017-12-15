#include <tuple>
#include <unordered_map>

#include <glog/logging.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/route.h>

#include "cnetlink.hpp"
#include "nl_output.hpp"
#include "nl_l3.hpp"
#include "sai.hpp"
#include "tap_manager.hpp"

namespace std {

template <> struct hash<rofl::caddress_ll> {
  typedef rofl::caddress_ll argument_type;
  typedef std::size_t result_type;
  result_type operator()(argument_type const &lla) const noexcept {
    return std::hash<uint64_t>{}(lla.get_mac());
  }
};

namespace {

// based on https://stackoverflow.com/questions/3611951 of Leo Goodstadt
// who
// Code from boost
// Reciprocal of the golden ratio helps spread entropy
//     and handles duplicates.
// See Mike Seymour in magic-numbers-in-boosthash-combine:
//     https://stackoverflow.com/questions/4948780

template <class T> inline void hash_combine(std::size_t &seed, T const &v) {
  seed ^= hash<T>()(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

// Recursive template code derived from Matthieu M.
template <class Tuple, size_t Index = std::tuple_size<Tuple>::value - 1>
struct HashValueImpl {
  static void apply(size_t &seed, Tuple const &tuple) {
    HashValueImpl<Tuple, Index - 1>::apply(seed, tuple);
    hash_combine(seed, get<Index>(tuple));
  }
};

template <class Tuple> struct HashValueImpl<Tuple, 0> {
  static void apply(size_t &seed, Tuple const &tuple) {
    hash_combine(seed, get<0>(tuple));
  }
};
} // namespace

template <typename... TT> struct hash<std::tuple<TT...>> {
  size_t operator()(std::tuple<TT...> const &tt) const {
    size_t seed = 0;
    HashValueImpl<std::tuple<TT...>>::apply(seed, tt);
    return seed;
  }
};
} // namespace std

namespace basebox {

class l3_interface final {
public:
  l3_interface(uint32_t l3_interface_id)
      : l3_interface_id(l3_interface_id), refcnt(1) {}

  uint32_t l3_interface_id;
  int refcnt;
};

// <port_id, vid, src_mac, dst_mac>
std::unordered_map<
    std::tuple<int, uint16_t, rofl::caddress_ll, rofl::caddress_ll>,
    l3_interface>
    l3_interface_mapping;

nl_l3::nl_l3(switch_interface *sw, std::shared_ptr<tap_manager> tap_man,
             cnetlink *nl)
    : sw(sw), tap_man(tap_man), nl(nl) {}

rofl::caddress_ll libnl_lladdr_2_rofl(const struct nl_addr *lladdr) {
  // XXX check for family
  return rofl::caddress_ll((uint8_t *)nl_addr_get_binary_addr(lladdr),
                           nl_addr_get_len(lladdr));
}

rofl::caddress_in4 libnl_in4addr_2_rofl(struct nl_addr *addr) {
  struct sockaddr_in sin;
  socklen_t salen = sizeof(sin);
  nl_addr_fill_sockaddr(addr, (struct sockaddr *)&sin, &salen);
  return rofl::caddress_in4(&sin, salen);
}

int nl_l3::add_l3_termination(struct rtnl_addr *a) {
  assert(sw);
  assert(a);

  sw->subscribe_to(switch_interface::SWIF_ARP);

  int rv = 0;
  uint16_t vid = 1;

  if (a == nullptr) {
    LOG(ERROR) << __FUNCTION__ << ": addr can't be null";
    return -EINVAL;
  }

  int ifindex = rtnl_addr_get_ifindex(a);
  int port_id = tap_man->get_port_id(ifindex);

  if (port_id == 0) {
    LOG(ERROR) << __FUNCTION__ << ": invalid port_id 0";
    return -EINVAL;
  }

  struct rtnl_link *link = rtnl_addr_get_link(a);
  if (link == nullptr) {
    LOG(ERROR) << __FUNCTION__ << ": no link for addr a=" << a;
    return -EINVAL;
  }

  struct nl_addr *addr = rtnl_link_get_addr(link);
  rofl::caddress_ll mac = libnl_lladdr_2_rofl(addr);

  rv = sw->l3_termination_add(port_id, vid, mac);
  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__
               << ": failed to setup termination mac port_id=" << port_id
               << ", vid=" << vid << " mac=" << mac << "; rv=" << rv;
    return rv;
  }

  // get v4 dst (local v4 addr)
  addr = rtnl_addr_get_local(a);
  rofl::caddress_in4 ipv4_dst = libnl_in4addr_2_rofl(addr);
  rv = sw->l3_unicast_host_add(ipv4_dst,
                               0); // TODO likely move this to separate entity
  if (rv < 0) {
    // TODO shall we remove the l3_termination mac?
    LOG(ERROR) << __FUNCTION__
               << ": failed to setup l3 neigh port_id=" << port_id
               << ", vid=" << vid << "; rv=" << rv;
  }

  return rv;
}

int nl_l3::del_l3_termination(struct rtnl_addr *a) {
  assert(sw);
  assert(a);

  int rv = 0;
  uint16_t vid = 1;

  if (a == nullptr) {
    LOG(ERROR) << __FUNCTION__ << ": addr can't be null";
    return -EINVAL;
  }

  struct nl_addr *addr = rtnl_addr_get_local(a);
  rofl::caddress_in4 ipv4_dst = libnl_in4addr_2_rofl(addr);

  rv = sw->l3_unicast_host_remove(ipv4_dst);
  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__
               << ": failed to remove l3 unicast host(local) vid=" << vid
               << "; rv=" << rv;
    return rv;
  }

  int ifindex = rtnl_addr_get_ifindex(a);
  int port_id = tap_man->get_port_id(ifindex);

  if (port_id == 0) {
    VLOG(1) << __FUNCTION__ << ": invalid port_id 0";
    return -EINVAL;
  }

  struct rtnl_link *link = rtnl_addr_get_link(a);
  if (link == nullptr) {
    LOG(ERROR) << __FUNCTION__ << ": no link for addr a=" << a;
    return -EINVAL;
  }

  addr = rtnl_link_get_addr(link);
  rofl::caddress_ll mac = libnl_lladdr_2_rofl(addr);

  // XXX TODO don't do this in case more l3 addresses are on this link
  rv = sw->l3_termination_remove(port_id, vid, mac);
  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__
               << ": failed to remove l3 termination mac(local) vid=" << vid
               << "; rv=" << rv;
  }

  return rv;
}

int nl_l3::port_vid_ingess(int ifindex, uint16_t vid) {
  int rv = 0;
  uint32_t port_id = tap_man->get_port_id(ifindex);

  if (port_id == 0) {
    LOG(ERROR) << __FUNCTION__ << ": invalid port_id=" << port_id;
    return -EINVAL;
  }

  // setup ingress interface
  rv = sw->ingress_port_vlan_add(port_id, vid, true);
  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__
               << ": failed to setup ingress vlan 1 (untagged) on port_id="
               << port_id << "; rv=" << rv;
  }

  return rv;
}

int nl_l3::port_vid_egress(int ifindex, uint16_t vid) {
  int rv = 0;
  uint32_t port_id = tap_man->get_port_id(ifindex);

  if (port_id == 0) {
    LOG(ERROR) << __FUNCTION__ << ": invalid port_id=" << port_id;
    return -EINVAL;
  }

  // setup egress interface
  rv = sw->egress_port_vlan_add(port_id, vid, true);

  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__
               << ": failed to setup egress vlan 1 (untagged) on port_id="
               << port_id << "; rv=" << rv;
  }

  return rv;
}

int nl_l3::add_l3_unicast_host(const rofl::caddress_in4 &ipv4_dst,
                               uint32_t l3_interface_id) const {
  int rv = 0;
  rv = sw->l3_unicast_host_add(ipv4_dst, l3_interface_id);

  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__ << ": failed ipv4_dst=" << ipv4_dst
               << "l3_interface_id=" << l3_interface_id << "; rv=" << rv;
  }

  return rv;
}

int nl_l3::add_l3_unicast_route(const rofl::caddress_in4 &ipv4_dst,
                                const rofl::caddress_in4 &mask,
                                uint32_t l3_interface_id) const {
  int rv = 0;
  rv = sw->l3_unicast_route_add(ipv4_dst, mask, l3_interface_id);
  return rv;
}

int nl_l3::add_l3_egress(const uint32_t port_id, const uint16_t vid,
                         const rofl::caddress_ll &dst_mac,
                         const rofl::caddress_ll &src_mac,
                         uint32_t *l3_interface_id) {
  int rv = 0;

  // setup egress L3 Unicast group
  uint32_t _l3_interface_id = 0;
  auto it = l3_interface_mapping.find(
      std::make_tuple(port_id, vid, src_mac, dst_mac));

  if (it == l3_interface_mapping.end()) {
    rv =
        sw->l3_egress_create(port_id, vid, src_mac, dst_mac, &_l3_interface_id);

    if (rv < 0) {
      LOG(ERROR) << __FUNCTION__
                 << ": failed to setup l3 egress port_id=" << port_id
                 << ", vid=" << vid << ", src_mac=" << src_mac
                 << ", dst_mac=" << dst_mac << "; rv=" << rv;
      return rv;
    }

    auto rv = l3_interface_mapping.emplace(
        std::make_pair(std::make_tuple(port_id, vid, src_mac, dst_mac),
                       l3_interface(_l3_interface_id)));

    if (!rv.second) {
      LOG(FATAL) << __FUNCTION__
                 << ": failed to store l3_interface_id port_id=" << port_id
                 << ", vid=" << vid << ", src_mac=" << src_mac
                 << ", dst_mac=" << dst_mac;
    }
  } else {
    assert(it->second.l3_interface_id);
    _l3_interface_id = it->second.l3_interface_id;
    it->second.refcnt++;
  }

  *l3_interface_id = _l3_interface_id;

  return rv;
}

int nl_l3::add_l3_neigh_egress(struct rtnl_neigh *n,
                               uint32_t *l3_interface_id) {
  int rv;
  assert(n);
  int state = rtnl_neigh_get_state(n);

  if (state == NUD_FAILED) {
    LOG(INFO) << __FUNCTION__ << ": neighbour not reachable state=failed";
    return -EINVAL;
  }

  int vid = 1; // XXX TODO currently only on vid 1
  struct nl_addr *addr = rtnl_neigh_get_lladdr(n);
  rofl::caddress_ll dst_mac = libnl_lladdr_2_rofl(addr);
  int ifindex = rtnl_neigh_get_ifindex(n);
  uint32_t port_id = tap_man->get_port_id(ifindex);

  if (port_id == 0) {
    LOG(ERROR) << __FUNCTION__ << ": invalid port_id=" << port_id;
    return -EINVAL;
  }

  struct rtnl_link *link =
      nl->get_link_by_ifindex(ifindex);

  if (link == nullptr)
    return -EINVAL;

  addr = rtnl_link_get_addr(link);
  rofl::caddress_ll src_mac = libnl_lladdr_2_rofl(addr);
  rtnl_link_put(link);
  link = nullptr;

  // XXX these still have to move to another entity
  rv = port_vid_ingess(ifindex, vid);
  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__ << ": failed to setup vid ingress vid=" << vid
               << "on link " << OBJ_CAST(link);
    return rv;
  }

  rv = port_vid_egress(ifindex, vid);
  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__ << ": failed to setup vid egress vid=" << vid
               << "on link " << OBJ_CAST(link);

    return rv;
  }

  rv = add_l3_egress(port_id, vid, dst_mac, src_mac, l3_interface_id);
  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__ << ": failed to add l3 egress";
  }

  return rv;
}

int nl_l3::add_l3_neigh(struct rtnl_neigh *n) {
  int rv;
  uint32_t l3_interface_id = 0;
  struct nl_addr *addr;

  assert(n);
  if (n == nullptr)
    return -EINVAL;

  rv = add_l3_neigh_egress(n, &l3_interface_id);
  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__ << ": add l3 neigh egress failed for neigh " << OBJ_CAST(n);
    return rv;
  }

  addr = rtnl_neigh_get_dst(n);
  rofl::caddress_in4 ipv4_dst = libnl_in4addr_2_rofl(addr);

  rv = add_l3_unicast_host(ipv4_dst, l3_interface_id);
  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__ << ": add l3 unicast host failed for "
               << OBJ_CAST(n);
  }

  return rv;
}

int nl_l3::update_l3_neigh(struct rtnl_neigh *n_old, struct rtnl_neigh *n_new) {
  assert(n_old);
  assert(n_new);

  int rv = 0;
  bool state_changed =
      !(rtnl_neigh_get_state(n_old) == rtnl_neigh_get_state(n_new));
  struct nl_addr *n_ll_old;
  struct nl_addr *n_ll_new;

  int ifindex = rtnl_neigh_get_ifindex(n_old);
  uint32_t port_id = tap_man->get_port_id(ifindex);

  if (port_id == 0) {
    VLOG(1) << __FUNCTION__ << ": invalid port id=" << port_id;
    return -EINVAL;
  }

  if (!state_changed) {
    VLOG(2) << __FUNCTION__ << ": neighbour state not changed states are n_old="
            << rtnl_neigh_get_state(n_old)
            << " n_new=" << rtnl_neigh_get_state(n_new);
    return 0;
  }

  n_ll_old = rtnl_neigh_get_lladdr(n_old);
  n_ll_new = rtnl_neigh_get_lladdr(n_new);

  if (n_ll_old == nullptr && n_ll_new) {
    // XXX neighbour reachable
    VLOG(2) << __FUNCTION__ << ": neighbour ll reachable";

  } else if (n_ll_old && n_ll_new == nullptr) {
    // neighbour unreachable
    VLOG(2) << __FUNCTION__ << ": neighbour ll unreachable";

    int ifindex = rtnl_neigh_get_ifindex(n_old);
    struct rtnl_link *link = nl->get_link_by_ifindex(ifindex);
    struct nl_addr *addr;

    if (link == nullptr)
      return -EINVAL;

    addr = rtnl_neigh_get_dst(n_old);
    rofl::caddress_in4 ipv4_dst = libnl_in4addr_2_rofl(addr);

    // delete next hop
    rv = sw->l3_unicast_host_remove(ipv4_dst);
    if (rv < 0) {
      LOG(ERROR) << __FUNCTION__
                 << ": failed to remove l3 unicast host ipv4_dst" << ipv4_dst
                 << "; rv=" << rv;
      return rv;
    }

    // delete from mapping
    rv = del_l3_egress(ifindex, rtnl_link_get_addr(link),
                       rtnl_neigh_get_lladdr(n_old));

    rtnl_link_put(link);

  } else if (nl_addr_cmp(n_ll_old, n_ll_new)) {
    // XXX TODO ll addr changed
    LOG(WARNING) << __FUNCTION__ << ": neighbour ll changed (not implemented)";
  } else {
    // nothing changed besides the nud
    VLOG(2) << __FUNCTION__ << ": nud changed from "
            << rtnl_neigh_get_state(n_old) << " to "
            << rtnl_neigh_get_state(n_new); // TODO print names
  }

  return rv;
}

int nl_l3::del_l3_neigh(struct rtnl_neigh *n) {
  int rv = 0;
  struct nl_addr *addr;

  assert(n);
  if (n == nullptr)
    return -EINVAL;

  LOG(INFO) << __FUNCTION__ << ": n=" << n;

  addr = rtnl_neigh_get_dst(n);
  rofl::caddress_in4 ipv4_dst = libnl_in4addr_2_rofl(addr);

  // delete next hop
  rv = sw->l3_unicast_host_remove(ipv4_dst);
  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__ << ": failed to remove l3 unicast host ipv4_dst"
               << ipv4_dst << "; rv=" << rv;
    return rv;
  }

  // delete l3 unicast group (mac rewrite)
  int ifindex = rtnl_neigh_get_ifindex(n);
  struct rtnl_link *link = nl->get_link_by_ifindex(ifindex);

  if (link == nullptr)
    return -EINVAL;

  struct nl_addr *s_mac = rtnl_link_get_addr(link);
  struct nl_addr *d_mac = rtnl_neigh_get_lladdr(n);

  if (s_mac && d_mac)
    rv = del_l3_egress(ifindex, s_mac, d_mac);

  rtnl_link_put(link);
  return rv;
}

void nl_l3::register_switch_interface(switch_interface *sw) { this->sw = sw; }

int nl_l3::del_l3_egress(int ifindex, const struct nl_addr *s_mac,
                         const struct nl_addr *d_mac) {
  assert(s_mac);
  assert(d_mac);

  uint32_t port_id = tap_man->get_port_id(ifindex);

  if (port_id == 0) {
    VLOG(1) << __FUNCTION__ << ": invalid port_id=0 of ifindex" << ifindex;
    return -EINVAL;
  }

  int rv = 0;
  int vid = 1; // XXX TODO currently only on vid 1
  rofl::caddress_ll src_mac = libnl_lladdr_2_rofl(s_mac);
  rofl::caddress_ll dst_mac = libnl_lladdr_2_rofl(d_mac);
  auto it = l3_interface_mapping.find(
      std::make_tuple(port_id, vid, src_mac, dst_mac));

  if (it == l3_interface_mapping.end()) {
    LOG(ERROR) << __FUNCTION__
               << ": l3 interface mapping not found port_id=" << port_id
               << ", vid=" << vid << ", src_mac=" << src_mac
               << ", dst_mac=" << dst_mac;
    return -EINVAL;
  }

  it->second.refcnt--;

  if (it->second.refcnt == 0) {
    // remove egress L3 Unicast group
    rv = sw->l3_egress_remove(it->second.l3_interface_id);

    if (rv < 0) {
      LOG(ERROR) << __FUNCTION__
                 << ": failed to setup l3 egress port_id=" << port_id
                 << ", vid=" << vid << ", src_mac=" << src_mac
                 << ", dst_mac=" << dst_mac << "; rv=" << rv;
      return rv;
    }

    l3_interface_mapping.erase(it);
  }

  return rv;
}

struct rtnl_neigh *nl_l3::nexthop_resolution(struct rtnl_nexthop *nh,
                                             void *arg) {
  struct nl_addr *nh_addr;
  int ifindex;
  struct rtnl_neigh *neigh = nullptr;

  LOG(INFO) << __FUNCTION__ << ": nh: " << nh;

  ifindex = rtnl_route_nh_get_ifindex(nh);
  nh_addr = rtnl_route_nh_get_via(nh);

  if (nh_addr) {
    switch (nl_addr_get_family(nh_addr)) {
    case AF_INET:
    case AF_INET6:
      LOG(INFO) << "via " << nh_addr;
      break;
    default:
      LOG(INFO) << "via " << nh_addr
                << " unsupported family=" << nl_addr_get_family(nh_addr);
      break;
    }
    struct rtnl_neigh *n =
        nl->get_neighbour(ifindex, nh_addr);
    LOG(INFO) << __FUNCTION__ << "; found neighbour: " << n;
    rtnl_neigh_put(n);
  } else {
    LOG(INFO) << "no via";
  }

  nh_addr = rtnl_route_nh_get_gateway(nh);

  if (nh_addr) {
    switch (nl_addr_get_family(nh_addr)) {
    case AF_INET:
    case AF_INET6:
      LOG(INFO) << "gw " << nh_addr;
      break;
    default:
      LOG(INFO) << "gw " << nh_addr
                << " unsupported family=" << nl_addr_get_family(nh_addr);
      break;
    }

    neigh = nl->get_neighbour(ifindex, nh_addr);
  }
  return neigh;
}

int nl_l3::add_l3_route(struct rtnl_route *r) {
  int rv = 0;
  int nnhs = rtnl_route_get_nnexthops(r);
  struct nl_list_head *nh_list = rtnl_route_get_nexthops(r);
  std::deque<struct rtnl_neigh *> neighs;

  LOG(INFO) << __FUNCTION__ << ": nnhs=" << nnhs;

  if (nh_list) {
    std::pair<nl_l3 *, std::deque<struct rtnl_neigh *> *> data =
        std::make_pair(this, &neighs);
    rtnl_route_foreach_nexthop(
        r,
        [](struct rtnl_nexthop *nh, void *arg) {
          std::pair<nl_l3 *, std::deque<struct rtnl_neigh *> *> *data =
              static_cast<
                  std::pair<nl_l3 *, std::deque<struct rtnl_neigh *> *> *>(arg);
          std::deque<struct rtnl_neigh *> *neighs = data->second;

          struct rtnl_neigh *neigh =
              static_cast<nl_l3 *>(arg)->nexthop_resolution(nh, nullptr);
          if (neigh) {
            LOG(INFO) << __FUNCTION__ << "; found neighbour: "
                      << reinterpret_cast<struct nl_object *>(neigh);
            neighs->push_back(neigh);
          }
        },
        &data);

    if (neighs.size()) {
      uint32_t l3_interface_id = 0;
      if (nnhs == 1) {
        // add neigh
        struct rtnl_neigh *n = neighs.front();
        rv = add_l3_neigh_egress(n, &l3_interface_id);
        if (rv < 0) {
          LOG(ERROR) << __FUNCTION__
                     << ": add l3 neigh egress failed for neigh "
                     << OBJ_CAST(n);
          return rv;
        }

        // add route
        rofl::caddress_in4 ipv4_dst;
        rofl::caddress_in4 mask;
        rv = add_l3_unicast_route(ipv4_dst, mask, l3_interface_id);

      } else {
        // ecmp
        LOG(WARNING) << __FUNCTION__ << ": ecmp is not supported";
      }
    }

    // clean up neighbours in neighs deqeue
    for (auto neigh : neighs) {
      rtnl_neigh_put(neigh);
    }
    neighs.clear();

  } else {
    LOG(INFO) << __FUNCTION__ << ": no nexthop for this route";
  }

  struct nl_addr *addr = rtnl_route_get_dst(r);

  if (addr) {
    LOG(INFO) << __FUNCTION__ << ": dst=" << addr;
  } else {
    LOG(INFO) << __FUNCTION__ << ": dst not set";
  }

  return rv;
}

int nl_l3::del_l3_route(struct rtnl_route *r) {
  int rv = 0;
  LOG(FATAL) << __FUNCTION__ << ": not implemented";
  return rv;
}

} // namespace basebox
