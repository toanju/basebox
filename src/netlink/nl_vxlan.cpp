#include <cassert>
#include <deque>
#include <string>
#include <tuple>
#include <unordered_map>

#include <netlink/route/link.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/link/bridge.h>
#include <netlink/route/link/vxlan.h>

#include "cnetlink.hpp"
#include "netlink-utils.hpp"
#include "nl_hashing.hpp"
#include "nl_l3.hpp"
#include "nl_output.hpp"
#include "nl_route_query.hpp"
#include "nl_vxlan.hpp"
#include "tap_manager.hpp"

namespace basebox {

struct pport_vlan {
  uint32_t pport;
  uint16_t vid;

  pport_vlan(uint32_t pport, uint16_t vid) : pport(pport), vid(vid) {}

  bool operator<(const pport_vlan &rhs) const {
    return std::tie(pport, vid) < std::tie(rhs.pport, rhs.vid);
  }

  bool operator==(const pport_vlan &rhs) const {
    return std::tie(pport, vid) == std::tie(rhs.pport, rhs.vid);
  }
};

struct access_tunnel_port {
  uint32_t lport_id;
  int tunnel_id;

  access_tunnel_port(int lport_id, int tunnel_id)
      : lport_id(lport_id), tunnel_id(tunnel_id) {}
};

struct tunnel_nh {
  uint64_t smac;
  uint64_t dmac;
  pport_vlan pv;

  tunnel_nh(uint64_t smac, uint64_t dmac, uint32_t pport, uint16_t vid)
      : smac(smac), dmac(dmac), pv(pport, vid) {}

  bool operator<(const tunnel_nh &rhs) const {
    return std::tie(smac, dmac, pv) < std::tie(rhs.smac, rhs.dmac, rhs.pv);
  }

  bool operator==(const tunnel_nh &rhs) const {
    return std::tie(smac, dmac, pv) == std::tie(rhs.smac, rhs.dmac, rhs.pv);
  }
};

struct tunnel_nh_port {
  int refcnt;
  uint32_t nh_id;
  tunnel_nh_port(uint32_t nh_id) : refcnt(1), nh_id(nh_id) {}
};

struct endpoint_port {
  uint32_t local_ipv4;
  uint32_t remote_ipv4;
  uint32_t initiator_udp_dst_port;

  endpoint_port(uint32_t local_ipv4, uint32_t remote_ipv4,
                uint32_t initiator_udp_dst_port)
      : local_ipv4(local_ipv4), remote_ipv4(remote_ipv4),
        initiator_udp_dst_port(initiator_udp_dst_port) {}

  bool operator<(const endpoint_port &rhs) const {
    return std::tie(local_ipv4, remote_ipv4, initiator_udp_dst_port) <
           std::tie(rhs.local_ipv4, rhs.remote_ipv4,
                    rhs.initiator_udp_dst_port);
  }

  bool operator==(const endpoint_port &rhs) const {
    return std::tie(local_ipv4, remote_ipv4, initiator_udp_dst_port) ==
           std::tie(rhs.local_ipv4, rhs.remote_ipv4,
                    rhs.initiator_udp_dst_port);
  }
};

struct endpoint_tunnel_port {
  int refcnt; // counts direct usage of l2 addresses and all zero address
  uint32_t lport_id;
  uint32_t nh_id;
  endpoint_tunnel_port(uint32_t lport_id, uint32_t nh_id)
      : refcnt(1), lport_id(lport_id), nh_id(nh_id) {}
};

} // namespace basebox

namespace std {

template <> struct hash<basebox::pport_vlan> {
  typedef basebox::pport_vlan argument_type;
  typedef std::size_t result_type;
  result_type operator()(argument_type const &v) const noexcept {
    size_t seed = 0;
    hash_combine(seed, v.pport);
    hash_combine(seed, v.vid);
    return seed;
  }
};

template <> struct hash<basebox::tunnel_nh> {
  typedef basebox::tunnel_nh argument_type;
  typedef std::size_t result_type;
  result_type operator()(argument_type const &v) const noexcept {
    size_t seed = 0;
    hash_combine(seed, v.smac);
    hash_combine(seed, v.dmac);
    hash_combine(seed, v.pv);
    return seed;
  }
};

template <> struct hash<basebox::endpoint_port> {
  typedef basebox::endpoint_port argument_type;
  typedef std::size_t result_type;
  result_type operator()(argument_type const &v) const noexcept {
    size_t seed = 0;
    hash_combine(seed, v.local_ipv4);
    hash_combine(seed, v.remote_ipv4);
    hash_combine(seed, v.initiator_udp_dst_port);
    return seed;
  }
};

} // namespace std

namespace basebox {

static std::unordered_multimap<pport_vlan, access_tunnel_port> access_port_ids;

static std::unordered_multimap<tunnel_nh, tunnel_nh_port> tunnel_next_hop_id;

static std::unordered_multimap<endpoint_port, endpoint_tunnel_port> endpoint_id;

static std::map<uint32_t, tunnel_nh> tunnel_next_hop2tnh;

static struct access_tunnel_port get_access_tunnel_port(uint32_t pport,
                                                        uint16_t vlan) {
  assert(pport);
  assert(vlan);

  VLOG(2) << __FUNCTION__
          << ": trying to find access tunnel_port for pport=" << pport
          << ", vlan=" << vlan;

  pport_vlan search(pport, vlan);
  auto port_range = access_port_ids.equal_range(search);
  access_tunnel_port invalid(0, 0);

  for (auto it = port_range.first; it != port_range.second; ++it) {
    if (it->first == search) {
      VLOG(2) << __FUNCTION__
              << ": found tunnel_port port_id=" << it->second.lport_id
              << ", tunnel_id=" << it->second.tunnel_id;
      return it->second;
    }
  }

  LOG(WARNING) << __FUNCTION__ << ": no pport_vlan matched on pport=" << pport
               << ", vlan=" << vlan;
  return invalid;
}

nl_vxlan::nl_vxlan(std::shared_ptr<tap_manager> tap_man,
                   std::shared_ptr<nl_l3> l3, cnetlink *nl)
    : sw(nullptr), tap_man(tap_man), l3(l3), nl(nl) {}

void nl_vxlan::register_switch_interface(switch_interface *sw) {
  this->sw = sw;
}

// XXX TODO alter this function to pass the vni instead of tunnel_id
int nl_vxlan::create_access_port(rtnl_link *br_link, uint32_t tunnel_id,
                                 const std::string &access_port_name,
                                 uint32_t pport_no, uint16_t vid, bool untagged,
                                 uint32_t *lport) {
  assert(sw);

  // lookup access port if it is already configured
  auto tp = get_access_tunnel_port(pport_no, vid);
  if (tp.lport_id || tp.tunnel_id) {
    VLOG(1) << __FUNCTION__
            << ": tunnel port already exists (lport_id=" << tp.lport_id
            << ", tunnel_id=" << tp.tunnel_id << "), tunnel_id=" << tunnel_id
            << ", access_port_name=" << access_port_name
            << ", pport_no=" << pport_no << ", vid=" << vid
            << ", untagged=" << untagged;
    return -EINVAL;
  }

  std::string port_name = access_port_name;
  port_name += "." + std::to_string(vid);

  // drop all vlans on port
  sw->egress_bridge_port_vlan_remove(pport_no, vid);
  sw->ingress_port_vlan_remove(pport_no, vid, untagged);

  int rv = 0;
  int cnt = 0;
  do {
    VLOG(2) << __FUNCTION__ << ": rv=" << rv << ", cnt=" << cnt << std::showbase
            << std::hex << ", port_id=" << port_id_cnt
            << ", port_name=" << port_name << std::dec
            << ", pport_no=" << pport_no << ", vid=" << vid
            << ", untagged=" << untagged;
    // XXX TODO this is totally crap even if it works for now
    rv = sw->tunnel_access_port_create(port_id_cnt, port_name, pport_no, vid,
                                       untagged);

    cnt++;
  } while (rv < 0 && cnt < 100);

  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__
               << ": failed to create access port tunnel_id=" << tunnel_id
               << ", vid=" << vid << ", port:" << access_port_name;
    return rv;
  }

  VLOG(2) << __FUNCTION__
          << ": call tunnel_port_tenant_add port_id=" << port_id_cnt
          << ", tunnel_id=" << tunnel_id;
  rv = sw->tunnel_port_tenant_add(port_id_cnt, tunnel_id);

  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__ << ": failed to add tunnel port " << port_id_cnt
               << " to tenant " << tunnel_id;
    delete_access_port(pport_no, vid, false);
    return rv;
  }

  rv = configure_flooding(br_link, tunnel_id, port_id_cnt);

  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__
               << ": failed to add flooding for lport=" << port_id_cnt
               << " in tenant=" << tunnel_id;
    disable_flooding(br_link, tunnel_id, port_id_cnt); // TODO needed?
    sw->tunnel_port_tenant_remove(port_id_cnt, tunnel_id);
    delete_access_port(pport_no, vid, false);
    return rv;
  }

  // XXX TODO check if access port is already existing?
  access_port_ids.emplace(std::make_pair(
      pport_vlan(pport_no, vid), access_tunnel_port(port_id_cnt, tunnel_id)));

  // optionally return lport
  if (lport)
    *lport = port_id_cnt;

  port_id_cnt++;

  return 0;
}

int nl_vxlan::delete_access_port(uint32_t pport_no, uint16_t vid,
                                 bool wipe_l2_addresses) {
  pport_vlan search(pport_no, vid);
  auto port_range = access_port_ids.equal_range(search);
  auto it = port_range.first;

  for (; it != port_range.second; ++it) {
    if (it->first == search) {
      VLOG(2) << __FUNCTION__
              << ": found tunnel_port lport_id=" << it->second.lport_id
              << ", tunnel_id=" << it->second.tunnel_id;
      break;
    }
  }

  if (it == access_port_ids.end()) {
    VLOG(1) << __FUNCTION__ << ": no port found for pport_no=" << pport_no
            << ", vid=" << vid;
    return 0;
  }

  if (wipe_l2_addresses) {
    sw->l2_overlay_addr_remove(it->second.tunnel_id, it->second.lport_id,
                               rofl::caddress_ll("ff:ff:ff:ff:ff:ff"));
  }

  sw->tunnel_port_tenant_remove(it->second.lport_id, it->second.tunnel_id);
  sw->tunnel_port_delete(it->second.lport_id);

  access_port_ids.erase(it);

  return 0;
}

int nl_vxlan::get_tunnel_id(rtnl_link *vxlan_link,
                            uint32_t *_tunnel_id) noexcept {
  assert(vxlan_link);

  uint32_t vni = 0;

  if (rtnl_link_vxlan_get_id(vxlan_link, &vni) != 0) {
    LOG(ERROR) << __FUNCTION__ << ": no valid vxlan interface " << vxlan_link;
    return -EINVAL;
  }

  return get_tunnel_id(vni, _tunnel_id);
}

int nl_vxlan::get_tunnel_id(uint32_t vni, uint32_t *_tunnel_id) noexcept {
  auto tunnel_id_it = vni2tunnel.find(vni);
  if (tunnel_id_it == vni2tunnel.end()) {
    LOG(ERROR) << __FUNCTION__ << ": got no tunnel_id for vni=" << vni;
    return -EINVAL;
  }

  *_tunnel_id = tunnel_id_it->second;

  return 0;
}

int nl_vxlan::create_vni(rtnl_link *link, uint32_t *tunnel_id) {
  uint32_t vni = 0;
  int rv = rtnl_link_vxlan_get_id(link, &vni);

  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__ << ": no vni for vxlan interface set";
    return -EINVAL;
  }

  // create tenant on switch
  rv = sw->tunnel_tenant_create(this->tunnel_id_cnt, vni);

  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__
               << ": failed to create tunnel tenant tunnel_id=" << tunnel_id
               << ", vni=" << vni << ", rv=" << rv;
    return -EINVAL;
  }

  // enable tunnel_id
  rv = sw->overlay_tunnel_add(this->tunnel_id_cnt);

  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__
               << ": failed to add overlay tunnel tunnel_id=" << tunnel_id
               << ", rv=" << rv;
    sw->tunnel_tenant_delete(this->tunnel_id_cnt);
    return -EINVAL;
  }

  vni2tunnel.emplace(vni, this->tunnel_id_cnt);
  *tunnel_id = this->tunnel_id_cnt++;

  return rv;
}

int nl_vxlan::remove_vni(rtnl_link *link) {
  uint32_t vni = 0;
  int rv = rtnl_link_vxlan_get_id(link, &vni);

  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__ << ": no vni for vxlan interface set";
    return -EINVAL;
  }

  auto v2t_it = vni2tunnel.find(vni);

  if (v2t_it == vni2tunnel.end()) {
    LOG(ERROR) << __FUNCTION__ << ": counld not delete vni " << OBJ_CAST(link);
    return -EINVAL;
  }

  rv = sw->overlay_tunnel_remove(v2t_it->second);

  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__ << ": failed with rv=" << rv
               << " to remove overlay tunnel tunnel_id=" << v2t_it->second;
    /* fall through and try to delete tenant anyway */
  }

  rv = sw->tunnel_tenant_delete(v2t_it->second);

  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__ << ": failed  with rv = " << rv
               << "to delete vni " << vni << " used for tenant "
               << v2t_it->second;
    return rv;
  }

  vni2tunnel.erase(v2t_it);

  return 0;
}

int nl_vxlan::create_endpoint(rtnl_link *vxlan_link, uint32_t tunnel_id) {
  assert(vxlan_link);

  std::thread rqt;
  // get group/remote addr
  nl_addr *addr = nullptr;
  int rv = rtnl_link_vxlan_get_group(vxlan_link, &addr);

  if (rv < 0) {
    VLOG(1) << __FUNCTION__ << ": no peer configured";
    return 0;
  }

  if (addr == nullptr) {
    LOG(ERROR) << __FUNCTION__ << ": no group/remote for vxlan interface set";
    return -EINVAL;
  }

  std::unique_ptr<nl_addr, void (*)(nl_addr *)> group_(addr, &nl_addr_put);

  if (nl_addr_get_family(addr) == AF_INET6) {
    LOG(ERROR) << __FUNCTION__
               << ": detected unsupported IPv6 remote for vxlan "
               << OBJ_CAST(vxlan_link);
    return -ENOTSUP;
  }

  create_endpoint(vxlan_link, nullptr, std::move(group_), tunnel_id);

  return 0;
}

int nl_vxlan::create_endpoint(
    rtnl_link *vxlan_link, rtnl_link *br_link,
    std::unique_ptr<nl_addr, void (*)(nl_addr *)> remote_addr,
    uint32_t tunnel_id) {
  assert(vxlan_link);

  uint32_t lport_id = 0;
  int family = nl_addr_get_family(remote_addr.get());

  // XXX TODO check for multicast here, not yet supported

  if (family != AF_INET) {
    LOG(ERROR) << __FUNCTION__ << ": currently only AF_INET is supported";
    return -EINVAL;
  }

  nl_addr *tmp_addr = nullptr;
  int rv = rtnl_link_vxlan_get_local(vxlan_link, &tmp_addr);

  if (rv != 0 || tmp_addr == nullptr) {
    LOG(ERROR) << __FUNCTION__ << ": no local address for vxlan interface set";
    return -EINVAL;
  }

  std::unique_ptr<nl_addr, void (*)(nl_addr *)> local_(tmp_addr, &nl_addr_put);

  family = nl_addr_get_family(local_.get());

  if (family != AF_INET) {
    LOG(ERROR) << __FUNCTION__ << ": currently only AF_INET is supported";
    return -EINVAL;
  }

  // XXX TODO could all be moved to create next hop
  // spin off a thread to query the next hop
  std::packaged_task<struct rtnl_route *(struct nl_addr *)> task(
      [](struct nl_addr *addr) {
        nl_route_query rq;
        return rq.query_route(addr);
      });
  std::future<struct rtnl_route *> result = task.get_future();
  std::thread(std::move(task), remote_addr.get()).detach();

  VLOG(4) << __FUNCTION__ << ": wait for rq_task to finish";
  result.wait();
  VLOG(4) << __FUNCTION__ << ": rq_task finished";
  std::unique_ptr<rtnl_route, void (*)(rtnl_route *)> route(result.get(),
                                                            &rtnl_route_put);

  if (route.get() == nullptr) {
    LOG(ERROR) << __FUNCTION__ << ": could not retrieve route to "
               << remote_addr.get();
    return -EINVAL;
  }

  VLOG(2) << __FUNCTION__ << ": route " << OBJ_CAST(route.get());

  int nnh = rtnl_route_get_nnexthops(route.get());

  if (nnh > 1) {
    // ecmp
    LOG(WARNING) << __FUNCTION__
                 << ": ecmp not supported, only first next hop will be used.";
  }

  std::deque<struct rtnl_neigh *> neighs;
  nl_l3::nh_lookup_params p = {&neighs, route.get(), nl};

  l3->get_neighbours_of_route(route.get(), &p);

  if (neighs.size() == 0) {
    LOG(ERROR) << __FUNCTION__ << ": neighs.size()=" << neighs.size();
    return -ENOTSUP;
  }

  std::unique_ptr<rtnl_neigh, void (*)(rtnl_neigh *)> neigh_(neighs.front(),
                                                             &rtnl_neigh_put);
  neighs.pop_front();

  // clean others
  for (auto n : neighs)
    rtnl_neigh_put(n);

  uint32_t _next_hop_id = 0;
  rv = create_next_hop(neigh_.get(), &_next_hop_id);
  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__ << ": failed to create next hop "
               << OBJ_CAST(neigh_.get());
    return -EINVAL;
  }

  rv = create_endpoint(vxlan_link, local_.get(), remote_addr.get(),
                       _next_hop_id, &lport_id);
  if (rv < 0) {
    delete_next_hop(neigh_.get());
    LOG(ERROR) << __FUNCTION__ << ": failed to create endpoint";
    return -EINVAL;
  }

  rv = sw->tunnel_port_tenant_add(lport_id, tunnel_id);
  if (rv < 0) {
    delete_endpoint(vxlan_link, local_.get(), remote_addr.get());
    delete_next_hop(neigh_.get());
    LOG(ERROR) << __FUNCTION__ << ": tunnel_port_tenant_add returned rv=" << rv
               << " for lport_id=" << lport_id << " tunnel_id=" << tunnel_id;
    return -EINVAL;
  }

  rv = configure_flooding(br_link, tunnel_id, lport_id);
  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__
               << ": failed to add flooding for lport=" << lport_id
               << " in tenant=" << tunnel_id;
    disable_flooding(br_link, tunnel_id, lport_id);
    sw->tunnel_port_tenant_remove(lport_id, tunnel_id);
    delete_endpoint(vxlan_link, local_.get(), remote_addr.get());
    delete_next_hop(neigh_.get());
  }

  return rv;
}

int nl_vxlan::configure_flooding(rtnl_link *br_link, uint32_t tunnel_id,
                                 uint32_t lport_id) {
  int rv = 0;
  bool enable_flooding = true; // TODO shall this be enabled by default?

  if (br_link) {
    int flags = rtnl_link_bridge_get_flags(br_link);
    if (!(flags & RTNL_BRIDGE_UNICAST_FLOOD)) {
      // flooding not set
      enable_flooding = false;
    }
  }

  if (enable_flooding) {
    VLOG(1) << __FUNCTION__ << ": enable flooding on lport_id=" << lport_id
            << ", tunnel_id=" << tunnel_id;
    rv = sw->add_l2_overlay_flood(tunnel_id, lport_id);
    if (rv < 0) {
      LOG(ERROR) << __FUNCTION__ << ": failed to add tunnel port "
                 << port_id_cnt << " to flooding for tenant " << tunnel_id;
      return -EINVAL;
    }
  }

  return rv;
}

int nl_vxlan::disable_flooding(rtnl_link *br_link, uint32_t tunnel_id,
                               uint32_t lport_id) {
  int rv = 0;
  bool disable_flooding = true; // TODO shall this be enabled by default?

  if (br_link) {
    int flags = rtnl_link_bridge_get_flags(br_link);
    if (!(flags & RTNL_BRIDGE_UNICAST_FLOOD)) {
      // flooding not set
      disable_flooding = false;
    }
  }

  if (disable_flooding) {
    VLOG(1) << __FUNCTION__ << ": enable flooding on lport_id=" << lport_id
            << ", tunnel_id=" << tunnel_id;
    rv = sw->del_l2_overlay_flood(tunnel_id, lport_id);
    if (rv < 0) {
      LOG(ERROR) << __FUNCTION__ << ": failed to add tunnel port "
                 << port_id_cnt << " to flooding for tenant " << tunnel_id;
      return -EINVAL;
    }
  }

  return rv;
}

int nl_vxlan::create_endpoint(rtnl_link *vxlan_link, nl_addr *local_,
                              nl_addr *group_, uint32_t _next_hop_id,
                              uint32_t *lport_id) {
  assert(group_);
  assert(local_);
  assert(vxlan_link);

  int ttl = rtnl_link_vxlan_get_ttl(vxlan_link);

  if (ttl == 0)
    ttl = 45; // XXX TODO is this a sane default?

  uint32_t remote_ipv4 = 0;
  memcpy(&remote_ipv4, nl_addr_get_binary_addr(group_), sizeof(remote_ipv4));
  remote_ipv4 = ntohl(remote_ipv4);

  uint32_t local_ipv4 = 0;
  memcpy(&local_ipv4, nl_addr_get_binary_addr(local_), sizeof(local_ipv4));
  local_ipv4 = ntohl(local_ipv4);

  uint32_t initiator_udp_dst_port = 4789;
  int rv = rtnl_link_vxlan_get_port(vxlan_link, &initiator_udp_dst_port);
  if (rv != 0) {
    LOG(WARNING) << __FUNCTION__
                 << ": vxlan dstport not specified. Falling back to "
                 << initiator_udp_dst_port;
  }

  uint32_t terminator_udp_dst_port = 4789;
  bool use_entropy = true;
  uint32_t udp_src_port_if_no_entropy = 0;

  auto ep = endpoint_port(local_ipv4, remote_ipv4, initiator_udp_dst_port);
  auto ep_it = endpoint_id.equal_range(ep);

  for (auto it = ep_it.first; it != ep_it.second; ++it) {
    if (it->first == ep) {
      VLOG(1) << __FUNCTION__
              << ": found an endpoint_port lport_id=" << it->second.lport_id;
      *lport_id = it->second.lport_id;
      it->second.refcnt++;
      return 0;
    }
  }

  // create endpoint port
  VLOG(2) << __FUNCTION__ << std::hex << std::showbase
          << ": calling tunnel_enpoint_create lport_id=" << lport_id
          << ", name=" << rtnl_link_get_name(vxlan_link)
          << ", remote=" << remote_ipv4 << ", local=" << local_ipv4
          << ", ttl=" << ttl << ", next_hop_id=" << _next_hop_id
          << ", terminator_udp_dst_port=" << terminator_udp_dst_port
          << ", initiator_udp_dst_port=" << initiator_udp_dst_port
          << ", use_entropy=" << use_entropy;
  rv = sw->tunnel_enpoint_create(
      this->port_id_cnt, std::string(rtnl_link_get_name(vxlan_link)),
      remote_ipv4, local_ipv4, ttl, _next_hop_id, terminator_udp_dst_port,
      initiator_udp_dst_port, udp_src_port_if_no_entropy, use_entropy);

  if (rv != 0) {
    LOG(ERROR) << __FUNCTION__
               << ": failed to create tunnel enpoint lport_id=" << std::hex
               << std::showbase << lport_id
               << ", name=" << rtnl_link_get_name(vxlan_link)
               << ", remote=" << remote_ipv4 << ", local=" << local_ipv4
               << ", ttl=" << ttl << ", next_hop_id=" << _next_hop_id
               << ", terminator_udp_dst_port=" << terminator_udp_dst_port
               << ", initiator_udp_dst_port=" << initiator_udp_dst_port
               << ", use_entropy=" << use_entropy << ", rv=" << rv;
    return -EINVAL;
  }

  endpoint_id.emplace(ep,
                      endpoint_tunnel_port(this->port_id_cnt, _next_hop_id));
  *lport_id = this->port_id_cnt++;
  return 0;
}

int nl_vxlan::delete_endpoint(rtnl_link *vxlan_link, nl_addr *local_,
                              nl_addr *group_) {
  assert(group_);
  assert(local_);
  assert(vxlan_link);

  uint32_t remote_ipv4 = 0;
  memcpy(&remote_ipv4, nl_addr_get_binary_addr(group_), sizeof(remote_ipv4));
  remote_ipv4 = ntohl(remote_ipv4);

  uint32_t local_ipv4 = 0;
  memcpy(&local_ipv4, nl_addr_get_binary_addr(local_), sizeof(local_ipv4));
  local_ipv4 = ntohl(local_ipv4);

  uint32_t initiator_udp_dst_port = 4789;
  int rv = rtnl_link_vxlan_get_port(vxlan_link, &initiator_udp_dst_port);
  if (rv != 0) {
    LOG(WARNING) << __FUNCTION__
                 << ": vxlan dstport not specified. Falling back to "
                 << initiator_udp_dst_port;
  }

  auto ep = endpoint_port(local_ipv4, remote_ipv4, initiator_udp_dst_port);
  auto ep_it = endpoint_id.equal_range(ep);

  if (ep_it.first == endpoint_id.end()) {
    LOG(ERROR)
        << __FUNCTION__
        << ": endpoint not found having the following parameter local addr "
        << local_ << ", remote addr " << group_ << ", on link "
        << OBJ_CAST(vxlan_link);
    return -EINVAL;
  }

  auto it = ep_it.first;

  for (; it != ep_it.second; ++it) {
    if (it->first == ep) {
      VLOG(1) << __FUNCTION__
              << ": found an endpoint_port lport_id=" << it->second.lport_id;
      it->second.refcnt--;
      break;
    }
  }

  if (it->second.refcnt == 0) {
    VLOG(1) << __FUNCTION__
            << ": deleting endpoint_port lport_id=" << it->second.lport_id;
    rv = sw->tunnel_port_delete(it->second.lport_id);

    endpoint_id.erase(it);
  }

  return rv;
}
int nl_vxlan::create_next_hop(rtnl_neigh *neigh, uint32_t *_next_hop_id) {
  int rv;

  assert(neigh);
  assert(next_hop_id_cnt);

  // get outgoing interface
  uint32_t ifindex = rtnl_neigh_get_ifindex(neigh);
  rtnl_link *local_link = nl->get_link_by_ifindex(ifindex);

  if (local_link == nullptr) {
    LOG(ERROR) << __FUNCTION__ << ": invalid link ifindex=" << ifindex;
    return -EINVAL;
  }

  uint32_t physical_port = nl->get_port_id(local_link);

  if (physical_port == 0) {
    LOG(ERROR) << __FUNCTION__ << ": no port_id for ifindex=" << ifindex;
    return -EINVAL;
  }

  nl_addr *addr = rtnl_link_get_addr(local_link);
  if (addr == nullptr) {
    LOG(ERROR) << __FUNCTION__ << ": invalid link (no ll addr) "
               << OBJ_CAST(local_link);
    return -EINVAL;
  }

  uint64_t src_mac = nlall2uint64(addr);

  // get neigh and set dst_mac
  addr = rtnl_neigh_get_lladdr(neigh);
  if (addr == nullptr) {
    LOG(ERROR) << __FUNCTION__ << ": invalid neigh (no ll addr) "
               << OBJ_CAST(neigh);
    return -EINVAL;
  }

  uint64_t dst_mac = nlall2uint64(addr);
  uint16_t vlan_id = 1; // XXX FIXME currently hardcoded to vid 1

  auto tnh = tunnel_nh(src_mac, dst_mac, physical_port, vlan_id);
  auto tnh_it = tunnel_next_hop_id.equal_range(tnh);

  for (auto it = tnh_it.first; it != tnh_it.second; ++it) {
    if (it->first == tnh) {
      VLOG(1) << __FUNCTION__
              << ": found a tunnel next hop match using next_hop_id="
              << it->second.nh_id;
      *_next_hop_id = it->second.nh_id;
      it->second.refcnt++;
      return 0;
    }
  }

  // create next hop
  VLOG(2) << __FUNCTION__ << std::hex << std::showbase
          << ": calling tunnel_next_hop_create next_hop_id=" << next_hop_id_cnt
          << ", src_mac=" << src_mac << ", dst_mac=" << dst_mac
          << ", physical_port=" << physical_port << ", vlan_id=" << vlan_id;
  rv = sw->tunnel_next_hop_create(next_hop_id_cnt, src_mac, dst_mac,
                                  physical_port, vlan_id);

  if (rv < 0) {
    LOG(ERROR) << __FUNCTION__ << ": tunnel_next_hop_create returned rv=" << rv
               << " for the following parameter: next_hop_id="
               << next_hop_id_cnt << ", src_mac=" << src_mac
               << ", dst_mac=" << dst_mac << ", physical_port=" << physical_port
               << ", vlan_id=" << vlan_id;
    return rv;
  }

  tunnel_next_hop_id.emplace(tnh, next_hop_id_cnt);
  tunnel_next_hop2tnh.emplace(next_hop_id_cnt, tnh);
  *_next_hop_id = next_hop_id_cnt++;

  return rv;
}

int nl_vxlan::delete_next_hop(rtnl_neigh *neigh) {
  assert(neigh);
  assert(next_hop_id_cnt);

  // get outgoing interface
  uint32_t ifindex = rtnl_neigh_get_ifindex(neigh);
  rtnl_link *local_link = nl->get_link_by_ifindex(ifindex);

  if (local_link == nullptr) {
    LOG(ERROR) << __FUNCTION__ << ": invalid link ifindex=" << ifindex;
    return -EINVAL;
  }

  uint32_t physical_port = nl->get_port_id(local_link);

  if (physical_port == 0) {
    LOG(ERROR) << __FUNCTION__ << ": no port_id for ifindex=" << ifindex;
    return -EINVAL;
  }

  nl_addr *addr = rtnl_link_get_addr(local_link);
  if (addr == nullptr) {
    LOG(ERROR) << __FUNCTION__ << ": invalid link (no ll addr) "
               << OBJ_CAST(local_link);
    return -EINVAL;
  }

  uint64_t src_mac = nlall2uint64(addr);

  // get neigh and set dst_mac
  addr = rtnl_neigh_get_lladdr(neigh);
  if (addr == nullptr) {
    LOG(ERROR) << __FUNCTION__ << ": invalid neigh (no ll addr) "
               << OBJ_CAST(neigh);
    return -EINVAL;
  }

  uint64_t dst_mac = nlall2uint64(addr);
  uint16_t vlan_id = 1; // XXX FIXME currently hardcoded to vid 1
  auto tnh = tunnel_nh(src_mac, dst_mac, physical_port, vlan_id);
  auto tnh_it = tunnel_next_hop_id.equal_range(tnh);
  auto it = tnh_it.first;
  bool found = false;

  for (; it != tnh_it.second; ++it) {
    if (it->first == tnh) {
      VLOG(1) << __FUNCTION__
              << ": found a tunnel next hop match using next_hop_id="
              << it->second.nh_id;
      it->second.refcnt--;
      found = true;
      break;
    }
  }

  if (!found) {
    LOG(WARNING) << __FUNCTION__ << ": tried to delete invalid next hop";
    return -EINVAL;
  }

  if (it->second.refcnt == 0) {
    int rv = sw->tunnel_next_hop_delete(it->second.nh_id);

    if (rv < 0) {
      LOG(ERROR) << __FUNCTION__ << ": failed to delete next hop next_hop_id="
                 << it->second.nh_id;
    }

    tunnel_next_hop2tnh.erase(it->second.nh_id);
    tunnel_next_hop_id.erase(it);
  }

  return 0;
}

int nl_vxlan::delete_next_hop(uint32_t nh_id) {
  auto nh2tnh_it = tunnel_next_hop2tnh.find(nh_id);

  if (nh2tnh_it == tunnel_next_hop2tnh.end()) {
    LOG(WARNING) << __FUNCTION__ << ": tired to delete next hop id " << nh_id;
    return -ENODATA;
  }

  bool found = false;
  auto tnh = tunnel_nh(nh2tnh_it->second.smac, nh2tnh_it->second.dmac,
                       nh2tnh_it->second.pv.pport, nh2tnh_it->second.pv.vid);
  auto tnh_it = tunnel_next_hop_id.equal_range(tnh);

  auto it = tnh_it.first;
  for (; it != tnh_it.second; ++it) {
    if (it->first == tnh) {
      VLOG(1) << __FUNCTION__
              << ": found a tunnel next hop match using next_hop_id="
              << it->second.nh_id;

      assert(nh_id == it->second.nh_id);
      it->second.refcnt--;
      found = true;
      break;
    }
  }

  if (!found) {
    LOG(WARNING) << __FUNCTION__
                 << ": tried to delete invalid next hop nh_id=" << nh_id;
    return -EINVAL;
  }

  if (it->second.refcnt == 0) {
    tunnel_next_hop2tnh.erase(nh2tnh_it);
    tunnel_next_hop_id.erase(it);
  }

  return 0;
}

int nl_vxlan::add_l2_neigh(rtnl_neigh *neigh, rtnl_link *vxlan_link,
                           rtnl_link *br_link) {
  assert(vxlan_link);
  assert(neigh);
  assert(rtnl_link_get_family(vxlan_link) == AF_UNSPEC); // the vxlan interface

  uint32_t lport = 0;
  uint32_t tunnel_id = 0;
  enum link_type lt = kind_to_link_type(rtnl_link_get_type(vxlan_link));
  auto neigh_mac = rtnl_neigh_get_lladdr(neigh);
  auto link_mac = rtnl_link_get_addr(vxlan_link);

  if (nl_addr_cmp(neigh_mac, link_mac) == 0) {
    VLOG(2) << __FUNCTION__ << ": ignoring interface address of link "
            << OBJ_CAST(vxlan_link);
    return -ENOTSUP;
  }

  switch (lt) {
    /* find according endpoint port */
  case LT_VXLAN: {

    LOG(INFO) << __FUNCTION__ << ": add neigh " << OBJ_CAST(neigh)
              << " on vxlan interface " << OBJ_CAST(vxlan_link);

    uint32_t vni;
    int rv = rtnl_link_vxlan_get_id(vxlan_link, &vni);

    if (rv < 0) {
      LOG(FATAL) << __FUNCTION__ << ": something went south";
      return -EINVAL;
    }

    uint32_t dst_port;

    rv = rtnl_link_vxlan_get_port(vxlan_link, &dst_port);

    if (rv < 0) {
      LOG(FATAL) << __FUNCTION__ << ": something went south";
      return -EINVAL;
    }

    nl_addr *local;

    rv = rtnl_link_vxlan_get_local(vxlan_link, &local);

    if (rv < 0) {
      LOG(ERROR) << __FUNCTION__ << "local addr not set";
      return -EINVAL;
    }

    std::unique_ptr<nl_addr, void (*)(nl_addr *)> local_(local, &nl_addr_put);
    int family = nl_addr_get_family(local_.get());

    if (family != AF_INET) {
      LOG(ERROR) << __FUNCTION__ << ": currently only AF_INET is supported";
      return -EINVAL;
    }

    uint32_t local_ipv4 = 0;

    memcpy(&local_ipv4, nl_addr_get_binary_addr(local_.get()),
           sizeof(local_ipv4));
    local_ipv4 = ntohl(local_ipv4);

    auto v2t_it = vni2tunnel.find(vni);

    if (v2t_it == vni2tunnel.end()) {
      LOG(ERROR) << __FUNCTION__ << ": tunnel_id not found for vni=" << vni;
      return -EINVAL;
    }

    nl_addr *dst = rtnl_neigh_get_dst(neigh);

    // XXX TODO could check on type unicast
    if (dst == nullptr) {
      LOG(ERROR) << __FUNCTION__ << ": invalid dst";
      return -EINVAL;
    }

#if 0
    family = nl_addr_get_family(dst);

    if (family != AF_INET) {
      LOG(ERROR) << __FUNCTION__
        << ": currently only AF_INET is supported fam=" << family
        << " dst=" << dst;
      return -EINVAL;
    }
#endif // 0

    uint32_t remote_ipv4 = 0;

    memcpy(&remote_ipv4, nl_addr_get_binary_addr(dst), sizeof(remote_ipv4));
    remote_ipv4 = ntohl(remote_ipv4);

    tunnel_id = v2t_it->second;
    // use endpoint_id to get lport
    auto ep = endpoint_port(local_ipv4, remote_ipv4, dst_port);
    auto ep_it = endpoint_id.equal_range(ep);

    for (auto it = ep_it.first; it != ep_it.second; ++it) {
      if (it->first == ep) {
        VLOG(1) << __FUNCTION__ << ": found an lport_id=" << it->second.lport_id
                << " for endpoint TODO print ep";
        lport = it->second.lport_id;
        it->second.refcnt++;

        break;
      }
    }

    if (nl_addr_iszero(neigh_mac)) {
      // first or additional endpoint

      if (lport == 0) {
        // setup tmp remote to pass to create remote
        uint32_t tmp_remote = htonl(remote_ipv4);
        std::unique_ptr<nl_addr, void (*)(nl_addr *)> addr(
            nl_addr_build(AF_INET, &tmp_remote, sizeof(tmp_remote)),
            &nl_addr_put);

        LOG(INFO) << __FUNCTION__
                  << ": create new enpoint with remote_ipv4=" << addr.get();

        rv = create_endpoint(vxlan_link, br_link, std::move(addr), tunnel_id);
      } else {
        // attach vni to existing remote
        rv = sw->tunnel_port_tenant_add(lport, tunnel_id);

        if (rv < 0) {
          LOG(ERROR) << __FUNCTION__ << ": failed to add lport=" << lport
                     << " to tenant=" << tunnel_id;
          return rv;
        }

        rv = configure_flooding(br_link, tunnel_id, lport);

        if (rv < 0) {
          LOG(ERROR) << __FUNCTION__
                     << ": failed to add flooding for lport=" << lport
                     << " in tenant=" << tunnel_id;
          return rv;
        }
      }

      return rv;
    }

  } break;
    /* find according access port */
  case LT_TUN: {
    int ifindex = rtnl_link_get_ifindex(vxlan_link);
    uint16_t vlan = rtnl_neigh_get_vlan(neigh);
    uint32_t pport = tap_man->get_port_id(ifindex);

    if (pport == 0) {
      LOG(WARNING) << __FUNCTION__ << ": ignoring unknown link "
                   << OBJ_CAST(vxlan_link);
      return -EINVAL;
    }

    auto port = get_access_tunnel_port(pport, vlan);
    lport = port.lport_id;
    tunnel_id = port.tunnel_id;
  } break;
  default:
    LOG(ERROR) << __FUNCTION__ << ": not supported";
    return -EINVAL;
    break;
  }

  if (lport == 0 || tunnel_id == 0) {
    LOG(ERROR) << __FUNCTION__
               << ": could not find vxlan port details to add neigh "
               << OBJ_CAST(neigh) << ", lport=" << lport
               << ", tunnel_id=" << tunnel_id;
    return -EINVAL;
  }

  rofl::caddress_ll mac((uint8_t *)nl_addr_get_binary_addr(neigh_mac),
                        nl_addr_get_len(neigh_mac));

  VLOG(2) << __FUNCTION__ << ": adding l2 overlay addr for lport=" << lport
          << ", tunnel_id=" << tunnel_id << ", mac=" << mac;
  sw->l2_overlay_addr_add(lport, tunnel_id, mac);
  return 0;
}

int nl_vxlan::delete_l2_neigh(rtnl_neigh *neigh, rtnl_link *l) {
  assert(l);
  assert(neigh);
  assert(rtnl_link_get_family(l) == AF_UNSPEC); // the vxlan interface

  uint32_t tunnel_id = 0;
  enum link_type lt = kind_to_link_type(rtnl_link_get_type(l));
  auto neigh_mac = rtnl_neigh_get_lladdr(neigh);

  switch (lt) {
  case LT_VXLAN: {
    /* find according endpoint port */
    LOG(INFO) << __FUNCTION__ << ": add neigh " << OBJ_CAST(neigh)
              << " on vxlan interface " << OBJ_CAST(l);

    uint32_t vni;
    int rv = rtnl_link_vxlan_get_id(l, &vni);

    if (rv < 0) {
      LOG(FATAL) << __FUNCTION__ << ": something went south";
      return -EINVAL;
    }

    uint32_t dst_port;

    rv = rtnl_link_vxlan_get_port(l, &dst_port);

    if (rv < 0) {
      LOG(FATAL) << __FUNCTION__ << ": something went south";
      return -EINVAL;
    }

    nl_addr *local;

    rv = rtnl_link_vxlan_get_local(l, &local);

    if (rv < 0) {
      LOG(ERROR) << __FUNCTION__ << "local addr not set";
      return -EINVAL;
    }

    std::unique_ptr<nl_addr, void (*)(nl_addr *)> local_(local, &nl_addr_put);
    int family = nl_addr_get_family(local_.get());

    if (family != AF_INET) {
      LOG(ERROR) << __FUNCTION__ << ": currently only AF_INET is supported";
      return -EINVAL;
    }

    uint32_t local_ipv4 = 0;

    memcpy(&local_ipv4, nl_addr_get_binary_addr(local_.get()),
           sizeof(local_ipv4));
    local_ipv4 = ntohl(local_ipv4);

    auto v2t_it = vni2tunnel.find(vni);

    if (v2t_it == vni2tunnel.end()) {
      LOG(ERROR) << __FUNCTION__ << ": tunnel_id not found for vni=" << vni;
      return -EINVAL;
    }

    tunnel_id = v2t_it->second;
    nl_addr *dst = rtnl_neigh_get_dst(neigh);

    // TODO could check on type unicast
    if (dst == nullptr) {
      LOG(ERROR) << __FUNCTION__ << ": invalid dst";
      return -EINVAL;
    }

#if 0
    // XXX TODO could this be fixed in libnl3?
    family = nl_addr_get_family(dst);

    if (family != AF_INET) {
      LOG(ERROR) << __FUNCTION__
        << ": currently only AF_INET is supported fam=" << family
        << " dst=" << dst;
      return -EINVAL;
    }
#endif // 0

    uint32_t remote_ipv4 = 0;

    memcpy(&remote_ipv4, nl_addr_get_binary_addr(dst), sizeof(remote_ipv4));
    remote_ipv4 = ntohl(remote_ipv4);

    // use endpoint_id to get lport
    auto ep = endpoint_port(local_ipv4, remote_ipv4, dst_port);
    auto ep_it = endpoint_id.equal_range(ep);
    uint32_t lport = 0;
    auto it = ep_it.first;

    for (; it != ep_it.second; ++it) {
      if (it->first == ep) {
        VLOG(1) << __FUNCTION__ << ": found an lport_id=" << it->second.lport_id
                << " for endpoint TODO print ep";
        lport = it->second.lport_id;
        it->second.refcnt--;

        break;
      }
    }

    if (nl_addr_iszero(neigh_mac)) {
      if (lport) {
        sw->del_l2_overlay_flood(tunnel_id, lport);
      } else {
        LOG(WARNING) << __FUNCTION__ << ": tunnel_id=" << tunnel_id
                     << ", neigh: " << OBJ_CAST(neigh);
      }
    } else {
      // just mac on endpoint deleted -> drop bridging entry
      delete_l2_neigh(tunnel_id, neigh_mac);
    }

    if (it->second.refcnt == 0) {
      rv = sw->tunnel_port_tenant_remove(lport, tunnel_id);

      if (rv < 0) {
        LOG(ERROR) << __FUNCTION__ << ": failed to remove port=" << lport
                   << " from tenant=" << tunnel_id;
        return rv;
      }

      // TODO is everything deleted that is pointing here?
      sw->tunnel_port_delete(lport);

      // delete next hop
      rv = delete_next_hop(it->second.nh_id);
    }

  } break;

  case LT_TUN: {
    /* find according access port */
    int ifindex = rtnl_link_get_ifindex(l);
    uint16_t vlan = rtnl_neigh_get_vlan(neigh);
    uint32_t pport = tap_man->get_port_id(ifindex);

    if (pport == 0) {
      LOG(WARNING) << __FUNCTION__ << ": ignoring unknown link " << OBJ_CAST(l);
      return -EINVAL;
    }

    auto port = get_access_tunnel_port(pport, vlan);
    tunnel_id = port.tunnel_id;

    delete_l2_neigh(tunnel_id, neigh_mac);
  } break;
  default:
    LOG(ERROR) << __FUNCTION__ << ": not supported";
    return -EINVAL;
    break;
  }

  return 0;
}

int nl_vxlan::delete_l2_neigh(uint32_t tunnel_id, nl_addr *neigh_mac) {
  if (tunnel_id == 0) {
    LOG(ERROR) << __FUNCTION__
               << ": could not find vxlan port details to add neigh mac "
               << neigh_mac << ", tunnel_id=" << tunnel_id;
    return -EINVAL;
  }

  rofl::caddress_ll mac((uint8_t *)nl_addr_get_binary_addr(neigh_mac),
                        nl_addr_get_len(neigh_mac));

  VLOG(2) << __FUNCTION__
          << ": removing l2 overlay addr from tunnel_id=" << tunnel_id
          << ", mac=" << mac;
  sw->l2_overlay_addr_remove(tunnel_id, 0, mac);
  return 0;
}

} // namespace basebox
