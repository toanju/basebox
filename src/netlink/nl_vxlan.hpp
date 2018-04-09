#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <tuple>

extern "C" {
struct nl_addr;
struct rtnl_link;
struct rtnl_neigh;
}

namespace basebox {

class cnetlink;
class nl_l3;
class switch_interface;
class tap_manager;

class nl_vxlan {
public:
  nl_vxlan(std::shared_ptr<tap_manager> tap_man, std::shared_ptr<nl_l3> l3,
           cnetlink *nl);
  ~nl_vxlan() {}

  int create_vni(rtnl_link *link, uint32_t *tunnel_id);
  int remove_vni(rtnl_link *link);

  void register_switch_interface(switch_interface *sw);

  int add_l2_neigh(rtnl_neigh *neigh, rtnl_link *vxlan_link,
                   rtnl_link *br_link);
  int delete_l2_neigh(rtnl_neigh *neigh, rtnl_link *l);

  int get_tunnel_id(rtnl_link *vxlan_link, uint32_t *tunnel_id) noexcept;
  int get_tunnel_id(uint32_t vni, uint32_t *tunnel_id) noexcept;

  int create_access_port(rtnl_link *br_link, uint32_t tunnel_id,
                         const std::string &access_port_name, uint32_t pport_no,
                         uint16_t vid, bool untagged, uint32_t *lport);
  int delete_access_port(uint32_t pport_no, uint16_t vid,
                         bool wipe_l2_addresses);

  int create_endpoint(rtnl_link *vxlan_link, uint32_t tunnel_id);
  int delete_endpoint(rtnl_link *vxlan_link, uint32_t tunnel_id); // XXX

private:
  int create_endpoint(rtnl_link *vxlan_link, rtnl_link *br_link,
                      std::unique_ptr<nl_addr, void (*)(nl_addr *)> group_,
                      uint32_t tunnel_id);
  int create_endpoint(rtnl_link *vxlan_link, nl_addr *local_, nl_addr *group_,
                      uint32_t _next_hop_id, uint32_t *_port_id);
  int delete_endpoint(rtnl_link *vxlan_link, nl_addr *local_, nl_addr *group_);

  int create_next_hop(rtnl_neigh *neigh, uint32_t *_next_hop_id);
  int delete_next_hop(rtnl_neigh *neigh);
  int delete_next_hop(uint32_t nh_id);

  int configure_flooding(rtnl_link *br_link, uint32_t tunnel_id,
                         uint32_t lport_id);
  int disable_flooding(rtnl_link *br_link, uint32_t tunnel_id,
                       uint32_t lport_id);

  int delete_l2_neigh(uint32_t tunnel_id, nl_addr *neigh_mac);

  // XXX TODO handle these better and prevent id overflow
  uint32_t next_hop_id_cnt = 1;
  uint32_t port_id_cnt = 1 << 16 | 1;
  uint32_t tunnel_id_cnt = 10;

  std::map<uint32_t, int> vni2tunnel;

  switch_interface *sw;
  std::shared_ptr<tap_manager> tap_man;
  std::shared_ptr<nl_l3> l3;
  cnetlink *nl;
};

} // namespace basebox
