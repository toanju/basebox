#pragma once

#include <cstdint>
#include <map>
#include <set>

extern "C" {
struct rtnl_link;
}

namespace basebox {

class cnetlink;
class switch_interface;

class nl_bond {
public:
  nl_bond(cnetlink *nl);
  ~nl_bond() {}

  void register_switch_interface(switch_interface *swi) { this->swi = swi; }

  uint32_t get_lag_id(rtnl_link *bond);
  int add_lag(rtnl_link *bond);
  int remove_lag(rtnl_link *bond);
  int add_lag_member(rtnl_link *bond, rtnl_link *link);
  int remove_lag_member(rtnl_link *bond, rtnl_link *link);

private:
  switch_interface *swi;
  cnetlink *nl;

  std::map<int, uint32_t> ifi2lag;
  std::map<int, uint32_t> lag_members;
};

} // namespace basebox
