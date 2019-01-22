#pragma once

#include <netlink/addr.h>
#include <glog/logging.h>

namespace basebox {

struct net_params {
  net_params(nl_addr *addr, int ifindex) : addr(addr), ifindex(ifindex) {
    VLOG(4) << __FUNCTION__ << ": this=" << this;
    nl_addr_get(addr);
  }

  net_params(const net_params &p) : addr(p.addr), ifindex(p.ifindex) {
    VLOG(4) << __FUNCTION__ << ": this=" << this
            << ", refcnt=" << nl_object_get_refcnt(OBJ_CAST(addr));
    nl_addr_get(addr);
  }

  ~net_params() {
    VLOG(4) << __FUNCTION__ << ": this=" << this
            << ", refcnt=" << nl_object_get_refcnt(OBJ_CAST(addr));
    nl_addr_put(addr);
  }

  nl_addr *addr;
  int ifindex;
};

struct nh_stub {
  nh_stub(nl_addr *nh, int ifindex) : nh(nh), ifindex(ifindex) {
    VLOG(4) << __FUNCTION__ << ": this=" << this;
    nl_addr_get(nh);
  }

  nh_stub(const nh_stub &r) : nh(r.nh), ifindex(r.ifindex) {
    VLOG(4) << __FUNCTION__ << ": this=" << this
            << ", refcnt=" << nl_object_get_refcnt(OBJ_CAST(nh));
    nl_addr_get(nh);
  }

  ~nh_stub() {
    VLOG(4) << __FUNCTION__ << ": this=" << this
            << ", refcnt=" << nl_object_get_refcnt(OBJ_CAST(nh));
    nl_addr_put(nh);
  }

  nl_addr *nh;
  int ifindex;
};

struct nh_params {
  nh_params(net_params np, nh_stub nh) : np(np), nh(nh) {}
  net_params np;
  nh_stub nh;
};

class net_reachable {
public:
  virtual ~net_reachable() = default;
  virtual void net_reachable_notification(struct net_params) noexcept = 0;
};

class nh_reachable {
public:
  virtual ~nh_reachable() = default;
  virtual void nh_reachable_notification(struct nh_params) noexcept = 0;
};

} // namespace basebox
