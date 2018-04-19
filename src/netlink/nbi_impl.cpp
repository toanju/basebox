#include <glog/logging.h>

#include "cnetlink.hpp"
#include "nbi_impl.hpp"
#include "tap_manager.hpp"

#include "netlink/ctapdev.hpp"
#include "utils.hpp"

namespace basebox {

nbi_impl::nbi_impl() : nl(new cnetlink()), tap_man(new tap_manager(nl.get())) {
  nl->set_tapmanager(tap_man);
  nl->start();
}

nbi_impl::~nbi_impl() { nl->stop(); }

void nbi_impl::resend_state() noexcept { nl->resend_state(); }

void nbi_impl::register_switch(switch_interface *swi) noexcept {
  this->swi = swi;
  nl->register_switch(swi);
}

void nbi_impl::port_notification(
    std::deque<port_notification_data> &notifications) noexcept {

  for (auto &&ntfy : notifications) {
    switch (ntfy.ev) {
    case PORT_EVENT_ADD:
      tap_man->create_tapdev(ntfy.port_id, ntfy.name, *this);
      break;
    case PORT_EVENT_DEL:
      tap_man->destroy_tapdev(ntfy.port_id, ntfy.name);
      break;
    default:
      break;
    }
  }
}

void nbi_impl::port_status_changed(uint32_t port_no,
                                   enum nbi::port_status ps) noexcept {
  nl->port_status_changed(port_no, ps);
}

int nbi_impl::enqueue_to_switch(uint32_t port_id, basebox::packet *packet) {
  swi->enqueue(port_id, packet);
  return 0;
}

int nbi_impl::enqueue(uint32_t port_id, basebox::packet *pkt) noexcept {
  int rv = 0;
  assert(pkt);
  try {
    // detour via netlink to learn the source mac
    int fd = tap_man->get_fd(port_id);
    nl->learn_l2(port_id, fd, pkt);
  } catch (std::exception &e) {
    LOG(ERROR) << __FUNCTION__
               << ": failed to enqueue packet for port_id=" << port_id << ": "
               << e.what();
    std::free(pkt);
    rv = -1;
  }
  return rv;
}

int nbi_impl::fdb_timeout(uint32_t port_id, uint16_t vid,
                          const rofl::caddress_ll &mac) noexcept {
  nl->fdb_timeout(port_id, vid, mac);
  return 0;
}

} // namespace basebox
