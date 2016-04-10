/*
 * cfibentry.hpp
 *
 *  Created on: 15.07.2013
 *      Author: andreas
 */

#ifndef CFIBENTRY_HPP_
#define CFIBENTRY_HPP_ 1

#include <inttypes.h>
#include <iostream>
#include <exception>
#include <bitset>

#include <rofl/common/ciosrv.h>
#include <rofl/common/caddress.h>
#include <rofl/common/crofbase.h>
#include <rofl/common/crofdpt.h>
#include <rofl/common/cdpid.h>
#include <rofl/common/logging.h>

#include "roflibs/netlink/clogging.hpp"
#include "roflibs/netlink/ccookiebox.hpp"

namespace roflibs {
namespace eth {

class eFibEntryBase : public std::runtime_error {
public:
  eFibEntryBase(const std::string &__arg) : std::runtime_error(__arg){};
};
class eFibEntryNotFound : public eFibEntryBase {
public:
  eFibEntryNotFound(const std::string &__arg) : eFibEntryBase(__arg){};
};
class eFibEntryPortNotMember : public eFibEntryBase {
public:
  eFibEntryPortNotMember(const std::string &__arg) : eFibEntryBase(__arg){};
};

class cfibentry; // forward declaration, see below

class cfibentry_owner {
public:
  virtual ~cfibentry_owner(){};
  virtual void fib_expired(cfibentry &entry) = 0;
};

class cfibentry : public roflibs::common::openflow::ccookie_owner {
public:
  /**
   *
   */
  cfibentry()
      : state(STATE_IDLE), fib(0),
        cookie_src(roflibs::common::openflow::ccookie_owner::acquire_cookie()),
        cookie_dst(roflibs::common::openflow::ccookie_owner::acquire_cookie()),
        vid(0), portno(0), tagged(true), src_stage_table_id(1),
        dst_stage_table_id(2), entry_timeout(0){};

  /**
   *
   */
  cfibentry(cfibentry_owner *fib, rofl::cdptid dptid, uint16_t vid,
            uint32_t portno, bool tagged, const rofl::caddress_ll &lladdr,
            bool permanent_entry = false,
            int entry_timeout = FIB_ENTRY_DEFAULT_TIMEOUT,
            uint8_t src_stage_table_id = 1, uint8_t dst_stage_table_id = 2)
      : state(STATE_IDLE), fib(fib), dptid(dptid),
        cookie_src(roflibs::common::openflow::ccookie_owner::acquire_cookie()),
        cookie_dst(roflibs::common::openflow::ccookie_owner::acquire_cookie()),
        vid(vid), portno(portno), tagged(tagged), lladdr(lladdr),
        src_stage_table_id(src_stage_table_id),
        dst_stage_table_id(dst_stage_table_id), entry_timeout(entry_timeout) {
    if (permanent_entry)
      flags.set(FLAG_PERMANENT_ENTRY);
  };

  /**
   *
   */
  virtual ~cfibentry() {
    try {
      if (STATE_ATTACHED == state) {
        handle_dpt_close(rofl::crofdpt::get_dpt(dptid));
      }
    } catch (rofl::eRofDptNotFound &e) {
    }
  };

  /**
   *
   */
  cfibentry(const cfibentry &entry)
      : cookie_src(roflibs::common::openflow::ccookie_owner::acquire_cookie()),
        cookie_dst(roflibs::common::openflow::ccookie_owner::acquire_cookie()) {
    *this = entry;
  };

  /**
   *
   */
  cfibentry &operator=(const cfibentry &entry) {
    if (this == &entry)
      return *this;
    state = entry.state;
    fib = entry.fib;
    dptid = entry.dptid;
    // do not copy cookies here!
    vid = entry.vid;
    portno = entry.portno;
    tagged = entry.tagged;
    lladdr = entry.lladdr;
    src_stage_table_id = entry.src_stage_table_id;
    dst_stage_table_id = entry.dst_stage_table_id;
    entry_timeout = entry.entry_timeout;
    return *this;
  };

public:
  /**
   *
   */
  const rofl::cdptid &get_dptid() const { return dptid; };

  /**
   *
   */
  uint16_t get_vid() const { return vid; };

  /**
   *
   */
  uint32_t get_portno() const { return portno; };

  /**
   *
   */
  bool get_tagged() const { return tagged; };

  /**
   *
   */
  rofl::cmacaddr const &get_lladdr() const { return lladdr; };

  /**
   *
   */
  int get_entry_timeout() const { return entry_timeout; };

  /**
   *
   */
  bool is_permanent() const { return flags.test(FLAG_PERMANENT_ENTRY); };

public:
  /**
   *
   */
  void handle_dpt_open(rofl::crofdpt &dpt);

  /**
   *
   */
  void handle_dpt_close(rofl::crofdpt &dpt);

  /**
   *
   */
  virtual void handle_packet_in(rofl::crofdpt &dpt, const rofl::cauxid &auxid,
                                rofl::openflow::cofmsg_packet_in &msg);

  /**
   *
   */
  virtual void handle_flow_removed(rofl::crofdpt &dpt,
                                   const rofl::cauxid &auxid,
                                   rofl::openflow::cofmsg_flow_removed &msg);

  /**
   *
   */
  void handle_port_status(rofl::crofdpt &dpt, const rofl::cauxid &auxid,
                          rofl::openflow::cofmsg_port_status &msg);

  /**
   *
   */
  void handle_error_message(rofl::crofdpt &dpt, const rofl::cauxid &auxid,
                            rofl::openflow::cofmsg_error &msg);

public:
  /**
   *
   */
  friend std::ostream &operator<<(std::ostream &os, const cfibentry &entry) {
    os << rofcore::indent(0) << "<cfibentry ";
    os << "vid:" << (int)entry.get_vid() << " ";
    os << "portno: " << entry.get_portno() << " ";
    os << "tagged:" << (entry.get_tagged() ? "true" : "false") << " ";
    os << ">" << std::endl;
    rofcore::indent i(2);
    os << "<dptid: >" << std::endl;
    os << entry.get_dptid();
    os << "<lladdr: >" << std::endl;
    os << entry.get_lladdr();
    return os;
  };

  static const int FIB_ENTRY_DEFAULT_TIMEOUT =
      300; // seconds (for idle-timeout), according to IEEE 802.1D-2004, page 45
  static const int FIB_ENTRY_PERMANENT = 0; // seconds (for idle-timeout)

  /**
   *
   */
  class cfibentry_find_by_portno {
    uint32_t portno;

  public:
    cfibentry_find_by_portno(uint32_t portno) : portno(portno){};
    bool operator()(const std::pair<rofl::caddress_ll, cfibentry> &p) const {
      return (p.second.get_portno() == portno);
    };
  };

private:
  enum dpt_state_t {
    STATE_IDLE = 1,
    STATE_DETACHED = 2,
    STATE_ATTACHED = 3,
  };

  dpt_state_t state;

  enum fibentry_flags_t {
    FLAG_PERMANENT_ENTRY = (1 << 0),
  };

  std::bitset<32> flags;
  cfibentry_owner *fib;
  rofl::cdptid dptid;
  uint64_t cookie_src; // cookie used for flow table entry in src stage
  uint64_t cookie_dst; // cookie used for flow table entry in dst stage
  uint16_t vid;
  uint32_t portno;
  bool tagged;
  rofl::cmacaddr lladdr;

  uint8_t src_stage_table_id;
  uint8_t dst_stage_table_id;
  int entry_timeout;
};

}; // end of namespace ethernet
}; // end of namespace roflibs

#endif /* CFIBENTRY_HPP_ */