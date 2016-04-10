/*
 * cgrecore.hpp
 *
 *  Created on: 18.08.2014
 *      Author: andreas
 */

#ifndef CGRECORE_HPP_
#define CGRECORE_HPP_

#include <map>
#include <iostream>
#include <exception>

#include <rofl/common/crofdpt.h>
#include <rofl/common/cdptid.h>
#include <rofl/common/protocols/fudpframe.h>
#include <rofl/common/protocols/fipv4frame.h>
#include <rofl/common/protocols/fipv6frame.h>
#include <rofl/common/thread_helper.h>
#include <rofl/common/crofdpt.h>
#include <rofl/common/cauxid.h>
#include <rofl/common/openflow/messages/cofmsg_packet_in.h>
#include <rofl/common/openflow/messages/cofmsg_flow_removed.h>
#include <rofl/common/openflow/messages/cofmsg_error.h>

#include "roflibs/netlink/clogging.hpp"
#include "roflibs/grecore/cgreterm.hpp"
#include "roflibs/netlink/ccookiebox.hpp"

namespace roflibs {
namespace gre {

class eGreCoreBase : public std::runtime_error {
public:
  eGreCoreBase(const std::string &__arg) : std::runtime_error(__arg){};
};
class eGreCoreNotFound : public eGreCoreBase {
public:
  eGreCoreNotFound(const std::string &__arg) : eGreCoreBase(__arg){};
};

class cgrecore : public roflibs::common::openflow::ccookie_owner {
public:
  /**
   *
   */
  static cgrecore &add_gre_core(const rofl::cdptid &dptid,
                                uint8_t eth_local_table_id,
                                uint8_t ip_local_table_id,
                                uint8_t gre_local_table_id,
                                uint8_t ip_fwd_table_id) {
    if (cgrecore::grecores.find(dptid) != cgrecore::grecores.end()) {
      delete cgrecore::grecores[dptid];
      cgrecore::grecores.erase(dptid);
    }
    cgrecore::grecores[dptid] =
        new cgrecore(dptid, eth_local_table_id, ip_local_table_id,
                     gre_local_table_id, ip_fwd_table_id);
    return *(cgrecore::grecores[dptid]);
  };

  /**
   *
   */
  static cgrecore &set_gre_core(const rofl::cdptid &dptid,
                                uint8_t eth_local_table_id,
                                uint8_t ip_local_table_id,
                                uint8_t gre_local_table_id,
                                uint8_t ip_fwd_table_id) {
    if (cgrecore::grecores.find(dptid) == cgrecore::grecores.end()) {
      cgrecore::grecores[dptid] =
          new cgrecore(dptid, eth_local_table_id, ip_local_table_id,
                       gre_local_table_id, ip_fwd_table_id);
    }
    return *(cgrecore::grecores[dptid]);
  };

  /**
   *
   */
  static cgrecore &set_gre_core(const rofl::cdptid &dptid) {
    if (cgrecore::grecores.find(dptid) == cgrecore::grecores.end()) {
      throw eGreCoreNotFound("cgrecore::set_gre_core() dpt not found");
    }
    return *(cgrecore::grecores[dptid]);
  };

  /**
   *
   */
  static const cgrecore &get_gre_core(const rofl::cdptid &dptid) {
    if (cgrecore::grecores.find(dptid) == cgrecore::grecores.end()) {
      throw eGreCoreNotFound("cgrecore::get_gre_core() dpt not found");
    }
    return *(cgrecore::grecores.at(dptid));
  };

  /**
   *
   */
  static void drop_gre_core(const rofl::cdptid &dptid) {
    if (cgrecore::grecores.find(dptid) == cgrecore::grecores.end()) {
      return;
    }
    delete cgrecore::grecores[dptid];
    cgrecore::grecores.erase(dptid);
  }

  /**
   *
   */
  static bool has_gre_core(const rofl::cdptid &dptid) {
    return (not(cgrecore::grecores.find(dptid) == cgrecore::grecores.end()));
  };

private:
  /**
   *
   */
  cgrecore(const rofl::cdptid &dptid, uint8_t eth_local_table_id,
           uint8_t ip_local_table_id, uint8_t gre_local_table_id,
           uint8_t ip_fwd_table_id)
      : state(STATE_DETACHED), dptid(dptid),
        cookie_miss_entry(
            roflibs::common::openflow::ccookie_owner::acquire_cookie()),
        eth_local_table_id(eth_local_table_id),
        ip_local_table_id(ip_local_table_id),
        gre_local_table_id(gre_local_table_id),
        ip_fwd_table_id(ip_fwd_table_id), tid(pthread_self()){};

  /**
   *
   */
  virtual ~cgrecore() {
    while (not terms_in4.empty()) {
      uint32_t term_id = terms_in4.begin()->first;
      drop_gre_term_in4(term_id);
    }
    while (not terms_in6.empty()) {
      uint32_t term_id = terms_in6.begin()->first;
      drop_gre_term_in6(term_id);
    }
  };

public:
  /**
   *
   */
  void handle_dpt_open();

  /**
   *
   */
  void handle_dpt_close();

public:
  /**
   *
   */
  std::vector<uint32_t> get_gre_terms_in4() const {
    rofl::RwLock rwlock(rwlock_in4, rofl::RwLock::RWLOCK_READ);
    std::vector<uint32_t> termids;
    for (std::map<uint32_t, cgreterm_in4 *>::const_iterator it =
             terms_in4.begin();
         it != terms_in4.end(); ++it) {
      termids.push_back(it->first);
    }
    return termids;
  };

  /**
   *
   */
  void clear_gre_terms_in4() {
    rofl::RwLock rwlock(rwlock_in4, rofl::RwLock::RWLOCK_WRITE);
    for (std::map<uint32_t, cgreterm_in4 *>::iterator it = terms_in4.begin();
         it != terms_in4.end(); ++it) {
      delete it->second;
    }
    terms_in4.clear();
  };

  /**
   *
   */
  cgreterm_in4 &add_gre_term_in4(uint32_t term_id, uint32_t gre_portno,
                                 const rofl::caddress_in4 &laddr,
                                 const rofl::caddress_in4 &raddr,
                                 uint32_t gre_key) {
    rofl::RwLock rwlock(rwlock_in4, rofl::RwLock::RWLOCK_WRITE);
    if (terms_in4.find(term_id) != terms_in4.end()) {
      delete terms_in4[term_id];
      terms_in4.erase(term_id);
    }
    terms_in4[term_id] =
        new cgreterm_in4(dptid, eth_local_table_id, gre_local_table_id,
                         ip_fwd_table_id, laddr, raddr, gre_portno, gre_key);
    try {
      if (STATE_ATTACHED == state) {
        terms_in4[term_id]->handle_dpt_open(rofl::crofdpt::get_dpt(dptid));
      }
    } catch (rofl::eRofDptNotFound &e) {
    };
    return *(terms_in4[term_id]);
  };

  /**
   *
   */
  cgreterm_in4 &set_gre_term_in4(uint32_t term_id, uint32_t gre_portno,
                                 const rofl::caddress_in4 &laddr,
                                 const rofl::caddress_in4 &raddr,
                                 uint32_t gre_key) {
    rofl::RwLock rwlock(rwlock_in4, rofl::RwLock::RWLOCK_WRITE);
    if (terms_in4.find(term_id) == terms_in4.end()) {
      terms_in4[term_id] =
          new cgreterm_in4(dptid, eth_local_table_id, gre_local_table_id,
                           ip_fwd_table_id, laddr, raddr, gre_portno, gre_key);
    }
    try {
      if (STATE_ATTACHED == state) {
        terms_in4[term_id]->handle_dpt_open(rofl::crofdpt::get_dpt(dptid));
      }
    } catch (rofl::eRofDptNotFound &e) {
    };
    return *(terms_in4[term_id]);
  };

  /**
   *
   */
  cgreterm_in4 &set_gre_term_in4(uint32_t term_id) {
    rofl::RwLock rwlock(rwlock_in4, rofl::RwLock::RWLOCK_READ);
    if (terms_in4.find(term_id) == terms_in4.end()) {
      throw eGreTermNotFound("cgrecore::get_gre_term_in4() term_id not found");
    }
    return *(terms_in4[term_id]);
  };

  /**
   *
   */
  const cgreterm_in4 &get_gre_term_in4(uint32_t term_id) const {
    rofl::RwLock rwlock(rwlock_in4, rofl::RwLock::RWLOCK_READ);
    if (terms_in4.find(term_id) == terms_in4.end()) {
      throw eGreTermNotFound("cgrecore::get_term_in4() term_id not found");
    }
    return *(terms_in4.at(term_id));
  };

  /**
   *
   */
  void drop_gre_term_in4(uint32_t term_id) {
    rofl::RwLock rwlock(rwlock_in4, rofl::RwLock::RWLOCK_WRITE);
    if (terms_in4.find(term_id) == terms_in4.end()) {
      return;
    }
    delete terms_in4[term_id];
    terms_in4.erase(term_id);
  };

  /**
   *
   */
  bool has_gre_term_in4(uint32_t term_id) const {
    rofl::RwLock rwlock(rwlock_in4, rofl::RwLock::RWLOCK_READ);
    return (not(terms_in4.find(term_id) == terms_in4.end()));
  };

public:
  /**
   *
   */
  std::vector<uint32_t> get_gre_terms_in6() const {
    rofl::RwLock rwlock(rwlock_in6, rofl::RwLock::RWLOCK_READ);
    std::vector<uint32_t> termids;
    for (std::map<uint32_t, cgreterm_in6 *>::const_iterator it =
             terms_in6.begin();
         it != terms_in6.end(); ++it) {
      termids.push_back(it->first);
    }
    return termids;
  };

  /**
   *
   */
  void clear_gre_terms_in6() {
    rofl::RwLock rwlock(rwlock_in6, rofl::RwLock::RWLOCK_WRITE);
    for (std::map<uint32_t, cgreterm_in6 *>::iterator it = terms_in6.begin();
         it != terms_in6.end(); ++it) {
      delete it->second;
    }
    terms_in6.clear();
  };

  /**
   *
   */
  cgreterm_in6 &add_gre_term_in6(uint32_t term_id, uint32_t gre_portno,
                                 const rofl::caddress_in6 &laddr,
                                 const rofl::caddress_in6 &raddr,
                                 uint32_t gre_key) {
    rofl::RwLock rwlock(rwlock_in6, rofl::RwLock::RWLOCK_WRITE);
    if (terms_in6.find(term_id) != terms_in6.end()) {
      delete terms_in6[term_id];
      terms_in6.erase(term_id);
    }
    terms_in6[term_id] =
        new cgreterm_in6(dptid, eth_local_table_id, gre_local_table_id,
                         ip_fwd_table_id, laddr, raddr, gre_portno, gre_key);
    try {
      if (STATE_ATTACHED == state) {
        terms_in6[term_id]->handle_dpt_open(rofl::crofdpt::get_dpt(dptid));
      }
    } catch (rofl::eRofDptNotFound &e) {
    };
    return *(terms_in6[term_id]);
  };

  /**
   *
   */
  cgreterm_in6 &set_gre_term_in6(uint32_t term_id, uint32_t gre_portno,
                                 const rofl::caddress_in6 &laddr,
                                 const rofl::caddress_in6 &raddr,
                                 uint32_t gre_key) {
    rofl::RwLock rwlock(rwlock_in6, rofl::RwLock::RWLOCK_WRITE);
    if (terms_in6.find(term_id) == terms_in6.end()) {
      terms_in6[term_id] =
          new cgreterm_in6(dptid, eth_local_table_id, gre_local_table_id,
                           ip_fwd_table_id, laddr, raddr, gre_portno, gre_key);
    }
    try {
      if (STATE_ATTACHED == state) {
        terms_in6[term_id]->handle_dpt_open(rofl::crofdpt::get_dpt(dptid));
      }
    } catch (rofl::eRofDptNotFound &e) {
    };
    return *(terms_in6[term_id]);
  };

  /**
   *
   */
  cgreterm_in6 &set_gre_term_in6(uint32_t term_id) {
    rofl::RwLock rwlock(rwlock_in6, rofl::RwLock::RWLOCK_READ);
    if (terms_in6.find(term_id) == terms_in6.end()) {
      throw eGreTermNotFound("cgrecore::get_gre_term_in6() term_id not found");
    }
    return *(terms_in6[term_id]);
  };

  /**
   *
   */
  const cgreterm_in6 &get_gre_term_in6(uint32_t term_id) const {
    rofl::RwLock rwlock(rwlock_in6, rofl::RwLock::RWLOCK_READ);
    if (terms_in6.find(term_id) == terms_in6.end()) {
      throw eGreTermNotFound("cgrecore::get_term_in6() term_id not found");
    }
    return *(terms_in6.at(term_id));
  };

  /**
   *
   */
  void drop_gre_term_in6(uint32_t term_id) {
    rofl::RwLock rwlock(rwlock_in6, rofl::RwLock::RWLOCK_WRITE);
    if (terms_in6.find(term_id) == terms_in6.end()) {
      return;
    }
    delete terms_in6[term_id];
    terms_in6.erase(term_id);
  };

  /**
   *
   */
  bool has_gre_term_in6(uint32_t term_id) const {
    rofl::RwLock rwlock(rwlock_in6, rofl::RwLock::RWLOCK_READ);
    return (not(terms_in6.find(term_id) == terms_in6.end()));
  };

public:
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
                                   rofl::openflow::cofmsg_flow_removed &msg){};

  /**
   *
   */
  virtual void handle_error_message(rofl::crofdpt &dpt,
                                    const rofl::cauxid &auxid,
                                    rofl::openflow::cofmsg_error &msg){};

protected:
  friend class cgreterm;

  /**
   *
   */
  pthread_t get_thread_id() const { return tid; };

public:
  friend std::ostream &operator<<(std::ostream &os, const cgrecore &grecore) {
    os << rofcore::indent(0) << "<cgrecore dpid:" << grecore.dptid.str() << " "
       << " 0x" << std::hex << &grecore << std::dec << " "
       << "#in4-term(s): " << grecore.terms_in4.size() << " "
       << "#in6-term(s): " << grecore.terms_in6.size() << " >" << std::endl;
    for (std::map<uint32_t, cgreterm_in4 *>::const_iterator it =
             grecore.terms_in4.begin();
         it != grecore.terms_in4.end(); ++it) {
      rofcore::indent i(2);
      os << *(it->second);
    }
    for (std::map<uint32_t, cgreterm_in6 *>::const_iterator it =
             grecore.terms_in6.begin();
         it != grecore.terms_in6.end(); ++it) {
      rofcore::indent i(2);
      os << *(it->second);
    }
    return os;
  };

private:
  enum ofp_state_t {
    STATE_DETACHED = 1,
    STATE_ATTACHED = 2,
  };

  enum ofp_state_t state;
  rofl::cdptid dptid;
  uint64_t cookie_miss_entry;
  uint8_t eth_local_table_id;
  uint8_t ip_local_table_id;
  uint8_t gre_local_table_id;
  uint8_t ip_fwd_table_id;
  std::map<uint32_t, cgreterm_in4 *> terms_in4;
  mutable rofl::PthreadRwLock rwlock_in4;
  std::map<uint32_t, cgreterm_in6 *> terms_in6;
  mutable rofl::PthreadRwLock rwlock_in6;
  static std::map<rofl::cdptid, cgrecore *> grecores;

  static const uint8_t GRE_IP_PROTO = 47;
  static const uint16_t GRE_PROT_TYPE_TRANSPARENT_ETHERNET_BRIDGING = 0x6558;

  pthread_t tid;
};

}; // end of namespace gre
}; // end of namespace roflibs

#endif /* CGRECORE_HPP_ */