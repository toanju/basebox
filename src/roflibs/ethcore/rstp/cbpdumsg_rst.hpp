/*
 * cbpdumsg_rst.hpp
 *
 *  Created on: 03.01.2015
 *      Author: andreas
 */

#ifndef CBPDUMSG_RST_HPP_
#define CBPDUMSG_RST_HPP_

#include "cbpdumsg.hpp"
#include "cbridgeid.hpp"
#include "crpcost.hpp"
#include "cportid.hpp"

namespace roflibs {
namespace eth {
namespace rstp {

/**
 * @class cbpdumsg_rst
 * @brief Configuration bridge PDU
 */
class cbpdumsg_rst : public cbpdumsg {
public:
  /**
   * @brief cbpdumsg_rst destructor
   */
  virtual ~cbpdumsg_rst(){};

  /**
   * @brief cbpdumsg_rst default constructor
   */
  cbpdumsg_rst()
      : flags(0), message_age(0), max_age(0), hello_time(0), forward_delay(0),
        version1_length(0){};

public:
  /**
   * @brief Assignment operator
   */
  cbpdumsg_rst &operator=(const cbpdumsg_rst &bpdu) {
    if (this == &bpdu)
      return *this;
    cbpdumsg::operator=(bpdu);
    flags = bpdu.flags;
    rootid = bpdu.rootid;
    rootpathcost = bpdu.rootpathcost;
    bridgeid = bpdu.bridgeid;
    portid = bpdu.portid;
    message_age = bpdu.message_age;
    max_age = bpdu.max_age;
    hello_time = bpdu.hello_time;
    forward_delay = bpdu.forward_delay;
    version1_length = bpdu.version1_length;
    return *this;
  };

public:
  /**
   * @brief Returns buffer length required for packing this instance.
   */
  virtual size_t length() const {
    return sizeof(bpdu_rst_body_t) + cbpdumsg::length();
  };

  /**
   * @brief Packs this instance' internal state into the given buffer.
   */
  virtual void pack(uint8_t *buf, size_t buflen);

  /**
   * @brief Unpacks a given buffer and stores its content in this instance.
   */
  virtual void unpack(uint8_t *buf, size_t buflen);

public:
  /**
   * @name Methods granting access to internal parameters
   */

  /**@{*/

  /**
   * @brief Returns flags field in rapid spanning tree BPDU.
   */
  uint8_t get_flags() const { return flags; };

  /**
   * @brief Sets flags field in rapid spanning tree BPDU.
   */
  void set_flags(uint8_t flags) { this->flags = flags; };

  /**
   * @brief Returns root bridge identifier in rapid spanning tree BPDU
   */
  const cbridgeid &get_rootid() const { return rootid; };

  /**
   * @brief Sets root bridge identifier in rapid spanning tree BPDU.
   */
  void set_rootid(const cbridgeid &rootid) { this->rootid = rootid; };

  /**
   * @brief Returns root path cost in rapid spanning tree BPDU
   */
  const crpcost &get_root_path_cost() const { return rootpathcost; };

  /**
   * @brief Sets root path cost in rapid spanning tree BPDU.
   */
  void set_root_path_cost(const crpcost &rootpathcost) {
    this->rootpathcost = rootpathcost;
  };

  /**
   * @brief Returns sending bridge identifier in rapid spanning tree BPDU
   */
  const cbridgeid &get_bridgeid() const { return bridgeid; };

  /**
   * @brief Sets sending bridge identifier in rapid spanning tree BPDU.
   */
  void set_bridgeid(const cbridgeid &bridgeid) { this->bridgeid = bridgeid; };

  /**
   * @brief Returns sending port identifier in rapid spanning tree BPDU
   */
  const cportid &get_portid() const { return portid; };

  /**
   * @brief Sets sending port identifier in rapid spanning tree BPDU.
   */
  void set_portid(const cportid &portid) { this->portid = portid; };

  /**
   * @brief Returns message-age field in rapid spanning tree BPDU.
   */
  uint16_t get_message_age() const { return message_age; };

  /**
   * @brief Sets message-age field in rapid spanning tree BPDU.
   */
  void set_message_age(uint16_t message_age) {
    this->message_age = message_age;
  };

  /**
   * @brief Returns max-age field in rapid spanning tree BPDU.
   */
  uint16_t get_max_age() const { return max_age; };

  /**
   * @brief Sets max-age field in rapid spanning tree BPDU.
   */
  void set_max_age(uint16_t max_age) { this->max_age = max_age; };

  /**
   * @brief Returns hello-time field in rapid spanning tree BPDU.
   */
  uint16_t get_hello_time() const { return hello_time; };

  /**
   * @brief Sets hello-time field in rapid spanning tree BPDU.
   */
  void set_hello_time(uint16_t hello_time) { this->hello_time = hello_time; };

  /**
   * @brief Returns forward-delay field in rapid spanning tree BPDU.
   */
  uint16_t get_forward_delay() const { return forward_delay; };

  /**
   * @brief Sets forward-delay field in rapid spanning tree BPDU.
   */
  void set_forward_delay(uint16_t forward_delay) {
    this->forward_delay = forward_delay;
  };

  /**
   * @brief Returns version1 field in rapid spanning tree BPDU.
   */
  uint8_t get_version1_length() const { return version1_length; };

  /**
   * @brief Sets version1 field in rapid spanning tree BPDU.
   */
  void set_version1_length(uint8_t version1_length) {
    this->version1_length = version1_length;
  };

  /**@}*/

public:
  friend std::ostream &operator<<(std::ostream &os, const cbpdumsg_rst &msg) {

    return os;
  };

private:
  uint8_t flags;
  // bridge identifier of current root bridge
  cbridgeid rootid;
  // path cost to current root bridge
  crpcost rootpathcost;
  // bridge identifier of PDU sending bridge
  cbridgeid bridgeid;
  // port identifier of sending port
  cportid portid;
  uint16_t message_age;
  uint16_t max_age;
  uint16_t hello_time;
  uint16_t forward_delay;
  uint8_t version1_length;
};

}; // end of namespace rstp
}; // end of namespace ethernet
}; // end of namespace roflibs

#endif /* CBPDUMSG_RST_HPP_ */