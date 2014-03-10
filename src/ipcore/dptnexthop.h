/*
 * dptnexthop.h
 *
 *  Created on: 03.07.2013
 *      Author: andreas
 */

#ifndef DPTNEXTHOP_H_
#define DPTNEXTHOP_H_ 1

#include <ostream>

#ifdef __cplusplus
extern "C" {
#endif
#include <inttypes.h>
#ifdef __cplusplus
}
#endif

#include <rofl/common/logging.h>
#include <rofl/common/crofbase.h>
#include <rofl/common/crofdpt.h>
#include <rofl/common/openflow/cofflowmod.h>

#include "crtneigh.h"
#include "flowmod.h"
#include "cnetlink.h"

namespace dptmap
{

class dptnexthop :
		public flowmod
{
private:

	rofl::crofbase				*rofbase;
	rofl::crofdpt				*dpt;
	uint32_t					of_port_no;
	uint8_t						of_table_id;
	int							ifindex;
	uint16_t					nbindex;
	rofl::cofflowmod			fe;
	rofl::caddress				dstaddr; // destination address when acting as a gateway
	rofl::caddress				dstmask; // destination mask when acting as a gateway

public:


	/**
	 *
	 */
	dptnexthop();


	/**
	 *
	 */
	virtual
	~dptnexthop();


	/**
	 *
	 */
	void
	open();


	/**
	 *
	 */
	void
	close();


	/**
	 *
	 */
	dptnexthop(
			dptnexthop const& neigh);


	/**
	 *
	 */
	dptnexthop&
	operator= (
			dptnexthop const& neigh);


	/**
	 *
	 */
	dptnexthop(
			rofl::crofbase *rofbase,
			rofl::crofdpt* dpt,
			uint32_t of_port_no,
			uint8_t of_table_id,
			int ifindex,
			uint16_t nbindex,
			rofl::caddress const& dstaddr,
			rofl::caddress const& dstmask);


public:


	/**
	 *
	 */
	int get_ifindex() const { return ifindex; };


	/**
	 *
	 */
	uint16_t get_nbindex() const { return nbindex; };


	/**
	 *
	 */
	rofl::cofflowmod get_flowentry() const { return fe; };


	/**
	 *
	 */
	rofl::caddress get_dstaddr() const { return dstaddr; };


	/**
	 *
	 */
	rofl::caddress get_dstmask() const { return dstmask; };


	/**
	 *
	 */
	rofl::caddress get_gateway() const;


private:

	/**
	 *
	 */
	virtual void flow_mod_add();


	/**
	 *
	 */
	virtual void flow_mod_modify();


	/**
	 *
	 */
	virtual void flow_mod_delete();


public:


	/**
	 *
	 */
	friend std::ostream&
	operator<< (std::ostream& os, dptnexthop const& neigh) {
		try {
			os << rofl::indent(0) << "<dptnexthop: >" 	<< std::endl;

			crtneigh& rtn = cnetlink::get_instance().get_link(neigh.ifindex).get_neigh(neigh.nbindex);
			os << rofl::indent(0) << "<dptnexthop: >" 	<< std::endl;
			os << rofl::indent(2) << "<destination: " 	<< rtn.get_dst() << " >" << std::endl;
			os << rofl::indent(2) << "<device: " 		<< cnetlink::get_instance().get_link(neigh.ifindex).get_devname() << " >" << std::endl;
			os << rofl::indent(2) << "<hwaddr: " 		<< rtn.get_lladdr() << " >" << std::endl;
			os << rofl::indent(2) << "<state: " 		<< rtn.get_state() << " >" << std::endl;
			os << rofl::indent(2) << "<table-id: " 		<< (unsigned int)neigh.of_table_id << " >" << std::endl;

		} catch (eNetLinkNotFound& e) {
			os << "<dptnexthop: ";
				os << "ifindex:" << neigh.ifindex << " ";
				os << "nbindex:" << (unsigned int)neigh.nbindex << " ";
				os << "ofportno:" << (unsigned int)neigh.of_port_no << " ";
				os << "oftableid: " << (unsigned int)neigh.of_table_id << " ";
				os << "dstaddr:" << neigh.dstaddr << " ";
				os << "dstmask:" << neigh.dstmask << " ";
			os << ">";
		} catch (eRtLinkNotFound& e) {
			os << "<dptnexthop: ";
				os << "ifindex:" << neigh.ifindex << " ";
				os << "nbindex:" << (unsigned int)neigh.nbindex << " ";
				os << "ofportno:" << (unsigned int)neigh.of_port_no << " ";
				os << "oftableid: " << (unsigned int)neigh.of_table_id << " ";
				os << "dstaddr:" << neigh.dstaddr << " ";
				os << "dstmask:" << neigh.dstmask << " ";
			os << ">";
		}
		return os;
	};
};

}; // end of namespace

#endif /* DPTNEIGH_H_ */

