/*
 * crtable.h
 *
 *  Created on: 02.07.2013
 *      Author: andreas
 */

#ifndef DPTROUTE_H_
#define DPTROUTE_H_ 1

#include <map>
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
#include <rofl/common/croflexception.h>

#include "cnetlink.h"
#include "crtroute.h"
#include "dptlink.h"
#include "dptnexthop.h"

namespace dptmap
{

class dptroute :
		public cnetlink_subscriber
{
private:


	rofl::crofbase					*rofbase;
	rofl::crofdpt					*dpt;
	uint8_t					 		table_id;
	unsigned int			 		rtindex;
	rofl::cofflowmod		 		flowentry;

	/* we make here one assumtpion: only one nexthop exists per neighbor and route
	 * this should be valid under all circumstances
	 */
	std::map<uint16_t, dptnexthop> 	dptnexthops; // key1:nbindex, value:dptnexthop instance


public:


	/**
	 *
	 */
	dptroute(
			rofl::crofbase* rofbase,
			rofl::crofdpt* dpt,
			uint8_t table_id,
			unsigned int rtindex);


	/**
	 *
	 * @param table_id
	 * @param rtindex
	 */
	virtual
	~dptroute();


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
	 * @param ifindex
	 * @param adindex
	 */
	virtual void
	addr_deleted(
			unsigned int ifindex,
			uint16_t adindex);


	/**
	 *
	 * @param rtindex
	 */
	virtual void
	route_created(
			uint8_t table_id,
			unsigned int rtindex);


	/**
	 *
	 * @param rtindex
	 */
	virtual void
	route_updated(
			uint8_t table_id,
			unsigned int rtindex);


	/**
	 *
	 * @param rtindex
	 */
	virtual void
	route_deleted(
			uint8_t table_id,
			unsigned int rtindex);


	/**
	 *
	 * @param ifindex
	 * @param nbindex
	 */
	virtual void
	neigh_created(
			unsigned int ifindex,
			uint16_t nbindex);


	/**
	 *
	 * @param ifindex
	 * @param nbindex
	 */
	virtual void
	neigh_updated(
			unsigned int ifindex,
			uint16_t nbindex);


	/**
	 *
	 * @param ifindex
	 * @param nbindex
	 */
	virtual void
	neigh_deleted(
			unsigned int ifindex,
			uint16_t nbindex);


public:

	/**
	 *
	 */
	friend std::ostream&
	operator<< (std::ostream& os, dptroute const& route) {
		crtroute& rtr = cnetlink::get_instance().get_route(route.table_id, route.rtindex);

		switch (rtr.get_scope()) {
#if 0
		case RT_SCOPE_HOST: {
			// nothing to do
		} break;
#endif
		case RT_SCOPE_HOST:
		case RT_SCOPE_LINK:
		case RT_SCOPE_SITE:
		case RT_SCOPE_UNIVERSE:
		default: {
			os << rofl::indent(0) << "<dptroute: >" 	<< std::endl;
			os << rofl::indent(2) << "<destination: " 	<< rtr.get_dst() 		<< " >" << std::endl;
			os << rofl::indent(2) << "<prefix: " 		<< rtr.get_prefixlen() 	<< " >" << std::endl;
			os << rofl::indent(2) << "<src " 			<< rtr.get_src() 		<< " >" << std::endl;
			os << rofl::indent(2) << "<scope " 			<< rtr.get_scope_s() 	<< " >" << std::endl;
			os << rofl::indent(2) << "<table " 			<< rtr.get_table_id_s() << " >" << std::endl;
			os << rofl::indent(2) << "<rtindex: " 		<< route.rtindex 		<< " >" << std::endl;

			rofl::indent i(2);
			for (std::map<uint16_t, dptnexthop>::const_iterator
					it = route.dptnexthops.begin(); it != route.dptnexthops.end(); ++it) {
				os << it->second;
			}
		} break;
		}
		return os;
	};


private:


	/**
	 *
	 */
	void
	set_nexthops();


	/**
	 *
	 */
	void
	delete_all_nexthops();

};

};

#endif /* CRTABLE_H_ */