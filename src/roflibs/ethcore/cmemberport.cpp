/*
 * cmemberport.cpp
 *
 *  Created on: 07.08.2014
 *      Author: andreas
 */

#include "cmemberport.hpp"

using namespace roflibs::eth;


void
cmemberport::handle_dpt_open(
		rofl::crofdpt& dpt)
{
	try {
		if (rofl::openflow::OFP_VERSION_UNKNOWN == dpt.get_version_negotiated()) {
			return;
		}

		dpt_state = STATE_ATTACHED;

		rofl::cindex index(0);

		rofl::openflow::cofflowmod fm(dpt.get_version_negotiated());
		fm.set_command(rofl::openflow::OFPFC_ADD);
		fm.set_idle_timeout(0);
		fm.set_hard_timeout(0);
		fm.set_priority(0x8000);
		fm.set_cookie(cookie);
		fm.set_table_id(table_id_eth_in);
		fm.set_match().set_in_port(portno);
		if (tagged) {
			fm.set_match().set_vlan_vid(vid | rofl::openflow::OFPVID_PRESENT);
		} else {
			fm.set_match().set_vlan_untagged();
			fm.set_instructions().set_inst_apply_actions().set_actions().
					add_action_push_vlan(index++).set_eth_type(rofl::fvlanframe::VLAN_CTAG_ETHER);
			fm.set_instructions().set_inst_apply_actions().set_actions().
					add_action_set_field(index++).set_oxm(rofl::openflow::coxmatch_ofb_vlan_vid(vid));
		}
#if 0
		fm.set_instructions().set_inst_write_metadata().set_metadata(vid);
		fm.set_instructions().set_inst_write_metadata().set_metadata_mask(0xfff);
#endif
		fm.set_instructions().set_inst_goto_table().set_table_id(table_id_eth_in+1);
		dpt.send_flow_mod_message(rofl::cauxid(0), fm);


	} catch (rofl::eRofBaseCongested& e) {
		// TODO: handle congested control channel
	}
}

void
cmemberport::handle_dpt_close(
		rofl::crofdpt& dpt)
{
	try {
		if (rofl::openflow::OFP_VERSION_UNKNOWN == dpt.get_version_negotiated()) {
			return;
		}

		dpt_state = STATE_DETACHED;

		rofl::cindex index(0);

		rofl::openflow::cofflowmod fm(dpt.get_version_negotiated());
		fm.set_command(rofl::openflow::OFPFC_DELETE_STRICT);
		fm.set_idle_timeout(0);
		fm.set_hard_timeout(0);
		fm.set_priority(0x8000);
		fm.set_cookie(cookie);
		fm.set_table_id(table_id_eth_in);
		fm.set_match().set_in_port(portno);
		if (tagged) {
			fm.set_match().set_vlan_vid(vid | rofl::openflow::OFPVID_PRESENT);
		} else {
			fm.set_match().set_vlan_untagged();
		}
		dpt.send_flow_mod_message(rofl::cauxid(0), fm);


	} catch (rofl::eRofBaseCongested& e) {
		// TODO: handle congested control channel
	}
}



void
cmemberport::handle_packet_in(
		rofl::crofdpt& dpt, const rofl::cauxid& auxid, rofl::openflow::cofmsg_packet_in& msg)
{
	// nothing to do
}



void
cmemberport::handle_flow_removed(
		rofl::crofdpt& dpt, const rofl::cauxid& auxid, rofl::openflow::cofmsg_flow_removed& msg)
{
	// nothing to do
}



void
cmemberport::handle_port_status(
		rofl::crofdpt& dpt, const rofl::cauxid& auxid, rofl::openflow::cofmsg_port_status& msg)
{
	if (STATE_ATTACHED != dpt_state) {
		return;
	}

	if (msg.get_port().get_port_no() != portno) {
		return;
	}

	switch (msg.get_reason()) {
	case rofl::openflow::OFPPR_ADD: {
		handle_dpt_open(dpt);
	} break;
	case rofl::openflow::OFPPR_MODIFY: {
		handle_dpt_close(dpt);
		handle_dpt_open(dpt);
		// TODO: port up/down?
	} break;
	case rofl::openflow::OFPPR_DELETE: {
		handle_dpt_close(dpt);
	} break;
	}
}



void
cmemberport::handle_error_message(
		rofl::crofdpt& dpt, const rofl::cauxid& auxid, rofl::openflow::cofmsg_error& msg)
{
	// TODO
}



