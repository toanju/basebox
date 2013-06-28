/*
 * cdptport.cc
 *
 *  Created on: 28.06.2013
 *      Author: andreas
 */

#include <dptport.h>

using namespace dptmap;

dptport::dptport(
		rofl::crofbase *rofbase,
		rofl::cofdpt *dpt,
		uint32_t of_port_no) :
				rofbase(rofbase),
				dpt(dpt),
				of_port_no(of_port_no),
				tapdev(0),
				ifindex(0)
{
	tapdev = new ctapdev(this, dpt->get_ports()[of_port_no]->get_name(), dpt->get_ports()[of_port_no]->get_hwaddr());

	ifindex = tapdev->get_ifindex();
}



dptport::~dptport()
{
	if (tapdev) delete tapdev;
}



void
dptport::enqueue(cnetdev *netdev, rofl::cpacket* pkt)
{
	try {
		if (0 == dpt) {
			throw eDptPortNoDptAttached();
		}

		ctapdev* tapdev = dynamic_cast<ctapdev*>( netdev );
		if (0 == tapdev) {
			throw eDptPortTapDevNotFound();
		}

		rofl::cofaclist actions;
		actions.next() = rofl::cofaction_output(of_port_no);

		rofbase->send_packet_out_message(dpt, OFP_NO_BUFFER, OFPP_CONTROLLER, actions, pkt->soframe(), pkt->framelen());

	} catch (eDptPortNoDptAttached& e) {

		fprintf(stderr, "dptport::enqueue() no data path attached\n");

	} catch (eDptPortTapDevNotFound& e) {

		fprintf(stderr, "dptport::enqueue() no tap device found\n");

	}

	cpacketpool::get_instance().release_pkt(pkt);
}



void
dptport::enqueue(cnetdev *netdev, std::vector<rofl::cpacket*> pkts)
{
	for (std::vector<rofl::cpacket*>::iterator
			it = pkts.begin(); it != pkts.end(); ++it) {
		enqueue(netdev, *it);
	}
}



void
dptport::handle_packet_in(rofl::cpacket const& pack)
{
	if (0 == tapdev)
		return;

	rofl::cpacket *pkt = cpacketpool::get_instance().acquire_pkt();

	*pkt = pack;

	tapdev->enqueue(pkt);
}



void
dptport::link_created(unsigned int ifindex)
{
	// filter out any events not related to our port
	if (ifindex != this->ifindex)
		return;

	fprintf(stderr, "dptport::link_created() ifindex=%d => ", ifindex);
	std::cerr << cnetlink::get_instance().get_link(ifindex) << std::endl;
}



void
dptport::link_updated(unsigned int ifindex)
{
	// filter out any events not related to our port
	if (ifindex != this->ifindex)
		return;

	fprintf(stderr, "dptport::link_updated() ifindex=%d => ", ifindex);
	std::cerr << cnetlink::get_instance().get_link(ifindex) << std::endl;

	if (0 == dpt) {
		return;
	}
}



void
dptport::link_deleted(unsigned int ifindex)
{
	// filter out any events not related to our port
	if (ifindex != this->ifindex)
		return;

	fprintf(stderr, "dptport::link_deleted() ifindex=%d\n", ifindex);
}



void
dptport::addr_created(unsigned int ifindex, uint16_t adindex)
{
	// filter out any events not related to our port
	if (ifindex != this->ifindex)
		return;

	fprintf(stderr, "dptport::addr_created() ifindex=%d adindex=%d => ", ifindex, adindex);
	std::cerr << cnetlink::get_instance().get_link(ifindex).get_addr(adindex) << std::endl;

	ip_endpoint_install_flow_mod(adindex);
}



void
dptport::addr_updated(unsigned int ifindex, uint16_t adindex)
{
	// filter out any events not related to our port
	if (ifindex != this->ifindex)
		return;

	fprintf(stderr, "dptport::addr_updated() ifindex=%d adindex=%d => ", ifindex, adindex);
	std::cerr << cnetlink::get_instance().get_link(ifindex).get_addr(adindex) << std::endl;
}



void
dptport::addr_deleted(unsigned int ifindex, uint16_t adindex)
{
	// filter out any events not related to our port
	if (ifindex != this->ifindex)
		return;

	fprintf(stderr, "dptport::addr_deleted() ifindex=%d adindex=%d\n", ifindex, adindex);

	ip_endpoint_remove_flow_mod(adindex);
}



void
dptport::ip_endpoint_install_flow_mod(uint16_t adindex)
{
	try {
		crtaddr& rta = cnetlink::get_instance().get_link(ifindex).get_addr(adindex);

		rofl::cflowentry fe(dpt->get_version());

		fe.set_command(OFPFC_ADD);
		fe.set_buffer_id(OFP_NO_BUFFER);
		fe.set_idle_timeout(0);
		fe.set_hard_timeout(0);
		fe.set_table_id(0);			// FIXME: check for first table-id in data path

		fe.match.set_ipv4_dst(rta.get_local_addr());

		rofbase->send_flow_mod_message(dpt, fe);

	} catch (eRtLinkNotFound& e) {
		fprintf(stderr, "dptport::ip_endpoint_install_flow_mod() unable to find link or address\n");
	}
}



void
dptport::ip_endpoint_remove_flow_mod(uint16_t adindex)
{
	try {
		crtaddr& rta = cnetlink::get_instance().get_link(ifindex).get_addr(adindex);

		rofl::cflowentry fe(dpt->get_version());

		fe.set_command(OFPFC_DELETE_STRICT);
		fe.set_buffer_id(OFP_NO_BUFFER);
		fe.set_idle_timeout(0);
		fe.set_hard_timeout(0);
		fe.set_table_id(0);			// FIXME: check for first table-id in data path

		fe.match.set_ipv4_dst(rta.get_local_addr());

		rofbase->send_flow_mod_message(dpt, fe);

	} catch (eRtLinkNotFound& e) {
		fprintf(stderr, "dptport::ip_endpoint_remove_flow_mod() unable to find link or address\n");
	}
}

