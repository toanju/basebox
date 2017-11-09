#include "basebox_grpc_statistics.h"
#include "netlink/cnetlink.hpp"
#include <glog/logging.h>
#include <vector>

namespace basebox {

using openconfig_interfaces::Interface_State;
using openconfig_interfaces::Interface_State_Counters;
using openconfig_interfaces::Interfaces;
using openconfig_interfaces::Interfaces_Interface;

NetworkStats::NetworkStats(std::shared_ptr<switch_interface> swi) : swi(swi) {}

::grpc::Status NetworkStats::GetStatistics(::grpc::ServerContext *context,
                                           const Empty *request,
                                           Interfaces *response) {
  VLOG(2) << __FUNCTION__ << ": received grpc call";

  std::vector<switch_interface::sai_port_stat_t> counter_ids = {
      switch_interface::SAI_PORT_STAT_RX_PACKETS,
      switch_interface::SAI_PORT_STAT_TX_PACKETS,
      switch_interface::SAI_PORT_STAT_RX_BYTES,
      switch_interface::SAI_PORT_STAT_TX_BYTES,
      switch_interface::SAI_PORT_STAT_RX_DROPPED,
      switch_interface::SAI_PORT_STAT_TX_DROPPED,
      switch_interface::SAI_PORT_STAT_RX_ERRORS,
      switch_interface::SAI_PORT_STAT_TX_ERRORS,
      switch_interface::SAI_PORT_STAT_RX_FRAME_ERR,
      switch_interface::SAI_PORT_STAT_RX_OVER_ERR,
      switch_interface::SAI_PORT_STAT_RX_CRC_ERR,
      switch_interface::SAI_PORT_STAT_COLLISIONS};
  std::vector<uint64_t> stats(counter_ids.size());
  std::map<std::string, uint32_t> ports =
      cnetlink::get_instance().get_registered_ports();

  for (const auto &port : ports) {
    std::cout << port.second << std::endl;
    int rv = swi->get_statistics(port.second, counter_ids.size(),
                                 counter_ids.data(), stats.data());
    if (rv != 0)
      continue;

    ::openconfig_interfaces::Interface_State *state =
        response->add_interface()->mutable_state();
    state->set_name(port.first);
    ::openconfig_interfaces::Interface_State_Counters *counters =
        state->mutable_counters();

    counters->set_in_discards(stats[5]);
    counters->set_in_errors(stats[7] + stats[10]);
    counters->set_in_fcs_errors(stats[9] + stats[11]);
    counters->set_in_octets(stats[3]);
    counters->set_in_unicast_pkts(stats[1]);

    counters->set_out_discards(stats[6]);
    counters->set_out_errors(stats[8] + stats[12]);
    counters->set_out_octets(stats[4]);
    counters->set_out_unicast_pkts(stats[2]);
  }

  return ::grpc::Status::OK;
}

} // namespace basebox
