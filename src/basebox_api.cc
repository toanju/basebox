#include "basebox_api.h"
#include "basebox_grpc_statistics.h"

#include <glog/logging.h>
#include <google/protobuf/repeated_field.h>
#include <grpc++/channel.h>
#include <grpc++/security/server_credentials.h>
#include <grpc++/server_builder.h>
#include <grpc++/server_context.h>
#include <grpc/grpc.h>

namespace basebox {

ApiServer::ApiServer(std::shared_ptr<switch_interface> swi)
    : stats(new NetworkStats(swi)) {}

ApiServer::~ApiServer() { delete stats; }

void ApiServer::runGRPCServer() {
  std::string server_address("0.0.0.0:5000");
  ::grpc::ServerBuilder builder;

  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  builder.RegisterService(stats);
  server = builder.BuildAndStart();
  LOG(INFO) << "gRPC server listening on " << server_address;
  server->Wait();
}

} // namespace basebox
