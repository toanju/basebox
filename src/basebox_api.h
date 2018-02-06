#pragma once

#include <grpc++/server.h>

namespace basebox {

// forward declarations
class NetworkStats;
class switch_interface;
class tap_manager;

class ApiServer final {
public:
  ApiServer(std::shared_ptr<switch_interface> swi,
            std::shared_ptr<tap_manager> tap_man);
  void runGRPCServer();
  ~ApiServer();

private:
  NetworkStats *stats;
  std::unique_ptr<::grpc::Server> server;
};

} // namespace basebox
