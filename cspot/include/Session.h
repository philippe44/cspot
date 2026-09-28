#pragma once

#include <stdint.h>  // for uint8_t
#include <memory>    // for shared_ptr, unique_ptr
#include <mutex>     // for mutex
#include <string>    // for string
#include <vector>    // for vector

namespace cspot {
class AuthChallenges;
class LoginBlob;
class PlainConnection;
class ShannonConnection;
}  // namespace cspot

#define LOGIN_REQUEST_COMMAND 0xAB
#define AUTH_SUCCESSFUL_COMMAND 0xAC
#define AUTH_DECLINED_COMMAND 0xAD

namespace cspot {
class Session {
 protected:
  std::unique_ptr<cspot::AuthChallenges> challenges;
  std::shared_ptr<cspot::PlainConnection> conn;
  std::shared_ptr<LoginBlob> authBlob;

  /* conn and shanConn are swapped by the session's task during reconnection,
   * but other tasks send through them; they must hold this while copying the
   * pointers, and the session's task while replacing them */
  std::mutex connMutex;

  std::string deviceId = "142137fd329622137a14901634264e6f332e2411";

 public:
  Session();
  ~Session();

  std::shared_ptr<cspot::ShannonConnection> shanConn;

  void connect(std::unique_ptr<cspot::PlainConnection> connection);
  void connectWithRandomAp();
  void close();
  virtual bool triggerTimeout() = 0;
  std::vector<uint8_t> authenticate(std::shared_ptr<LoginBlob> blob);
};
}  // namespace cspot
