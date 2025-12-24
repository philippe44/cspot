#include "AccessKeyFetcher.h"

#include <cstring>           // for strrchr
#include <initializer_list>  // for initializer_list
#include <map>               // for operator!=, operator==
#include <type_traits>       // for remove_extent_t
#include <vector>            // for vector

#include "BellLogger.h"    // for AbstractLogger
#include "BellUtils.h"     // for BELL_SLEEP_MS
#include "CSpotContext.h"  // for Context
#include "HTTPClient.h"
#include "Logger.h"            // for CSPOT_LOG
#include "MercurySession.h"    // for MercurySession, MercurySession::Res...
#include "NanoPBExtensions.h"  // for bell::nanopb::encode...
#include "NanoPBHelper.h"      // for pbEncode and pbDecode
#include "Packet.h"            // for cspot
#include "TimeProvider.h"      // for TimeProvider
#include "Utils.h"             // for string_format

#ifdef BELL_ONLY_CJSON
#include "cJSON.h"
#else
#include "nlohmann/json.hpp"      // for basic_json<>::object_t, basic_json
#include "nlohmann/json_fwd.hpp"  // for json
#endif

using namespace cspot;

static std::string SCOPES =
    "streaming,user-library-read,user-library-modify,user-top-read,user-read-"
    "recently-played";  // Required access scopes

AccessKeyFetcher::AccessKeyFetcher(std::shared_ptr<cspot::Context> ctx)
    : ctx(ctx) {}

bool AccessKeyFetcher::isExpired() {
  if (accessKey.empty()) {
    return true;
  }

  if (ctx->timeProvider->getSyncedTimestamp() > expiresAt) {
    return true;
  }

  return false;
}

std::string AccessKeyFetcher::getAccessKey() {
  if (!isExpired()) {
    return accessKey;
  }

  updateAccessKey();

  return accessKey;
}

void AccessKeyFetcher::updateAccessKey() {
  if (keyPending) {
    // Already pending refresh request
    return;
  }

  keyPending = true;

  // Max retry of 3, can receive different hash cat types
  int retryCount = 3;
  bool success = false;

  do {
    CSPOT_LOG(info, "Access token expired, fetching new one...");

    std::string client_id("4f4102fa8d1d45d5bb6aea87915f4329"), client_secret("aefacafba2414d0fbfa2d8314fd3d204");
    std::string credentials;

    credentials = "grant_type=client_credentials&client_id=" + client_id + "&client_secret=" + client_secret;
    std::vector<uint8_t> body(credentials.begin(), credentials.end());
    
    auto response = bell::HTTPClient::post(
        "https://accounts.spotify.com/api/token",
        { {"Content-Type", "application/x-www-form-urlencoded"} }, body);
    
    auto responseBytes = response->bytes();

#ifdef BELL_ONLY_CJSON
    cJSON* root = cJSON_Parse(responseBytes.c_str());
    if (!cJSON_GetObjectItem(root, "error")) {
        access_key = std::string(cJSON_GetObjectItem(root, "access_token")->valuestring);
        int expiresIn = cJSON_GetObjectItem(root, "expires_in")->valueint;
        cJSON_Delete(root);
#else
    auto root = nlohmann::json::parse(responseBytes);
    if (!root.contains("error")) {
      accessKey = std::string(root["access_token"]);
      int expiresIn = root["expires_in"];
#endif
        // Successfully received an auth token
      CSPOT_LOG(info, "Access token sucessfully fetched");
      success = true;

      this->expiresAt =
            ctx->timeProvider->getSyncedTimestamp() + (expiresIn * 1000);
    }
    else {
      CSPOT_LOG(error, "Failed to fetch access token");
      BELL_SLEEP_MS(3000);
    }

    retryCount--;
  } while (retryCount >= 0 && !success);

  keyPending = false;
}
