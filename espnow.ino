/*
  ============================================================
       ESP-NOW MULTI-STATION GATEWAY
       ESP NOW Monitor
  ============================================================

  Hardware: ESP32 DevKit V1 / ESP32-WROOM-32
  Arduino ESP32 Core: 3.x

  ACCESS POINT:
    SSID: ESP Now Monitor
    Password: ILDNgateway123
    IP: 10.10.10.3

  ROUTER:
    DHCP or user-configured Static IP
    Settings saved in Preferences

  ESP-NOW:
    Receives arbitrary application payloads
    Registered and unregistered senders supported
    Automatic 20-byte ACK transmission
    Registered encrypted peers retain encryption
    Unregistered peers receive unencrypted ACKs

  DASHBOARD:
    http://10.10.10.3

  TIME:
    NTP synchronisation through configured router
    UTC and IST displayed on dashboard
    ACK includes UTC Unix timestamp in milliseconds
    IST is calculated from UTC (UTC + 5:30)
    Browser does not set the ESP32 clock

  ACK FORMAT: 20 BYTES
    Bytes 0-3   : 24JD signature
    Byte 4      : Version 1
    Byte 5      : Type 0x06
    Bytes 6-7   : Original packet length, little-endian
    Bytes 8-11  : CRC32 of original payload, little-endian
    Bytes 12-19 : Gateway UTC Unix timestamp in milliseconds,
                  little-endian uint64

  ============================================================
*/

#include <WiFi.h>
#include <WebServer.h>
#include <Preferences.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include <esp_system.h>
#include <time.h>
#include <sys/time.h>

// ============================================================
// 1. CONFIGURATION
// ============================================================

#define AP_SSID              "ESP Now Monitor"
#define AP_PASSWORD          "ILDNgateway123"

#define DEFAULT_CHANNEL      6

#define MAX_STATIONS         20
#define HISTORY_SIZE         30
#define RX_QUEUE_SIZE        16

#define OFFLINE_TIMEOUT      120000UL

#define ACK_PACKET_SIZE      20
#define ACK_VERSION          1
#define ACK_TYPE             0x06

#define MAX_DYNAMIC_PEERS    20
#define DYNAMIC_PEER_TIMEOUT 60000UL

#define RAW_PACKET_MAX_LEN   ESP_NOW_MAX_DATA_LEN

#define VALID_EPOCH_SECONDS  1700000000ULL
#define IST_OFFSET_SECONDS   19800

IPAddress apIP(10, 10, 10, 3);
IPAddress apGateway(10, 10, 10, 3);
IPAddress apSubnet(255, 255, 255, 0);

IPAddress routerStaticIP(192, 168, 1, 50);
IPAddress routerGateway(192, 168, 1, 1);
IPAddress routerSubnet(255, 255, 255, 0);
IPAddress routerDNS1(8, 8, 8, 8);
IPAddress routerDNS2(1, 1, 1, 1);

bool useStaticIP = false;

// ============================================================
// 2. DATA STRUCTURES
// ============================================================

struct Station {
  uint8_t mac[6];
  char name[24];
  uint8_t lmk[16];
  bool encrypted;
  uint32_t count;
  uint32_t lastSequence;
  uint32_t lastSeen;
};

struct ReceivedMessage {
  uint8_t mac[6];
  uint16_t len;
  uint8_t data[RAW_PACKET_MAX_LEN];
  uint32_t receivedMillis;
  uint64_t receivedUnixMs;
};

struct DynamicPeer {
  uint8_t mac[6];
  uint32_t lastUsed;
  bool active;
};

// ============================================================
// 3. GLOBAL VARIABLES
// ============================================================

Station stations[MAX_STATIONS];

ReceivedMessage history[HISTORY_SIZE];
ReceivedMessage rxQueue[RX_QUEUE_SIZE];

DynamicPeer dynamicPeers[MAX_DYNAMIC_PEERS];

uint8_t stationCount = 0;

uint8_t historyHead = 0;
uint8_t historyCount = 0;

volatile uint8_t rxHead = 0;
volatile uint8_t rxTail = 0;

portMUX_TYPE rxMux = portMUX_INITIALIZER_UNLOCKED;

Preferences prefs;
WebServer server(80);

uint8_t pmk[16];
bool pmkConfigured = false;

String routerSSID;
String routerPassword;

bool routerConnected = false;

uint8_t radioChannel = DEFAULT_CHANNEL;

volatile uint32_t totalReceived = 0;
volatile uint32_t invalidPackets = 0;
volatile uint32_t droppedPackets = 0;

volatile uint32_t ackQueued = 0;
volatile uint32_t ackQueueFailed = 0;
volatile uint32_t ackTxSuccess = 0;
volatile uint32_t ackTxFailed = 0;
volatile uint32_t ackReceived = 0;

// ============================================================
// 4. MAC ADDRESS FUNCTIONS
// ============================================================

String macString(const uint8_t *mac) {
  char buf[18];

  snprintf(
    buf, sizeof(buf),
    "%02X:%02X:%02X:%02X:%02X:%02X",
    mac[0], mac[1], mac[2],
    mac[3], mac[4], mac[5]
  );

  return String(buf);
}

bool parseMAC(String input, uint8_t *mac) {
  input.replace("-", ":");

  unsigned int v[6];

  if (sscanf(
    input.c_str(),
    "%x:%x:%x:%x:%x:%x",
    &v[0], &v[1], &v[2],
    &v[3], &v[4], &v[5]
  ) != 6) {
    return false;
  }

  for (int i = 0; i < 6; i++) {
    if (v[i] > 255) return false;
    mac[i] = (uint8_t)v[i];
  }

  return true;
}

// ============================================================
// 5. ENCRYPTION KEY FUNCTIONS
// ============================================================

bool parseHexKey(String input, uint8_t *key) {
  input.trim();

  if (input.length() != 32) return false;

  for (int i = 0; i < 16; i++) {
    char part[3] = {
      input[i * 2],
      input[i * 2 + 1],
      0
    };

    char *end;
    long value = strtol(part, &end, 16);

    if (*end != '\0') return false;

    key[i] = (uint8_t)value;
  }

  return true;
}

String hexKey(const uint8_t *key) {
  char buf[33];

  for (int i = 0; i < 16; i++) {
    sprintf(buf + i * 2, "%02X", key[i]);
  }

  buf[32] = 0;
  return String(buf);
}

// ============================================================
// 6. TIME FUNCTIONS
// ============================================================

// Returns true once NTP has supplied a valid clock value.

bool isTimeSynchronized() {
  time_t now = time(nullptr);

  return ((uint64_t)now >= VALID_EPOCH_SECONDS);
}

// Current UTC Unix timestamp in milliseconds.
// Returns zero until the clock is synchronized.

uint64_t currentUnixMs() {
  if (!isTimeSynchronized()) {
    return 0;
  }

  struct timeval tv;
  gettimeofday(&tv, nullptr);

  return (uint64_t)tv.tv_sec * 1000ULL
       + (uint64_t)tv.tv_usec / 1000ULL;
}

// Format a UTC timestamp with a specified offset.

String formatTimestampOffset(
  uint64_t epochMs,
  int32_t offsetSeconds,
  const char *zone
) {
  if (epochMs < 1700000000000ULL) {
    return "TIME NOT SYNCHRONIZED";
  }

  time_t seconds =
    (time_t)(epochMs / 1000ULL) + offsetSeconds;

  struct tm t;
  gmtime_r(&seconds, &t);

  char buf[48];

  snprintf(
    buf, sizeof(buf),
    "%04d-%02d-%02d %02d:%02d:%02d.%03llu",
    t.tm_year + 1900,
    t.tm_mon + 1,
    t.tm_mday,
    t.tm_hour,
    t.tm_min,
    t.tm_sec,
    (unsigned long long)(epochMs % 1000ULL)
  );

  return String(buf) + " " + zone;
}

// UTC display.

String formatUTC(uint64_t epochMs) {
  return formatTimestampOffset(epochMs, 0, "UTC");
}

// Indian Standard Time display.

String formatIST(uint64_t epochMs) {
  return formatTimestampOffset(
    epochMs,
    IST_OFFSET_SECONDS,
    "IST"
  );
}

// General timestamp function retained for packet history.

String formatTimestamp(uint64_t epochMs) {
  return formatUTC(epochMs);
}

// ============================================================
// 7. JSON UTILITY
// ============================================================

String jsonEscape(String input) {
  input.replace("\\", "\\\\");
  input.replace("\"", "\\\"");
  input.replace("\n", "\\n");
  input.replace("\r", "\\r");
  input.replace("\t", "\\t");

  return input;
}

// ============================================================
// 8. RAW PACKET DISPLAY FUNCTIONS
// ============================================================

String rawHex(const uint8_t *data, uint16_t len) {
  String result;
  result.reserve((size_t)len * 3);

  for (uint16_t i = 0; i < len; i++) {
    char buf[4];

    snprintf(buf, sizeof(buf), "%02X", data[i]);

    result += buf;

    if (i < len - 1) result += " ";
  }

  return result;
}

String rawText(const uint8_t *data, uint16_t len) {
  String result;
  result.reserve(len);

  for (uint16_t i = 0; i < len; i++) {
    uint8_t c = data[i];

    if (c >= 32 && c <= 126) {
      result += (char)c;
    } else {
      result += '.';
    }
  }

  return result;
}

// ============================================================
// 9. STATION MANAGEMENT
// ============================================================

int findStation(const uint8_t *mac) {
  for (int i = 0; i < stationCount; i++) {
    if (memcmp(stations[i].mac, mac, 6) == 0) {
      return i;
    }
  }

  return -1;
}

int findDynamicPeer(const uint8_t *mac) {
  for (int i = 0; i < MAX_DYNAMIC_PEERS; i++) {
    if (dynamicPeers[i].active &&
        memcmp(dynamicPeers[i].mac, mac, 6) == 0) {
      return i;
    }
  }

  return -1;
}

void forgetDynamicPeer(const uint8_t *mac) {
  int index = findDynamicPeer(mac);

  if (index >= 0) {
    dynamicPeers[index].active = false;
  }
}

bool installPeer(const Station &s) {
  esp_now_peer_info_t peer = {};

  memcpy(peer.peer_addr, s.mac, 6);

  peer.channel = radioChannel;
  peer.ifidx = WIFI_IF_AP;
  peer.encrypt = s.encrypted;

  if (s.encrypted) {
    memcpy(peer.lmk, s.lmk, 16);
  }

  return esp_now_add_peer(&peer) == ESP_OK;
}

void saveStations() {
  prefs.putUChar("count", stationCount);

  for (int i = 0; i < stationCount; i++) {
    String n = String(i);

    prefs.putBytes(
      ("mac" + n).c_str(),
      stations[i].mac, 6
    );

    prefs.putString(
      ("name" + n).c_str(),
      stations[i].name
    );

    prefs.putBool(
      ("enc" + n).c_str(),
      stations[i].encrypted
    );

    prefs.putBytes(
      ("lmk" + n).c_str(),
      stations[i].lmk, 16
    );
  }
}

bool registerStation(
  const uint8_t *mac,
  const char *name,
  const uint8_t *lmk,
  bool encrypted,
  bool persist = true
) {
  int existing = findStation(mac);

  if (encrypted && !pmkConfigured) return false;

  if (existing < 0 && stationCount >= MAX_STATIONS) {
    return false;
  }

  Station candidate = {};

  memcpy(candidate.mac, mac, 6);

  strlcpy(
    candidate.name,
    name,
    sizeof(candidate.name)
  );

  candidate.encrypted = encrypted;

  if (encrypted) {
    memcpy(candidate.lmk, lmk, 16);
  }

  if (existing >= 0) {
    candidate.count = stations[existing].count;
    candidate.lastSequence = stations[existing].lastSequence;
    candidate.lastSeen = stations[existing].lastSeen;
  }

  forgetDynamicPeer(mac);

  if (esp_now_is_peer_exist(mac)) {
    esp_now_del_peer(mac);
  }

  if (!installPeer(candidate)) {
    return false;
  }

  if (existing >= 0) {
    stations[existing] = candidate;
  } else {
    stations[stationCount++] = candidate;
  }

  if (persist) saveStations();

  return true;
}

// ============================================================
// 10. ACKNOWLEDGEMENT FUNCTIONS
// ============================================================

// Standard reflected CRC32.

uint32_t calculateCRC32(
  const uint8_t *data,
  uint16_t len
) {
  uint32_t crc = 0xFFFFFFFF;

  for (uint16_t i = 0; i < len; i++) {
    crc ^= data[i];

    for (uint8_t bit = 0; bit < 8; bit++) {
      if (crc & 1) {
        crc = (crc >> 1) ^ 0xEDB88320;
      } else {
        crc >>= 1;
      }
    }
  }

  return ~crc;
}

// Store a uint64 timestamp in little-endian byte order.

void writeUint64LE(uint8_t *destination, uint64_t value) {
  for (uint8_t i = 0; i < 8; i++) {
    destination[i] = (uint8_t)(value >> (8 * i));
  }
}

// Read a uint64 timestamp from little-endian byte order.

uint64_t readUint64LE(const uint8_t *source) {
  uint64_t value = 0;

  for (uint8_t i = 0; i < 8; i++) {
    value |= ((uint64_t)source[i]) << (8 * i);
  }

  return value;
}

// Check whether an incoming packet is a gateway ACK.
// Signature is 24JD, not ILDA.

bool isGatewayACK(
  const uint8_t *data,
  uint16_t len
) {
  if (len != ACK_PACKET_SIZE) return false;

  if (data[0] != '2' ||
      data[1] != '4' ||
      data[2] != 'J' ||
      data[3] != 'D') {
    return false;
  }

  return (
    data[4] == ACK_VERSION &&
    data[5] == ACK_TYPE
  );
}

// Construct the complete 20-byte ACK.

void buildGatewayACK(
  const ReceivedMessage &msg,
  uint8_t *ack
) {
  // Bytes 0-3: Signature "24JD"

  ack[0] = '2';
  ack[1] = '4';
  ack[2] = 'J';
  ack[3] = 'D';

  // Bytes 4-5: Version and packet type

  ack[4] = ACK_VERSION;
  ack[5] = ACK_TYPE;

  // Bytes 6-7: Original packet length, little-endian

  ack[6] = msg.len & 0xFF;
  ack[7] = (msg.len >> 8) & 0xFF;

  // Bytes 8-11: CRC32 of original application payload

  uint32_t crc = calculateCRC32(msg.data, msg.len);

  ack[8]  = crc & 0xFF;
  ack[9]  = (crc >> 8) & 0xFF;
  ack[10] = (crc >> 16) & 0xFF;
  ack[11] = (crc >> 24) & 0xFF;

  // Bytes 12-19: Gateway UTC Unix timestamp in milliseconds

  uint64_t timestamp = currentUnixMs();

  writeUint64LE(&ack[12], timestamp);
}

// ============================================================
// 11. DYNAMIC PEER MANAGEMENT
// ============================================================

int findFreeDynamicSlot() {
  for (int i = 0; i < MAX_DYNAMIC_PEERS; i++) {
    if (!dynamicPeers[i].active) return i;
  }

  return -1;
}

void removeDynamicPeer(int index) {
  if (index < 0 || index >= MAX_DYNAMIC_PEERS) return;
  if (!dynamicPeers[index].active) return;

  uint8_t mac[6];

  memcpy(mac, dynamicPeers[index].mac, 6);

  if (findStation(mac) >= 0) {
    dynamicPeers[index].active = false;
    return;
  }

  if (esp_now_is_peer_exist(mac)) {
    esp_now_del_peer(mac);
  }

  dynamicPeers[index].active = false;
}

bool evictOldestDynamicPeer() {
  int oldestIndex = -1;
  uint32_t oldestAge = 0;
  uint32_t now = millis();

  for (int i = 0; i < MAX_DYNAMIC_PEERS; i++) {
    if (!dynamicPeers[i].active) continue;

    uint32_t age = now - dynamicPeers[i].lastUsed;

    if (oldestIndex < 0 || age > oldestAge) {
      oldestIndex = i;
      oldestAge = age;
    }
  }

  if (oldestIndex < 0) return false;

  removeDynamicPeer(oldestIndex);

  return true;
}

void cleanupDynamicPeers() {
  uint32_t now = millis();

  for (int i = 0; i < MAX_DYNAMIC_PEERS; i++) {
    if (!dynamicPeers[i].active) continue;

    if (now - dynamicPeers[i].lastUsed >= DYNAMIC_PEER_TIMEOUT) {
      removeDynamicPeer(i);
    }
  }
}

bool ensureACKPeer(const uint8_t *mac) {

  if (findStation(mac) >= 0) {
    return esp_now_is_peer_exist(mac);
  }

  int dynamicIndex = findDynamicPeer(mac);

  if (dynamicIndex >= 0) {
    dynamicPeers[dynamicIndex].lastUsed = millis();

    if (esp_now_is_peer_exist(mac)) {
      return true;
    }

    dynamicPeers[dynamicIndex].active = false;
  }

  if (esp_now_is_peer_exist(mac)) {
    return true;
  }

  int slot = findFreeDynamicSlot();

  if (slot < 0) {
    if (!evictOldestDynamicPeer()) {
      Serial.println("ACK: No dynamic peer slot available");
      return false;
    }

    slot = findFreeDynamicSlot();
  }

  if (slot < 0) return false;

  esp_now_peer_info_t peer = {};

  memcpy(peer.peer_addr, mac, 6);

  peer.channel = radioChannel;
  peer.ifidx = WIFI_IF_AP;
  peer.encrypt = false;

  esp_err_t result = esp_now_add_peer(&peer);

  if (result == ESP_ERR_ESPNOW_FULL) {
    if (!evictOldestDynamicPeer()) {
      Serial.println("ACK: ESP-NOW peer table full");
      return false;
    }

    slot = findFreeDynamicSlot();

    if (slot < 0) return false;

    result = esp_now_add_peer(&peer);
  }

  if (result != ESP_OK) {
    Serial.printf(
      "ACK: Could not add temporary peer: %d\n",
      (int)result
    );

    return false;
  }

  memcpy(dynamicPeers[slot].mac, mac, 6);

  dynamicPeers[slot].lastUsed = millis();
  dynamicPeers[slot].active = true;

  return true;
}

// ============================================================
// 12. SEND ACKNOWLEDGEMENT
// ============================================================

void sendGatewayACK(const ReceivedMessage &msg) {

  if (!ensureACKPeer(msg.mac)) {
    Serial.println("ACK: Peer unavailable; ACK not sent");
    return;
  }

  uint8_t ack[ACK_PACKET_SIZE] = {};

  buildGatewayACK(msg, ack);

  uint64_t ackTimestamp = readUint64LE(&ack[12]);

  esp_err_t result = esp_now_send(
    msg.mac,
    ack,
    ACK_PACKET_SIZE
  );

  if (result == ESP_OK) {
    ackQueued++;

    Serial.println();
    Serial.println("----------- ACK QUEUED -----------");

    Serial.print("Destination: ");
    Serial.println(macString(msg.mac));

    Serial.print("ACK length: ");
    Serial.println(ACK_PACKET_SIZE);

    Serial.print("Signature: ");
    Serial.println("24JD");

    Serial.print("ACK UTC: ");
    Serial.println(formatUTC(ackTimestamp));

    Serial.print("ACK IST: ");
    Serial.println(formatIST(ackTimestamp));

    Serial.print("ACK HEX: ");
    Serial.println(rawHex(ack, ACK_PACKET_SIZE));

    Serial.println("----------------------------------");

  } else {
    ackQueueFailed++;

    Serial.print("ACK QUEUE FAILED -> ");
    Serial.print(macString(msg.mac));
    Serial.print(" | Error: ");
    Serial.println((int)result);
  }
}

void onDataSent(
  const wifi_tx_info_t *tx_info,
  esp_now_send_status_t status
) {
  (void)tx_info;

  if (status == ESP_NOW_SEND_SUCCESS) {
    ackTxSuccess++;
  } else {
    ackTxFailed++;
  }
}

// ============================================================
// 13. LOAD SAVED CONFIGURATION
// ============================================================

void loadWiFiConfiguration() {
  routerSSID = prefs.getString("wifi_ssid", "");
  routerPassword = prefs.getString("wifi_pass", "");

  useStaticIP = prefs.getBool("static_ip", false);

  String value;

  value = prefs.getString("sta_ip", "192.168.1.50");
  routerStaticIP.fromString(value);

  value = prefs.getString("sta_gw", "192.168.1.1");
  routerGateway.fromString(value);

  value = prefs.getString("sta_mask", "255.255.255.0");
  routerSubnet.fromString(value);

  value = prefs.getString("sta_dns1", "8.8.8.8");
  routerDNS1.fromString(value);

  value = prefs.getString("sta_dns2", "1.1.1.1");
  routerDNS2.fromString(value);
}

void loadConfiguration() {
  String savedPMK = prefs.getString("pmk", "");

  if (savedPMK.length() == 32) {
    pmkConfigured = parseHexKey(savedPMK, pmk);
  }

  if (pmkConfigured) {
    if (esp_now_set_pmk(pmk) != ESP_OK) {
      pmkConfigured = false;
      Serial.println("PMK initialization failed");
    }
  }

  uint8_t savedCount = prefs.getUChar("count", 0);

  if (savedCount > MAX_STATIONS) {
    savedCount = 0;
  }

  stationCount = 0;

  for (int i = 0; i < savedCount; i++) {
    String n = String(i);

    uint8_t mac[6];
    uint8_t lmk[16] = {};

    if (prefs.getBytes(
      ("mac" + n).c_str(), mac, 6
    ) != 6) {
      continue;
    }

    String name = prefs.getString(
      ("name" + n).c_str(), "STATION"
    );

    bool encrypted = prefs.getBool(
      ("enc" + n).c_str(), false
    );

    if (encrypted) {
      if (!pmkConfigured) continue;

      if (prefs.getBytes(
        ("lmk" + n).c_str(), lmk, 16
      ) != 16) {
        continue;
      }
    }

    registerStation(
      mac,
      name.c_str(),
      encrypted ? lmk : nullptr,
      encrypted,
      false
    );
  }

  saveStations();
}

// ============================================================
// 14. NTP INITIALIZATION
// ============================================================

void startNTP() {
  // Keep the system clock in UTC.
  // IST is calculated separately for display.

  configTime(
    0,
    0,
    "pool.ntp.org",
    "time.google.com",
    "time.cloudflare.com"
  );

  Serial.println("NTP time synchronisation requested");
}

void printTimeStatus() {
  if (isTimeSynchronized()) {
    uint64_t nowMs = currentUnixMs();

    Serial.println();
    Serial.println("NTP TIME SYNCHRONIZED");

    Serial.print("UTC: ");
    Serial.println(formatUTC(nowMs));

    Serial.print("IST: ");
    Serial.println(formatIST(nowMs));

  } else {
    Serial.println("NTP time not synchronized yet");
  }
}

// ============================================================
// 15. WIFI INITIALIZATION
// ============================================================

void initializeWiFi() {
  WiFi.mode(WIFI_AP_STA);
  WiFi.setSleep(false);
  WiFi.setAutoReconnect(false);

  routerConnected = false;
  radioChannel = DEFAULT_CHANNEL;

  if (routerSSID.length() > 0) {

    Serial.println();
    Serial.println("Connecting to configured Wi-Fi router");

    if (useStaticIP) {
      Serial.println("Using STATIC IP configuration");

      if (!WiFi.config(
        routerStaticIP,
        routerGateway,
        routerSubnet,
        routerDNS1,
        routerDNS2
      )) {
        Serial.println("Static IP configuration failed");
      }

    } else {
      Serial.println("Using DHCP");

      if (!WiFi.config(
        IPAddress(0, 0, 0, 0),
        IPAddress(0, 0, 0, 0),
        IPAddress(0, 0, 0, 0)
      )) {
        Serial.println("DHCP configuration reset warning");
      }
    }

    WiFi.begin(
      routerSSID.c_str(),
      routerPassword.c_str()
    );

    uint32_t start = millis();

    while (
      WiFi.status() != WL_CONNECTED &&
      millis() - start < 15000
    ) {
      delay(250);
      Serial.print(".");
    }

    Serial.println();

    if (WiFi.status() == WL_CONNECTED) {
      routerConnected = true;
      radioChannel = WiFi.channel();

      WiFi.setAutoReconnect(true);

      Serial.println("Router connected");

      Serial.print("Router IP: ");
      Serial.println(WiFi.localIP());

      Serial.print("Router channel: ");
      Serial.println(radioChannel);

      startNTP();

    } else {
      Serial.println("Router unavailable");

      WiFi.disconnect(false, false);
      WiFi.setAutoReconnect(false);
    }
  }

  if (!WiFi.softAPConfig(apIP, apGateway, apSubnet)) {
    Serial.println("AP IP configuration failed");
    ESP.restart();
  }

  if (!WiFi.softAP(
    AP_SSID,
    AP_PASSWORD,
    radioChannel,
    0,
    4
  )) {
    Serial.println("AP startup failed");
    ESP.restart();
  }

  Serial.println();
  Serial.println("================================");
  Serial.println("ESP NOW Monitor READY");

  Serial.print("AP SSID: ");
  Serial.println(AP_SSID);

  Serial.print("AP IP: ");
  Serial.println(WiFi.softAPIP());

  Serial.print("AP MAC: ");
  Serial.println(WiFi.softAPmacAddress());

  Serial.print("Radio channel: ");
  Serial.println(radioChannel);

  if (routerConnected) {
    Serial.print("Router IP: ");
    Serial.println(WiFi.localIP());
  }

  Serial.println("================================");
}

// ============================================================
// 16. ESP-NOW RECEIVE CALLBACK
// ============================================================

void onDataRecv(
  const esp_now_recv_info_t *info,
  const uint8_t *data,
  int len
) {
  if (!info || !info->src_addr || !data) return;

  if (len <= 0 || len > RAW_PACKET_MAX_LEN) {
    invalidPackets++;
    return;
  }

  ReceivedMessage msg = {};

  memcpy(msg.mac, info->src_addr, 6);

  msg.len = (uint16_t)len;

  memcpy(msg.data, data, len);

  msg.receivedMillis = millis();
  msg.receivedUnixMs = currentUnixMs();

  portENTER_CRITICAL(&rxMux);

  uint8_t next = (rxHead + 1) % RX_QUEUE_SIZE;

  if (next != rxTail) {
    memcpy(&rxQueue[rxHead], &msg, sizeof(msg));
    rxHead = next;
  } else {
    droppedPackets++;
  }

  portEXIT_CRITICAL(&rxMux);
}

// ============================================================
// 17. PROCESS RECEIVED MESSAGES
// ============================================================

void processIncoming() {

  while (true) {

    ReceivedMessage msg;
    bool available = false;

    portENTER_CRITICAL(&rxMux);

    if (rxTail != rxHead) {
      memcpy(&msg, &rxQueue[rxTail], sizeof(msg));

      rxTail = (rxTail + 1) % RX_QUEUE_SIZE;

      available = true;
    }

    portEXIT_CRITICAL(&rxMux);

    if (!available) break;

    // --------------------------------------------------------
    // ACK PACKET DETECTION
    // --------------------------------------------------------

    if (isGatewayACK(msg.data, msg.len)) {

      ackReceived++;

      uint16_t originalLength =
        (uint16_t)msg.data[6] |
        ((uint16_t)msg.data[7] << 8);

      uint32_t receivedCRC =
        (uint32_t)msg.data[8] |
        ((uint32_t)msg.data[9] << 8) |
        ((uint32_t)msg.data[10] << 16) |
        ((uint32_t)msg.data[11] << 24);

      uint64_t ackTimestamp =
        readUint64LE(&msg.data[12]);

      Serial.println();
      Serial.println("========================================");
      Serial.println("         ESP-NOW ACK RECEIVED");
      Serial.println("========================================");

      Serial.print("Sender MAC: ");
      Serial.println(macString(msg.mac));

      Serial.print("ACK signature: ");
      Serial.println("24JD");

      Serial.print("Original packet length: ");
      Serial.println(originalLength);

      Serial.printf(
        "Original packet CRC32: %08lX\n",
        (unsigned long)receivedCRC
      );

      Serial.print("ACK UTC timestamp: ");
      Serial.println(formatUTC(ackTimestamp));

      Serial.print("ACK IST timestamp: ");
      Serial.println(formatIST(ackTimestamp));

      Serial.println("ACK will not be acknowledged.");
      Serial.println("========================================");

      continue;
    }

    // --------------------------------------------------------
    // NORMAL APPLICATION PACKET
    // --------------------------------------------------------

    int index = findStation(msg.mac);

    String stationName = "UNREGISTERED";

    if (index >= 0) {
      stationName = stations[index].name;

      stations[index].count++;
      stations[index].lastSeen = msg.receivedMillis;
    }

    history[historyHead] = msg;

    historyHead = (historyHead + 1) % HISTORY_SIZE;

    if (historyCount < HISTORY_SIZE) {
      historyCount++;
    }

    totalReceived++;

    Serial.println();
    Serial.println("========================================");
    Serial.println("       ESP-NOW RAW PACKET RECEIVED");
    Serial.println("========================================");

    Serial.print("Station: ");
    Serial.println(stationName);

    Serial.print("Sender MAC: ");
    Serial.println(macString(msg.mac));

    Serial.print("Packet length: ");
    Serial.print(msg.len);
    Serial.println(" bytes");

    Serial.print("Receiver UTC: ");
    Serial.println(formatUTC(msg.receivedUnixMs));

    Serial.print("Receiver IST: ");
    Serial.println(formatIST(msg.receivedUnixMs));

    Serial.println();
    Serial.println("RAW HEX DATA:");
    Serial.println(rawHex(msg.data, msg.len));

    Serial.println();
    Serial.println("READABLE DATA:");
    Serial.println(rawText(msg.data, msg.len));

    Serial.println("========================================");

    sendGatewayACK(msg);
  }
}

// ============================================================
// 18. STATION JSON API
// ============================================================

String stationJSON() {
  String out = "[";

  for (int i = 0; i < stationCount; i++) {
    if (i) out += ",";

    Station &s = stations[i];

    bool online =
      s.lastSeen != 0 &&
      (millis() - s.lastSeen) < OFFLINE_TIMEOUT;

    out += "{";

    out += "\"name\":\"";
    out += jsonEscape(s.name);
    out += "\",";

    out += "\"mac\":\"";
    out += macString(s.mac);
    out += "\",";

    out += "\"count\":";
    out += String(s.count);
    out += ",";

    out += "\"sequence\":";
    out += String(s.lastSequence);
    out += ",";

    out += "\"encrypted\":";
    out += (s.encrypted ? "true" : "false");
    out += ",";

    out += "\"online\":";
    out += (online ? "true" : "false");
    out += ",";

    out += "\"lastSeenMs\":";
    out += String(s.lastSeen ? millis() - s.lastSeen : 0);

    out += "}";
  }

  out += "]";
  return out;
}

// ============================================================
// 19. MESSAGE HISTORY JSON API
// ============================================================

String historyJSON() {
  String out = "[";

  for (int n = 0; n < historyCount; n++) {

    int index =
      (historyHead + HISTORY_SIZE - 1 - n)
      % HISTORY_SIZE;

    ReceivedMessage &m = history[index];

    if (n) out += ",";

    int stationIndex = findStation(m.mac);

    String name = stationIndex >= 0
      ? String(stations[stationIndex].name)
      : "UNREGISTERED";

    out += "{";

    out += "\"station\":\"";
    out += jsonEscape(name);
    out += "\",";

    out += "\"mac\":\"";
    out += macString(m.mac);
    out += "\",";

    out += "\"length\":";
    out += String(m.len);
    out += ",";

    out += "\"message\":\"";
    out += jsonEscape(rawText(m.data, m.len));
    out += "\",";

    out += "\"raw\":\"";
    out += rawHex(m.data, m.len);
    out += "\",";

    out += "\"sender\":\"NOT PROVIDED\",";

    out += "\"receiver\":\"";
    out += formatTimestamp(m.receivedUnixMs);
    out += "\",";

    out += "\"receiverUTC\":\"";
    out += formatUTC(m.receivedUnixMs);
    out += "\",";

    out += "\"receiverIST\":\"";
    out += formatIST(m.receivedUnixMs);
    out += "\",";

    out += "\"uptime\":";
    out += String(m.receivedMillis);

    out += "}";
  }

  out += "]";
  return out;
}

// ============================================================
// 20. SYSTEM STATUS API
// ============================================================

void apiStatus() {
  bool connected = (WiFi.status() == WL_CONNECTED);
  routerConnected = connected;

  uint64_t nowMs = currentUnixMs();

  String out = "{";

  out += "\"mac\":\"";
  out += WiFi.softAPmacAddress();
  out += "\",";

  out += "\"ip\":\"";
  out += WiFi.softAPIP().toString();
  out += "\",";

  out += "\"routerConnected\":";
  out += (connected ? "true" : "false");
  out += ",";

  out += "\"routerIP\":\"";
  out += (connected
    ? WiFi.localIP().toString()
    : String("NOT CONNECTED"));
  out += "\",";

  out += "\"rssi\":";
  out += String(connected ? WiFi.RSSI() : 0);
  out += ",";

  out += "\"channel\":";
  out += String(radioChannel);
  out += ",";

  out += "\"heap\":";
  out += String(ESP.getFreeHeap());
  out += ",";

  out += "\"uptime\":";
  out += String(millis());
  out += ",";

  // ----------------------------------------------------------
  // TIME STATUS
  // ----------------------------------------------------------

  out += "\"timeSynced\":";
  out += (isTimeSynchronized() ? "true" : "false");
  out += ",";

  out += "\"utcTime\":\"";
  out += jsonEscape(formatUTC(nowMs));
  out += "\",";

  out += "\"istTime\":\"";
  out += jsonEscape(formatIST(nowMs));
  out += "\",";

  out += "\"unixTimeMs\":\"";
  out += String((unsigned long long)nowMs);
  out += "\",";

  // ----------------------------------------------------------
  // PACKET AND ACK COUNTERS
  // ----------------------------------------------------------

  out += "\"received\":";
  out += String(totalReceived);
  out += ",";

  out += "\"invalid\":";
  out += String(invalidPackets);
  out += ",";

  out += "\"dropped\":";
  out += String(droppedPackets);
  out += ",";

  out += "\"ackQueued\":";
  out += String(ackQueued);
  out += ",";

  out += "\"ackQueueFailed\":";
  out += String(ackQueueFailed);
  out += ",";

  out += "\"ackTxSuccess\":";
  out += String(ackTxSuccess);
  out += ",";

  out += "\"ackTxFailed\":";
  out += String(ackTxFailed);
  out += ",";

  out += "\"ackReceived\":";
  out += String(ackReceived);
  out += ",";

  // ----------------------------------------------------------
  // CONFIGURATION
  // ----------------------------------------------------------

  out += "\"pmkConfigured\":";
  out += (pmkConfigured ? "true" : "false");
  out += ",";

  out += "\"staticIP\":";
  out += (useStaticIP ? "true" : "false");
  out += ",";

  out += "\"routerSSID\":\"";
  out += jsonEscape(routerSSID);
  out += "\",";

  out += "\"staticAddress\":\"";
  out += routerStaticIP.toString();
  out += "\",";

  out += "\"gateway\":\"";
  out += routerGateway.toString();
  out += "\",";

  out += "\"subnet\":\"";
  out += routerSubnet.toString();
  out += "\",";

  out += "\"dns1\":\"";
  out += routerDNS1.toString();
  out += "\",";

  out += "\"dns2\":\"";
  out += routerDNS2.toString();
  out += "\",";

  out += "\"stations\":";
  out += stationJSON();

  out += "}";

  server.send(200, "application/json", out);
}

void apiMessages() {
  server.send(200, "application/json", historyJSON());
}

// ============================================================
// 21. CLEAR RECENT ACTIVITY API
// ============================================================

void apiClearHistory() {

  historyHead = 0;
  historyCount = 0;

  memset(history, 0, sizeof(history));

  server.send(
    200,
    "text/plain",
    "Recent activity cleared"
  );

  Serial.println();
  Serial.println("================================");
  Serial.println("RECENT ACTIVITY CLEARED");
  Serial.println("Lifetime counters preserved.");
  Serial.println("Registered stations preserved.");
  Serial.println("================================");
}

// ============================================================
// 22. RESTART GATEWAY API
// ============================================================

void apiRestart() {

  Serial.println();
  Serial.println("================================");
  Serial.println("GATEWAY RESTART REQUESTED");
  Serial.println("================================");

  server.send(
    200,
    "text/plain",
    "Gateway restarting..."
  );

  delay(700);

  ESP.restart();
}

// ============================================================
// 23. ADD STATION API
// ============================================================

void apiAddStation() {
  if (!server.hasArg("mac") || !server.hasArg("name")) {
    server.send(400, "text/plain", "MAC and station name required");
    return;
  }

  uint8_t mac[6];

  if (!parseMAC(server.arg("mac"), mac)) {
    server.send(400, "text/plain", "Invalid MAC");
    return;
  }

  uint8_t zeroMAC[6] = {};

  if ((mac[0] & 1) || memcmp(mac, zeroMAC, 6) == 0) {
    server.send(400, "text/plain", "Invalid unicast MAC");
    return;
  }

  String name = server.arg("name");
  name.trim();

  if (name.length() == 0 || name.length() > 23) {
    server.send(400, "text/plain", "Invalid station name");
    return;
  }

  String key = server.arg("lmk");
  key.trim();

  uint8_t lmk[16] = {};
  bool encrypted = key.length() > 0;

  if (encrypted) {
    if (!pmkConfigured) {
      server.send(400, "text/plain", "Configure PMK before encrypted stations");
      return;
    }

    if (!parseHexKey(key, lmk)) {
      server.send(400, "text/plain", "LMK must contain 32 hexadecimal characters");
      return;
    }
  }

  if (!registerStation(
    mac,
    name.c_str(),
    encrypted ? lmk : nullptr,
    encrypted
  )) {
    server.send(500, "text/plain", "Registration failed. Check peer capacity and keys.");
    return;
  }

  server.send(200, "text/plain", "Station registered successfully");
}

// ============================================================
// 24. DELETE STATION API
// ============================================================

void apiDeleteStation() {
  if (!server.hasArg("mac")) {
    server.send(400, "text/plain", "MAC required");
    return;
  }

  uint8_t mac[6];

  if (!parseMAC(server.arg("mac"), mac)) {
    server.send(400, "text/plain", "Invalid MAC");
    return;
  }

  int index = findStation(mac);

  if (index < 0) {
    server.send(404, "text/plain", "Station not found");
    return;
  }

  if (esp_now_is_peer_exist(mac)) {
    esp_now_del_peer(mac);
  }

  forgetDynamicPeer(mac);

  for (int i = index; i < stationCount - 1; i++) {
    stations[i] = stations[i + 1];
  }

  stationCount--;

  saveStations();

  server.send(200, "text/plain", "Station removed");
}

// ============================================================
// 25. COMMON PMK API
// ============================================================

void apiSetPMK() {
  if (!server.hasArg("pmk")) {
    server.send(400, "text/plain", "PMK required");
    return;
  }

  uint8_t newKey[16];

  if (!parseHexKey(server.arg("pmk"), newKey)) {
    server.send(400, "text/plain", "PMK must contain 32 hexadecimal characters");
    return;
  }

  for (int i = 0; i < stationCount; i++) {
    if (esp_now_is_peer_exist(stations[i].mac)) {
      esp_now_del_peer(stations[i].mac);
    }
  }

  memcpy(pmk, newKey, 16);

  if (esp_now_set_pmk(pmk) != ESP_OK) {
    server.send(500, "text/plain", "PMK update failed");
    return;
  }

  pmkConfigured = true;

  bool failed = false;

  for (int i = 0; i < stationCount; i++) {
    if (!installPeer(stations[i])) {
      failed = true;
    }
  }

  if (failed) {
    server.send(500, "text/plain", "PMK set, but one or more peers could not be restored");
    return;
  }

  prefs.putString("pmk", hexKey(pmk));

  server.send(
    200,
    "text/plain",
    "PMK saved. Update all encrypted transmitters with the new PMK."
  );
}

// ============================================================
// 26. ROUTER WIFI CONFIGURATION API
// ============================================================

bool readIPArgument(const char *name, IPAddress &address) {
  if (!server.hasArg(name)) return false;

  String value = server.arg(name);
  value.trim();

  IPAddress parsed;

  if (!parsed.fromString(value)) return false;

  address = parsed;
  return true;
}

void apiSetWiFi() {
  if (!server.hasArg("ssid") ||
      !server.hasArg("password") ||
      !server.hasArg("mode")) {
    server.send(400, "text/plain", "SSID, password and IP mode are required");
    return;
  }

  String ssid = server.arg("ssid");
  String password = server.arg("password");
  String mode = server.arg("mode");

  ssid.trim();
  mode.trim();

  if (ssid.length() == 0 || ssid.length() > 32 ||
      password.length() > 63 ||
      (password.length() > 0 && password.length() < 8)) {
    server.send(400, "text/plain", "Invalid Wi-Fi credentials");
    return;
  }

  bool newStaticMode = (mode == "static");

  IPAddress newIP, newGateway, newSubnet, newDNS1, newDNS2;

  if (newStaticMode) {
    if (!readIPArgument("ip", newIP) ||
        !readIPArgument("gateway", newGateway) ||
        !readIPArgument("subnet", newSubnet) ||
        !readIPArgument("dns1", newDNS1) ||
        !readIPArgument("dns2", newDNS2)) {
      server.send(400, "text/plain", "One or more IP fields are invalid");
      return;
    }

    if (newIP == IPAddress(0, 0, 0, 0) ||
        newGateway == IPAddress(0, 0, 0, 0) ||
        newSubnet == IPAddress(0, 0, 0, 0)) {
      server.send(400, "text/plain", "IP, gateway and subnet cannot be 0.0.0.0");
      return;
    }

    if (newIP == newGateway) {
      server.send(400, "text/plain", "ESP32 IP and gateway must be different");
      return;
    }

    if (newIP == apIP) {
      server.send(400, "text/plain", "Router IP cannot be 10.10.10.3");
      return;
    }
  }

  prefs.putString("wifi_ssid", ssid);
  prefs.putString("wifi_pass", password);
  prefs.putBool("static_ip", newStaticMode);

  if (newStaticMode) {
    prefs.putString("sta_ip", newIP.toString());
    prefs.putString("sta_gw", newGateway.toString());
    prefs.putString("sta_mask", newSubnet.toString());
    prefs.putString("sta_dns1", newDNS1.toString());
    prefs.putString("sta_dns2", newDNS2.toString());
  }

  server.send(
    200,
    "text/plain",
    "Wi-Fi settings saved. Gateway restarting."
  );

  delay(1000);
  ESP.restart();
}

// ============================================================
// 27. DASHBOARD HTML
// ============================================================

const char DASHBOARD[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1">

<meta name="theme-color" content="#0b1220">

<title>ESP-NOW Monitor</title>

<style>

:root {
  --background: #0b1220;
  --surface: #111c2e;
  --surface2: #172438;
  --border: #263750;
  --text: #e5edf8;
  --muted: #91a4bd;
  --green: #22c55e;
  --blue: #38bdf8;
  --orange: #f59e0b;
  --red: #ef4444;
}

* {
  box-sizing: border-box;
}

body {
  background: var(--background);
  color: var(--text);
  font-family: Inter, system-ui, -apple-system,
    BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
  margin: 0;
  padding: 22px;
  line-height: 1.5;
}

.container {
  max-width: 1500px;
  margin: auto;
}

h1, h2, h3 {
  margin-top: 0;
}

h1 {
  font-size: 25px;
  letter-spacing: .3px;
}

h2 {
  font-size: 19px;
}

h3 {
  font-size: 15px;
  color: #b9d8fa;
  margin-bottom: 16px;
}

small {
  color: var(--muted);
}

p {
  color: var(--muted);
}

.header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 18px;
  margin-bottom: 24px;
}

.brand {
  display: flex;
  align-items: center;
  gap: 13px;
}

.brand-icon {
  width: 48px;
  height: 48px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 13px;
  background: #123a31;
  color: #4ade80;
  font-size: 26px;
}

.brand-subtitle {
  color: var(--muted);
  font-size: 12px;
  letter-spacing: 1.5px;
  text-transform: uppercase;
}

.header-status {
  display: flex;
  align-items: center;
  gap: 9px;
  padding: 9px 14px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 30px;
  font-size: 12px;
  font-weight: bold;
}

.status-dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background: var(--green);
  box-shadow: 0 0 9px var(--green);
}

.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 20px;
  margin-bottom: 18px;
  box-shadow: 0 5px 18px rgba(0,0,0,.12);
  overflow-x: auto;
}

.card-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 16px;
}

.card-heading h3 {
  margin: 0;
}

.section-label {
  font-size: 11px;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 1.3px;
  margin-bottom: 7px;
}

.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(155px, 1fr));
  gap: 12px;
}

.metric-card {
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 15px;
  min-width: 0;
}

.metric-label {
  color: var(--muted);
  font-size: 12px;
  margin-bottom: 9px;
}

.metric {
  color: var(--green);
  font-size: 25px;
  font-weight: 750;
  letter-spacing: .3px;
  overflow-wrap: anywhere;
}

.metric.blue {
  color: var(--blue);
}

.metric.orange {
  color: var(--orange);
}

.metric.red {
  color: #fb7185;
}

.metric.small {
  font-size: 14px;
}

button {
  border: 0;
  border-radius: 8px;
  padding: 11px 16px;
  color: white;
  font-size: 13px;
  font-weight: 650;
  cursor: pointer;
  transition: background .18s ease, transform .15s ease, opacity .15s ease;
}

button:hover {
  filter: brightness(1.12);
}

button:active {
  transform: scale(.98);
}

button:disabled {
  opacity: .5;
  cursor: not-allowed;
}

.button-green {
  background: #15803d;
}

.button-blue {
  background: #0369a1;
}

.button-orange {
  background: #b45309;
}

.button-red {
  background: #b91c1c;
}

.button-secondary {
  background: #334155;
}

.button-delete {
  background: #991b1b;
  padding: 7px 11px;
  font-size: 12px;
}

.control-buttons {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
}

.control-buttons button {
  min-height: 44px;
  padding: 12px 20px;
}

.table-wrapper {
  width: 100%;
  overflow-x: auto;
}

table {
  width: 100%;
  border-collapse: collapse;
  min-width: 700px;
}

th {
  text-align: left;
  color: var(--muted);
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: .8px;
  padding: 12px;
  border-bottom: 1px solid var(--border);
}

td {
  padding: 12px;
  border-bottom: 1px solid var(--border);
  font-size: 13px;
  vertical-align: top;
}

tr:last-child td {
  border-bottom: 0;
}

tbody tr:hover {
  background: rgba(255,255,255,.025);
}

.online {
  color: var(--green);
  font-weight: bold;
}

.offline {
  color: #fb7185;
  font-weight: bold;
}

.status-pill {
  display: inline-block;
  padding: 4px 9px;
  border-radius: 30px;
  font-size: 11px;
  font-weight: bold;
}

.status-online {
  background: rgba(34,197,94,.13);
  color: #4ade80;
}

.status-offline {
  background: rgba(239,68,68,.13);
  color: #fb7185;
}

label {
  display: block;
  color: #cbd5e1;
  font-size: 12px;
  font-weight: 600;
  margin-top: 12px;
}

input, select {
  width: 100%;
  padding: 12px;
  margin-top: 7px;
  margin-bottom: 8px;
  border: 1px solid #354861;
  border-radius: 8px;
  background: #0b1525;
  color: white;
  font-size: 13px;
}

input:focus, select:focus {
  outline: none;
  border-color: var(--blue);
  box-shadow: 0 0 0 2px rgba(56,189,248,.12);
}

.ipFields {
  border: 1px solid var(--border);
  background: var(--surface2);
  padding: 15px;
  border-radius: 10px;
  margin: 12px 0;
}

.hidden {
  display: none;
}

pre {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  font-size: 12px;
  line-height: 1.8;
  background: #091321;
  border: 1px solid var(--border);
  border-radius: 9px;
  padding: 15px;
  color: #c7d8ed;
  margin: 0;
}

.raw {
  max-width: 350px;
  word-break: break-all;
  font-family: monospace;
  color: #93c5fd;
}

.note {
  color: var(--orange);
  font-size: 12px;
  line-height: 1.6;
  margin-bottom: 0;
}

.empty-state {
  text-align: center;
  padding: 25px;
  color: var(--muted);
  font-size: 13px;
}

.footer {
  text-align: center;
  color: #64748b;
  font-size: 11px;
  padding: 15px 0 5px;
}

@media(max-width: 700px) {
  body {
    padding: 11px;
  }

  .header {
    align-items: flex-start;
  }

  h1 {
    font-size: 21px;
  }

  .card {
    padding: 14px;
  }

  .grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .metric {
    font-size: 21px;
  }

  .control-buttons {
    flex-direction: column;
  }

  .control-buttons button {
    width: 100%;
  }
}

@media(max-width: 360px) {
  .grid {
    grid-template-columns: 1fr;
  }
}

</style>
</head>

<body>

<div class="container">

<div class="header">

  <div class="brand">

    <div class="brand-icon">⚡</div>

    <div>
      <h1>ESP-NOW Monitor</h1>
      <div class="brand-subtitle">
        Multi-station wireless gateway
      </div>
    </div>

  </div>

  <div class="header-status">
    <span class="status-dot"></span>
    GATEWAY ACTIVE
  </div>

</div>

<!-- RECEIVER TELEMETRY -->

<div class="card">

  <div class="card-heading">
    <h3>Receiver telemetry</h3>
    <small>Live gateway status</small>
  </div>

  <div class="grid">

    <div class="metric-card">
      <div class="metric-label">Receiver MAC</div>
      <div class="metric small" id="mac">--</div>
    </div>

    <div class="metric-card">
      <div class="metric-label">Access Point IP</div>
      <div class="metric" id="ip">--</div>
    </div>

    <div class="metric-card">
      <div class="metric-label">Router IP</div>
      <div class="metric small" id="routerIP">--</div>
    </div>

    <div class="metric-card">
      <div class="metric-label">Packets received</div>
      <div class="metric" id="received">0</div>
    </div>

    <div class="metric-card">
      <div class="metric-label">Registered stations</div>
      <div class="metric" id="stationCount">0</div>
    </div>

    <div class="metric-card">
      <div class="metric-label">Free heap</div>
      <div class="metric" id="heap">--</div>
    </div>

    <div class="metric-card">
      <div class="metric-label">Radio channel</div>
      <div class="metric blue" id="channel">--</div>
    </div>

    <div class="metric-card">
      <div class="metric-label">Router connection</div>
      <div class="metric small" id="routerStatus">--</div>
    </div>

    <div class="metric-card">
      <div class="metric-label">Dropped packets</div>
      <div class="metric orange" id="dropped">0</div>
    </div>

    <div class="metric-card">
      <div class="metric-label">Invalid packets</div>
      <div class="metric red" id="invalid">0</div>
    </div>

    <div class="metric-card">
      <div class="metric-label">Gateway time (UTC)</div>
      <div class="metric small" id="utcTime">Waiting for NTP...</div>
    </div>

    <div class="metric-card">
      <div class="metric-label">Gateway time (IST)</div>
      <div class="metric small" id="istTime">Waiting for NTP...</div>
    </div>

    <div class="metric-card">
      <div class="metric-label">Clock synchronisation</div>
      <div class="metric small" id="timeStatus">WAITING FOR NTP</div>
    </div>

  </div>

</div>

<!-- GATEWAY CONTROLS -->

<div class="card">

  <div class="card-heading">
    <h3>Gateway controls</h3>
    <small>System management</small>
  </div>

  <div class="control-buttons">

    <button class="button-orange" onclick="clearActivity()">
      Clear recent activity
    </button>

    <button class="button-red" onclick="restartGateway()">
      ↻ Restart ESP32 gateway
    </button>

  </div>

  <p class="note">
    Clear activity removes the displayed packet history only.
    Lifetime counters, registered stations and saved settings remain intact.
    Restart reboots the gateway and preserves saved configuration.
  </p>

</div>

<!-- ACK STATISTICS -->

<div class="card">

  <div class="card-heading">
    <h3>ACK transmission statistics</h3>
    <small>Application acknowledgement monitoring</small>
  </div>

  <div class="grid">

    <div class="metric-card">
      <div class="metric-label">ACK queued</div>
      <div class="metric" id="ackQueued">0</div>
    </div>

    <div class="metric-card">
      <div class="metric-label">ACK queue failures</div>
      <div class="metric orange" id="ackQueueFailed">0</div>
    </div>

    <div class="metric-card">
      <div class="metric-label">ACK TX success</div>
      <div class="metric" id="ackTxSuccess">0</div>
    </div>

    <div class="metric-card">
      <div class="metric-label">ACK TX failures</div>
      <div class="metric red" id="ackTxFailed">0</div>
    </div>

    <div class="metric-card">
      <div class="metric-label">ACK packets received</div>
      <div class="metric blue" id="ackReceived">0</div>
    </div>

  </div>

  <p class="note">
    ACK TX success is the ESP-NOW transmission callback result.
    It does not confirm that the remote application validated the ACK.
  </p>

</div>

<!-- REGISTERED STATIONS -->

<div class="card">

  <div class="card-heading">
    <h3>Registered ESP32 stations</h3>
    <small>Station registry</small>
  </div>

  <div class="table-wrapper">

    <table>

      <thead>
        <tr>
          <th>Name</th>
          <th>MAC</th>
          <th>Status</th>
          <th>Packets</th>
          <th>Last seen</th>
          <th>Security</th>
          <th>Action</th>
        </tr>
      </thead>

      <tbody id="stations">
        <tr>
          <td colspan="7" class="empty-state">
            Loading registered stations...
          </td>
        </tr>
      </tbody>

    </table>

  </div>

</div>

<!-- ADD STATION -->

<div class="card">

  <div class="card-heading">
    <h3>Register new station</h3>
    <small>ESP-NOW peer configuration</small>
  </div>

  <label>Station name</label>
  <input id="name" placeholder="ILDN-SENSOR-01" maxlength="23">

  <label>Sender MAC address</label>
  <input id="senderMac" placeholder="AA:BB:CC:11:22:33">

  <label>Individual LMK (32 hexadecimal characters)</label>
  <input id="lmk" type="password"
    placeholder="Leave blank for unencrypted station">

  <button class="button-green" onclick="addStation()">
    + Register station
  </button>

  <p>
    <small>
      Configure the common PMK first if using encryption.
    </small>
  </p>

  <p class="note">
    Unregistered senders can still be received and displayed.
    Unregistered senders receive unencrypted ACKs.
  </p>

</div>

<!-- ENCRYPTION -->

<div class="card">

  <div class="card-heading">
    <h3>ESP-NOW encryption configuration</h3>
    <small>Network security</small>
  </div>

  <label>Common PMK (32 hexadecimal characters)</label>
  <input id="pmk" type="password"
    placeholder="Enter common network PMK">

  <button class="button-blue" onclick="setPMK()">
    Save PMK
  </button>

  <p>
    <small>
      The PMK must match all encrypted transmitters.
      Each station has its own LMK. Changing the PMK requires
      updating the transmitters.
    </small>
  </p>

</div>

<!-- ROUTER CONFIGURATION -->

<div class="card">

  <div class="card-heading">
    <h3>Wi-Fi router configuration</h3>
    <small>Internet / LAN connectivity</small>
  </div>

  <label>Router SSID</label>
  <input id="wifiSSID" placeholder="Enter Wi-Fi network name">

  <label>Router password</label>
  <input id="wifiPassword" type="password"
    placeholder="Enter Wi-Fi password">

  <label>Router IP assignment</label>

  <select id="ipMode" onchange="toggleIPFields()">
    <option value="dhcp">DHCP - Obtain IP automatically</option>
    <option value="static">Static IP - Enter IP manually</option>
  </select>

  <div id="staticFields" class="ipFields hidden">

    <h3>Static IP settings</h3>

    <label>ESP32 router-side IP address</label>
    <input id="staticIP" value="192.168.1.50">

    <label>Gateway / router address</label>
    <input id="gateway" value="192.168.1.1">

    <label>Subnet mask</label>
    <input id="subnet" value="255.255.255.0">

    <label>Primary DNS</label>
    <input id="dns1" value="8.8.8.8">

    <label>Secondary DNS</label>
    <input id="dns2" value="1.1.1.1">

    <p class="note">
      Choose an unused address on your router's network.
      Ideally reserve this address in your router's DHCP settings
      or choose an address outside its DHCP pool.
    </p>

  </div>

  <button class="button-blue" onclick="saveWiFi()">
    Save Wi-Fi settings and restart
  </button>

  <p>
    <small>
      The ESP32 access point remains at 10.10.10.3.
      The router connection and access point are separate interfaces.
      ESP-NOW and Wi-Fi share the same radio channel.
    </small>
  </p>

</div>

<!-- LATEST PACKET -->

<div class="card">

  <div class="card-heading">
    <h3>Latest incoming packet</h3>
    <small>Most recently received application message</small>
  </div>

  <pre id="latest">Waiting for ESP-NOW packets...</pre>

</div>

<!-- PACKET HISTORY -->

<div class="card">

  <div class="card-heading">
    <h3>Incoming raw packet history</h3>

    <button class="button-orange" onclick="clearActivity()">
      Clear history
    </button>
  </div>

  <div class="table-wrapper">

    <table>

      <thead>
        <tr>
          <th>Station</th>
          <th>Sender MAC</th>
          <th>Length</th>
          <th>Receiver timestamp (UTC / IST)</th>
          <th>Readable data</th>
          <th>Raw hexadecimal</th>
        </tr>
      </thead>

      <tbody id="messages">
        <tr>
          <td colspan="6" class="empty-state">
            Waiting for incoming packets...
          </td>
        </tr>
      </tbody>

    </table>

  </div>

</div>

<!-- SYSTEM INFORMATION -->

<div class="card">

  <div class="card-heading">
    <h3>Gateway information</h3>
    <small>System diagnostics</small>
  </div>

  <pre id="systemInfo">Loading...</pre>

</div>

<div class="footer">
  ESP-NOW MULTI-STATION GATEWAY
  <br>
  ESP NOW Monitor
</div>

</div>

<script>

// =================================================
// API FUNCTIONS
// =================================================

async function getJSON(url) {
  const r = await fetch(url);

  if (!r.ok) {
    throw new Error(await r.text());
  }

  return r.json();
}

async function post(url, data) {
  const r = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams(data)
  });

  const t = await r.text();

  if (!r.ok) {
    throw new Error(t);
  }

  return t;
}

// =================================================
// CLEAR RECENT ACTIVITY
// =================================================

async function clearActivity() {

  if (!confirm(
    'Clear all recent packet activity?\n\n' +
    'This will clear the recent packet history and latest packet display.\n\n' +
    'Registered stations and lifetime counters will remain unchanged.'
  )) {
    return;
  }

  try {
    const message = await post('/api/clear', {});

    document.getElementById('latest').textContent =
      'Waiting for ESP-NOW packets...';

    document.getElementById('messages').innerHTML =
      '<tr><td colspan="6" class="empty-state">' +
      'Activity cleared. Waiting for incoming packets...' +
      '</td></tr>';

    await refresh();

    alert(message);

  } catch(e) {
    alert('Could not clear activity: ' + e.message);
  }
}

// =================================================
// RESTART GATEWAY
// =================================================

async function restartGateway() {

  if (!confirm(
    'RESTART ESP32 GATEWAY?\n\n' +
    'The dashboard and access point will temporarily disconnect.\n\n' +
    'Saved stations, encryption keys and Wi-Fi settings will be preserved.'
  )) {
    return;
  }

  try {
    await post('/api/restart', {});
  } catch(e) {
    console.log('Gateway restart requested.');
  }

  document.body.innerHTML =
    '<div style="' +
    'min-height:90vh;' +
    'display:flex;' +
    'align-items:center;' +
    'justify-content:center;' +
    'text-align:center;' +
    'font-family:Arial;' +
    'color:#e5edf8;' +
    'background:#0b1220;' +
    'padding:20px;' +
    '">' +
    '<div>' +
    '<div style="font-size:42px">↻</div>' +
    '<h2>Gateway restarting</h2>' +
    '<p style="color:#91a4bd">' +
    'Please wait for the ESP32 access point to return.' +
    '</p>' +
    '<p style="color:#91a4bd">' +
    'Then reconnect and open http://10.10.10.3' +
    '</p>' +
    '</div></div>';
}

// =================================================
// WIFI IP MODE
// =================================================

function toggleIPFields() {
  const mode = document.getElementById('ipMode').value;

  document.getElementById('staticFields').classList.toggle(
    'hidden',
    mode !== 'static'
  );
}

function validIPv4(value) {
  const parts = value.trim().split('.');

  if (parts.length !== 4) return false;

  return parts.every(p =>
    /^\d{1,3}$/.test(p) &&
    Number(p) >= 0 &&
    Number(p) <= 255
  );
}

function populateWiFiSettings(s) {

  if (s.routerSSID) {
    document.getElementById('wifiSSID').value = s.routerSSID;
  }

  document.getElementById('ipMode').value =
    s.staticIP ? 'static' : 'dhcp';

  document.getElementById('staticIP').value = s.staticAddress;
  document.getElementById('gateway').value = s.gateway;
  document.getElementById('subnet').value = s.subnet;
  document.getElementById('dns1').value = s.dns1;
  document.getElementById('dns2').value = s.dns2;

  toggleIPFields();
}

// =================================================
// REGISTER STATION
// =================================================

async function addStation() {

  try {
    await post('/api/add', {
      name: document.getElementById('name').value,
      mac: document.getElementById('senderMac').value,
      lmk: document.getElementById('lmk').value
    });

    document.getElementById('name').value = '';
    document.getElementById('senderMac').value = '';
    document.getElementById('lmk').value = '';

    await refresh();

    alert('Station registered successfully.');

  } catch(e) {
    alert(e.message);
  }
}

// =================================================
// DELETE STATION
// =================================================

async function deleteStation(mac) {

  if (!confirm('Remove station ' + mac + '?')) return;

  try {
    await post('/api/delete', { mac: mac });

    await refresh();

    alert('Station removed.');

  } catch(e) {
    alert(e.message);
  }
}

// =================================================
// SAVE PMK
// =================================================

async function setPMK() {

  const pmk = document.getElementById('pmk').value;

  if (!/^[0-9a-fA-F]{32}$/.test(pmk)) {
    alert('PMK must contain exactly 32 hexadecimal characters');
    return;
  }

  try {
    await post('/api/pmk', { pmk: pmk });

    document.getElementById('pmk').value = '';

  } catch(e) {
    alert(e.message);
  }
}

// =================================================
// SAVE ROUTER SETTINGS
// =================================================

async function saveWiFi() {

  const ssid =
    document.getElementById('wifiSSID').value.trim();

  const password =
    document.getElementById('wifiPassword').value;

  const mode =
    document.getElementById('ipMode').value;

  if (!ssid) {
    alert('Enter router SSID');
    return;
  }

  if (password.length > 0 && password.length < 8) {
    alert('Password must be at least 8 characters');
    return;
  }

  const data = {
    ssid: ssid,
    password: password,
    mode: mode
  };

  if (mode === 'static') {

    const fields = [
      ['ip', 'staticIP'],
      ['gateway', 'gateway'],
      ['subnet', 'subnet'],
      ['dns1', 'dns1'],
      ['dns2', 'dns2']
    ];

    for (const [key, id] of fields) {

      const value =
        document.getElementById(id).value.trim();

      if (!validIPv4(value)) {
        alert('Invalid IPv4 address in ' + key);
        return;
      }

      data[key] = value;
    }
  }

  const description = mode === 'static'
    ? 'Static IP: ' + data.ip
    : 'DHCP automatic IP assignment';

  if (!confirm(
    'Save router settings and restart gateway?\n\n' +
    description
  )) {
    return;
  }

  try {
    await post('/api/wifi', data);
  } catch(e) {
    console.log('Wi-Fi configuration submitted.');
  }
}

// =================================================
// HTML ESCAPING
// =================================================

function escapeHTML(v) {
  return String(v).replace(/[&<>"']/g,
    c => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    }[c])
  );
}

// =================================================
// DASHBOARD REFRESH
// =================================================

let settingsLoaded = false;

async function refresh() {

  try {

    const s = await getJSON('/api/status');

    // -------------------------------------------------
    // RECEIVER TELEMETRY
    // -------------------------------------------------

    document.getElementById('mac').textContent = s.mac;
    document.getElementById('ip').textContent = s.ip;
    document.getElementById('routerIP').textContent = s.routerIP;

    document.getElementById('received').textContent = s.received;

    document.getElementById('stationCount').textContent =
      s.stations.length;

    document.getElementById('heap').textContent =
      Math.round(s.heap / 1024) + ' KB';

    document.getElementById('channel').textContent = s.channel;

    const routerStatus =
      document.getElementById('routerStatus');

    routerStatus.textContent =
      s.routerConnected ? 'CONNECTED' : 'OFFLINE';

    routerStatus.style.color =
      s.routerConnected ? '#4ade80' : '#fb7185';

    document.getElementById('dropped').textContent = s.dropped;
    document.getElementById('invalid').textContent = s.invalid;

    // -------------------------------------------------
    // GATEWAY TIME
    // -------------------------------------------------

    document.getElementById('utcTime').textContent =
      s.utcTime;

    document.getElementById('istTime').textContent =
      s.istTime;

    const timeStatus =
      document.getElementById('timeStatus');

    timeStatus.textContent =
      s.timeSynced ? 'NTP SYNCHRONIZED' : 'WAITING FOR NTP';

    timeStatus.style.color =
      s.timeSynced ? '#4ade80' : '#f59e0b';

    // -------------------------------------------------
    // ACK STATISTICS
    // -------------------------------------------------

    document.getElementById('ackQueued').textContent =
      s.ackQueued;

    document.getElementById('ackQueueFailed').textContent =
      s.ackQueueFailed;

    document.getElementById('ackTxSuccess').textContent =
      s.ackTxSuccess;

    document.getElementById('ackTxFailed').textContent =
      s.ackTxFailed;

    document.getElementById('ackReceived').textContent =
      s.ackReceived;

    // -------------------------------------------------
    // WIFI SETTINGS
    // -------------------------------------------------

    if (!settingsLoaded) {
      populateWiFiSettings(s);
      settingsLoaded = true;
    }

    // -------------------------------------------------
    // REGISTERED STATIONS
    // -------------------------------------------------

    const stationTable =
      document.getElementById('stations');

    if (s.stations.length === 0) {

      stationTable.innerHTML =
        '<tr><td colspan="7" class="empty-state">' +
        'No registered stations.' +
        '</td></tr>';

    } else {

      stationTable.innerHTML =
        s.stations.map(x => `

          <tr>

            <td>
              <strong>${escapeHTML(x.name)}</strong>
            </td>

            <td>${escapeHTML(x.mac)}</td>

            <td>
              <span class="status-pill ${
                x.online
                  ? 'status-online'
                  : 'status-offline'
              }">
                ${x.online ? 'ONLINE' : 'OFFLINE'}
              </span>
            </td>

            <td>${x.count}</td>

            <td>
              ${x.lastSeenMs
                ? Math.round(x.lastSeenMs / 1000) + ' sec'
                : 'Never'}
            </td>

            <td>
              ${x.encrypted ? 'ENCRYPTED' : 'OPEN'}
            </td>

            <td>
              <button
                class="button-delete"
                onclick="deleteStation('${x.mac}')">
                Remove
              </button>
            </td>

          </tr>

        `).join('');
    }

    // -------------------------------------------------
    // INCOMING PACKET HISTORY
    // -------------------------------------------------

    const m = await getJSON('/api/messages');

    const messageTable =
      document.getElementById('messages');

    if (m.length === 0) {

      messageTable.innerHTML =
        '<tr><td colspan="6" class="empty-state">' +
        'No recent packet activity.' +
        '</td></tr>';

      document.getElementById('latest').textContent =
        'Waiting for ESP-NOW packets...';

    } else {

      messageTable.innerHTML =
        m.map(x => `

          <tr>

            <td>
              <strong>${escapeHTML(x.station)}</strong>
            </td>

            <td>${escapeHTML(x.mac)}</td>

            <td>${x.length} bytes</td>

            <td>
              ${escapeHTML(x.receiverUTC)}
              <br>
              ${escapeHTML(x.receiverIST)}
            </td>

            <td>${escapeHTML(x.message)}</td>

            <td class="raw">${escapeHTML(x.raw)}</td>

          </tr>

        `).join('');

      // -------------------------------------------------
      // LATEST PACKET
      // -------------------------------------------------

      const x = m[0];

      document.getElementById('latest').textContent =

        'STATION: ' + x.station +

        '\nSENDER MAC: ' + x.mac +

        '\nPACKET LENGTH: ' + x.length + ' bytes' +

        '\nRECEIVER UTC: ' + x.receiverUTC +

        '\nRECEIVER IST: ' + x.receiverIST +

        '\n\nREADABLE DATA:\n' + x.message +

        '\n\nRAW HEX DATA:\n' + x.raw;
    }

    // -------------------------------------------------
    // SYSTEM INFORMATION
    // -------------------------------------------------

    document.getElementById('systemInfo').textContent =

      'AP SSID: ESP NOW Monitor' +

      '\nAP IP: ' + s.ip +

      '\nAP MAC: ' + s.mac +

      '\nRADIO CHANNEL: ' + s.channel +

      '\nROUTER CONNECTED: ' + s.routerConnected +

      '\nROUTER IP: ' + s.routerIP +

      '\nIP MODE: ' + (s.staticIP ? 'STATIC' : 'DHCP') +

      '\nSTATIC IP SETTING: ' + s.staticAddress +

      '\nGATEWAY: ' + s.gateway +

      '\nSUBNET: ' + s.subnet +

      '\nPMK CONFIGURED: ' + s.pmkConfigured +

      '\nTIME SYNCHRONIZED: ' + s.timeSynced +

      '\nUTC TIME: ' + s.utcTime +

      '\nIST TIME: ' + s.istTime +

      '\nACK SIGNATURE: 24JD' +

      '\nACK PACKET SIZE: 20 bytes' +

      '\nACK TIMESTAMP: UTC Unix milliseconds' +

      '\nACK QUEUED: ' + s.ackQueued +

      '\nACK QUEUE FAILURES: ' + s.ackQueueFailed +

      '\nACK TX SUCCESS: ' + s.ackTxSuccess +

      '\nACK TX FAILURES: ' + s.ackTxFailed +

      '\nACK RECEIVED: ' + s.ackReceived +

      '\nUPTIME: ' + Math.round(s.uptime / 1000) + ' seconds';

  } catch(e) {
    console.log('Dashboard refresh error:', e);
  }
}

// =================================================
// START DASHBOARD
// =================================================

toggleIPFields();

setInterval(refresh, 1000);

refresh();

</script>

</body>
</html>
)rawliteral";

// ============================================================
// 28. WEB SERVER INITIALIZATION
// ============================================================

void setupWebServer() {

  server.on("/", HTTP_GET, []() {
    server.send_P(200, "text/html", DASHBOARD);
  });

  server.on("/api/status", HTTP_GET, apiStatus);
  server.on("/api/messages", HTTP_GET, apiMessages);

  // The old /api/time endpoint has been removed.
  // The browser no longer sets the ESP32 clock.

  server.on("/api/add", HTTP_POST, apiAddStation);
  server.on("/api/delete", HTTP_POST, apiDeleteStation);
  server.on("/api/pmk", HTTP_POST, apiSetPMK);
  server.on("/api/wifi", HTTP_POST, apiSetWiFi);

  server.on("/api/clear", HTTP_POST, apiClearHistory);
  server.on("/api/restart", HTTP_POST, apiRestart);

  server.begin();

  Serial.println("Web server started");
}

// ============================================================
// 29. SETUP
// ============================================================

void setup() {

  Serial.begin(115200);
  delay(1000);

  Serial.println();
  Serial.println("================================");
  Serial.println("ESP-NOW GATEWAY");
  Serial.println("ESP NOW Monitor");
  Serial.println("ACK signature: 24JD");
  Serial.println("ACK size: 20 bytes");
  Serial.println("================================");

  prefs.begin("ildn-gateway", false);

  loadWiFiConfiguration();

  initializeWiFi();

  if (esp_now_init() != ESP_OK) {
    Serial.println("ESP-NOW initialization failed");
    ESP.restart();
  }

  Serial.println("ESP-NOW initialized");

  loadConfiguration();

  if (esp_now_register_recv_cb(onDataRecv) != ESP_OK) {
    Serial.println("Receive callback registration failed");
    ESP.restart();
  }

  if (esp_now_register_send_cb(onDataSent) != ESP_OK) {
    Serial.println("Send callback registration failed");
    ESP.restart();
  }

  Serial.println("ESP-NOW receive callback registered");
  Serial.println("ESP-NOW send callback registered");
  Serial.println("Automatic 20-byte ACK transmission enabled");

  setupWebServer();

  Serial.println();
  Serial.println("GATEWAY READY");
  Serial.println("Connect to: ESP NOW Monitor");
  Serial.println("Dashboard: http://10.10.10.3");
  Serial.println("Raw ESP-NOW receive mode enabled");
  Serial.println("Automatic ACK mode enabled");
  Serial.println("ACK signature: 24JD");
  Serial.println("ACK timestamp: UTC Unix milliseconds");
  Serial.println("Gateway restart control enabled");
  Serial.println("Activity clear control enabled");
  Serial.println("================================");

  printTimeStatus();
}

// ============================================================
// 30. MAIN LOOP
// ============================================================

void loop() {

  server.handleClient();

  processIncoming();

  // ----------------------------------------------------------
  // NTP RECONNECTION HANDLING
  // ----------------------------------------------------------

  static bool previousRouterConnected = false;
  static uint32_t lastNTPRetry = 0;

  bool currentlyConnected = (WiFi.status() == WL_CONNECTED);

  routerConnected = currentlyConnected;

  // If the router becomes available after boot, request NTP.

  if (currentlyConnected && !previousRouterConnected) {
    radioChannel = WiFi.channel();

    Serial.println("Router connection detected");

    startNTP();

    lastNTPRetry = millis();
  }

  previousRouterConnected = currentlyConnected;

  // Retry NTP periodically while connected if time is not valid.

  if (currentlyConnected &&
      !isTimeSynchronized() &&
      millis() - lastNTPRetry >= 60000UL) {

    lastNTPRetry = millis();

    Serial.println("Retrying NTP synchronisation");

    startNTP();
  }

  // Report time once it becomes synchronized.

  static bool timeStatusReported = false;

  if (isTimeSynchronized() && !timeStatusReported) {
    printTimeStatus();
    timeStatusReported = true;
  }

  // If clock has not synchronized, allow a future report
  // after another successful NTP synchronisation attempt.

  if (!isTimeSynchronized()) {
    timeStatusReported = false;
  }

  // ----------------------------------------------------------
  // EXPIRE TEMPORARY PEERS PERIODICALLY
  // ----------------------------------------------------------

  static uint32_t lastPeerCleanup = 0;

  if (millis() - lastPeerCleanup >= 10000) {
    lastPeerCleanup = millis();
    cleanupDynamicPeers();
  }

  // ----------------------------------------------------------
  // PERIODIC DIAGNOSTICS
  // ----------------------------------------------------------

  static uint32_t lastDebug = 0;

  if (millis() - lastDebug >= 10000) {

    lastDebug = millis();

    Serial.println();
    Serial.println("========== GATEWAY STATISTICS ==========");

    Serial.printf(
      "Received: %lu\n",
      (unsigned long)totalReceived
    );

    Serial.printf(
      "Stations: %u\n",
      stationCount
    );

    Serial.printf(
      "Invalid: %lu\n",
      (unsigned long)invalidPackets
    );

    Serial.printf(
      "Dropped: %lu\n",
      (unsigned long)droppedPackets
    );

    Serial.println("----------------------------------------");

    Serial.printf(
      "ACK queued: %lu\n",
      (unsigned long)ackQueued
    );

    Serial.printf(
      "ACK queue failures: %lu\n",
      (unsigned long)ackQueueFailed
    );

    Serial.printf(
      "ACK TX success: %lu\n",
      (unsigned long)ackTxSuccess
    );

    Serial.printf(
      "ACK TX failures: %lu\n",
      (unsigned long)ackTxFailed
    );

    Serial.printf(
      "ACK received: %lu\n",
      (unsigned long)ackReceived
    );

    Serial.println("----------------------------------------");

    Serial.print("Time synchronized: ");
    Serial.println(isTimeSynchronized() ? "YES" : "NO");

    uint64_t nowMs = currentUnixMs();

    Serial.print("UTC: ");
    Serial.println(formatUTC(nowMs));

    Serial.print("IST: ");
    Serial.println(formatIST(nowMs));

    Serial.println("----------------------------------------");

    Serial.printf(
      "Heap: %u bytes\n",
      ESP.getFreeHeap()
    );

    Serial.println("========================================");
  }

  delay(2);
}