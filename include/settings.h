const char * ssid = "kyg";
const char * pass = "kelvita18102009";
const char * mqtt_server = "192.168.0.142";
const int mqtt_port = 1883;
const char * mqtt_user = NULL;
const char * mqtt_pass = NULL;

// Generate shared secret:
// ats-cli gs 16
// Register sensor secret
// Generate hash code:
// ats-cli hc code
// Copy here hash code
uint8_t hmacKey[] = { 0x90, 0xB3, 0x1C, 0x1F, 0x23, 0xC2, 0xEB, 0x02, 0x72, 0xAB }; // I2PHO7P3OBLG4SLB
const int keyLen = 10;