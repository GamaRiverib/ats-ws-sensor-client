#include <Arduino.h>

#include <ESP8266WiFi.h>
#include <ESP8266WiFiMulti.h>

#include <WebSocketsClient.h>

#include <Hash.h>

#include "sha1.h"
#include "TOTP.h"

ESP8266WiFiMulti WiFiMulti;
WebSocketsClient webSocket;

#define PIR_SENSOR_1_ENABLED
#define PIR_SENSOR_2_ENABLED
// #define PROX_SENSOR_ENABLED

#define SERIAL_MONITOR          Serial

#if defined(PIR_SENSOR_1_ENABLED) || defined(PIR_SENSOR_2_ENABLED)
    #define PIR_SENSOR_INTERVAL     1000
#endif

#ifdef PROX_SENSOR_ENABLED
    #define PROX_SENSOR_INTERVAL    500
#endif

#define HEARTBEAT_INTERVAL      30000

#define toDigit(c) (c - 0x30)

#ifdef PIR_SENSOR_1_ENABLED
    #define PIR_SENSOR_1_PIN            D5
#endif

#ifdef PIR_SENSOR_2_ENABLED
    #define PIR_SENSOR_2_PIN            D6
#endif

#ifdef PROX_SENSOR_ENABLED
    #define PROX_SENSOR_TRIG_PIN        D1
    #define PROX_SENSOR_ECHO_PIN        D2

    #define PROX_SENSOR_THRESHOLD       15
#endif

const char * wsServer = "192.168.0.120";
const int wsPort = 3000;
const char * ssid = "";
const char * pass = "";

uint64_t heartbeatTimestamp = 0;
bool isConnected = false;

#if defined (PIR_SENSOR_1_ENABLED) || defined (PIR_SENSOR_2_ENABLED)
    uint64_t pirSensorTimestamp[2] = { 0, 0 };
    uint8_t pirSensorLastState[2] = { 0, 0 };
#endif

#ifdef PROX_SENSOR_ENABLED
    uint64_t proxSensorTimestamp = 0;
    uint8_t proxSensorLastDist = 0;
#endif

// The shared secret is 6GN2ITLOKDAEL2QN -> 0x34, 0x2E, 0x29, 0x76, 0xB8, 0xA3, 0x54, 0xEA, 0x8B, 0x57
// The shared secret is 3L0CGTCMRQ1TRBJV -> 0x1D, 0x40, 0xC8, 0x75, 0x96, 0xDE, 0x83, 0xDD, 0xAE, 0x7F
// The shared secret is 1VGIHDLFNHOTUCOK -> 0x0F, 0xE1, 0x28, 0xB6, 0xAF, 0xBC, 0x71, 0xDF, 0x33, 0x14
// The shared secrte is G6JASFJQPH0O80PH -> 0x81, 0xA6, 0xAE, 0x3E, 0x7A, 0xCC, 0x41, 0x84, 0x03, 0x31
// The shared secret is MM6N67MLMVNBF51E -> 0xB5, 0x8D, 0x73, 0x1E, 0xD5, 0xB7, 0xEE, 0xB7, 0x94, 0x2E
// The shared secret is C8FNBGOG4VPO55FA -> 0x62, 0x1F, 0x75, 0xC3, 0x10, 0x27, 0xF3, 0x82, 0x95, 0xEA
uint8_t hmacKey[] = { 0x1D, 0x40, 0xC8, 0x75, 0x96, 0xDE, 0x83, 0xDD, 0xAE, 0x7F }; // <- Conversions.base32ToHexadecimal(secret);
const int keyLen = 10;
const int timeStep = 60;
unsigned long serverTime = 0;
unsigned long captureAt = 0;

TOTP totp = TOTP(hmacKey, keyLen, timeStep);
char code[7];

void updateCode() {
    long epoch = serverTime + (millis() / 1000) - captureAt;
    char * newCode = totp.getCode(epoch);
    if(strcmp(code, newCode) != 0) {
        strcpy(code, newCode);
    } 
}

void webSocketEvent(WStype_t type, uint8_t * payload, size_t length) {
    switch(type) {
        case WStype_DISCONNECTED:
        {
            SERIAL_MONITOR.printf("[WSc] Disconnected!\n");
            isConnected = false;
            break;
        }
        case WStype_CONNECTED:
        {
            SERIAL_MONITOR.printf("[WSc] Connected to url: %s\n",  payload);
            isConnected = true;
	        webSocket.sendTXT("5");
            break;
        }
        case WStype_TEXT:
        {
            // SERIAL_MONITOR.printf("%s\n", payload);
            // SERIAL_MONITOR.printf("%d\n", length);

            // MessageType: Who
            if(length == 12) {
                uint8_t index = 4;
                if(payload[index++] == 0x57 && payload[index++] == 0x68 && payload[index++] == 0x6F) {
                    updateCode();
                    char payload[100];
                    snprintf(payload, 100, "42[\"is\",{\"code\":%s,\"clientId\":\"device%d\",\"mac\":\"%s\"}]", code, ESP.getChipId(), WiFi.macAddress().c_str());
                    webSocket.sendTXT(payload);
                    SERIAL_MONITOR.printf("42[\"is\",{\"code\":%s,\"clientId\":\"device%d\",\"mac\":\"%s\"}]\n", code, ESP.getChipId(), WiFi.macAddress().c_str());
                }
            }

            // MessageType: Time
            if (length == 21) { // works for long time
                uint8_t index = 4;
                if(payload[index++] == 0x54 && payload[index++] == 0x69 && payload[index++] == 0x6D && payload[index++] == 0x65) {
                    uint16_t i = 10;
                    unsigned long time = toDigit(payload[i++]);
                    for(; i < length - 1; i++) {
                        time = time * 10 + toDigit(payload[i]);
                    }
                    serverTime = time;
                    captureAt = millis() / 1000;
                }
            }

            /*if(length > 15) {
                uint8_t i = 4;
                uint8_t event = toDigit(payload[i++]);
                while(payload[i] != 0x22) { // '\""'
                    event *= 10;
                    event += toDigit(payload[i++]);
                }

                // SERIAL_MONITOR.printf("Event: %d\n", event);
                if (event == 2) { // SYSTEM_STATE_CHANGED
                    // CODES
                    // 00000000 -> ready
                    // 10000001 0H -> disarmed (pin 17)
                    // 20000A00 -> leaving
                    // 30000000 -> armed
                    // 400A0001 0H -> entering
                    // 50000000 -> alarmed
                    // 6XXXXXXX -> programing

                    uint8_t index = 8;
                    uint8_t state = toDigit(payload[index++]);
                    uint8_t mode = toDigit(payload[index++]);
                    uint16_t leftTime = (toDigit(payload[index++]) * 10) + toDigit(payload[index++]);
                    uint16_t count = (toDigit(payload[index++]) * 10) + toDigit(payload[index++]);

                    SERIAL_MONITOR.printf("State: %d\n", state);
                    SERIAL_MONITOR.printf("Mode: %d\n", mode);
                    SERIAL_MONITOR.printf("Left Time: %d\n", leftTime);
                    SERIAL_MONITOR.printf("Count: %d\n", count);

                    if(count > 0) {
                        for(uint16_t i = index; i < index + count * 2; i++) {
                            uint16_t l = (toDigit(payload[i++]) * 10) + toDigit(payload[i]);
                            SERIAL_MONITOR.printf("\t %d Sensor location: %d", i - index, l);
                        }
                    }
                    SERIAL_MONITOR.println();
                }
                // event 22 SYSTEM_ARMED        30000000
                // event 23 SYSTEM_DISARMED     100000010H
                // event 24 SYSTEM_ALARMED      50000000
                // event 25 SYSTEM_ALERT
            }*/
            break;
        }
        case WStype_ERROR:
        {
            SERIAL_MONITOR.printf("[WSc] Error: %s\n", payload);
            break;
        }
    }

}

#if defined(PIR_SENSOR_1_ENABLED) || defined (PIR_SENSOR_2_ENABLED)
void loopPirSensor(uint8_t i, uint8_t pin) {
    if(isConnected) {
        uint64_t now = millis();
        if(now - pirSensorTimestamp[i] > PIR_SENSOR_INTERVAL) {
            pirSensorTimestamp[i] = now;
            uint8_t val = digitalRead(pin);
            if(val != pirSensorLastState[i]) {
                char payload[100];
                snprintf(payload, 100, "42[\"state\",{\"sensors\":[{\"pin\":%d,\"value\":%d}]}]", pin, val);
                webSocket.sendTXT(payload);
                pirSensorLastState[i] = val;
                SERIAL_MONITOR.printf("42[\"state\",{\"sensors\":[{\"pin\":%d,\"value\":%d}]}]\n", pin, val);
            }
        }
    }
}
#endif

#ifdef PROX_SENSOR_ENABLED
void loopProxSensor(uint8_t trigger, uint8_t echo) {
    if(isConnected) {
        uint64_t now = millis();
        if(now - proxSensorTimestamp > PROX_SENSOR_INTERVAL) {
            proxSensorTimestamp = now;

            // Clears the trigPin
            digitalWrite(trigger, LOW);
            delayMicroseconds(2);
            // Sets the trigPin on HIGH state for 10 micro seconds
            digitalWrite(trigger, HIGH);
            delayMicroseconds(10);
            digitalWrite(trigger, LOW);
            // Reads the echoPin, returns the sound wave travel time in microseconds
            unsigned long duration = pulseIn(echo, HIGH);
            // Calculating the distance
            int distance= duration * 0.034 / 2;
            // Prints the distance on the Serial Monitor
            SERIAL_MONITOR.print("Distance: ");
            SERIAL_MONITOR.println(distance);

            if(distance != proxSensorLastDist) {
                char payload[100];
                uint8_t val = 0;
                if (distance < PROX_SENSOR_THRESHOLD) {
                    val = 1;
                }
                snprintf(payload, 100, "42[\"state\",{\"sensors\":[{\"pin\":%d,\"value\":%d}]}]", echo, val);
                webSocket.sendTXT(payload);
                proxSensorLastDist = val;
                SERIAL_MONITOR.printf("42[\"state\",{\"sensors\":[{\"pin\":%d,\"value\":%d}]}]\n", echo, val);
            }
        }
    }
}
#endif

void heartbeat() {
    if(isConnected) {
        uint64_t now = millis();
        if((now - heartbeatTimestamp) > HEARTBEAT_INTERVAL) {
            heartbeatTimestamp = now;
            webSocket.sendTXT("2");
        }
    }
}

void setup() {
    SERIAL_MONITOR.begin(115200);

    SERIAL_MONITOR.println();

    SERIAL_MONITOR.println(F("Starting..."));

    WiFiMulti.addAP(ssid, pass);

    SERIAL_MONITOR.print(F("[SETUP] Connecting to "));
    SERIAL_MONITOR.print(ssid);
    //WiFi.disconnect();
    while(WiFiMulti.run() != WL_CONNECTED) {
        SERIAL_MONITOR.print(".");
        delay(100);
    }
    SERIAL_MONITOR.println();

    webSocket.beginSocketIO(wsServer, wsPort);
    //webSocket.setAuthorization("user", "Password"); // HTTP Basic Authorization
    webSocket.onEvent(webSocketEvent);

    #ifdef PIR_SENSOR_1_ENABLED
        SERIAL_MONITOR.println(F("Configuring Pir Sensor 1"));
        pinMode(PIR_SENSOR_1_PIN, INPUT);
        pirSensorLastState[0] = digitalRead(PIR_SENSOR_1_PIN);
    #endif

    #ifdef PIR_SENSOR_2_ENABLED
        SERIAL_MONITOR.println(F("Configuring Pir Sensor 2"));
        pinMode(PIR_SENSOR_2_PIN, INPUT);
        pirSensorLastState[1] = digitalRead(PIR_SENSOR_2_PIN);
    #endif

    #ifdef PROX_SENSOR_ENABLED
        SERIAL_MONITOR.println(F("Configuring Proximity Sensor"));
        pinMode(PROX_SENSOR_TRIG_PIN, OUTPUT);
        pinMode(PROX_SENSOR_ECHO_PIN, INPUT);
    #endif

    SERIAL_MONITOR.println(F("[SETUP] DONE!"));
    SERIAL_MONITOR.printf("[%s] device%d ready\n", WiFi.macAddress().c_str(), ESP.getChipId());
    SERIAL_MONITOR.println();
    delay(500);
}

void loop() {
    webSocket.loop();

    #ifdef PIR_SENSOR_1_ENABLED
        loopPirSensor(0, PIR_SENSOR_1_PIN);
    #endif

    #ifdef PIR_SENSOR_2_ENABLED
        loopPirSensor(1, PIR_SENSOR_2_PIN);
    #endif

    #ifdef PROX_SENSOR_ENABLED
        loopProxSensor(PROX_SENSOR_TRIG_PIN, PROX_SENSOR_ECHO_PIN);
    #endif

    heartbeat();
}