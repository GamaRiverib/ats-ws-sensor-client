#include <Arduino.h>

#include <ESP8266WiFi.h>
#include <ESP8266WiFiMulti.h>

#include <WebSocketsClient.h>

#include <Hash.h>

#include "sha1.h"
#include "TOTP.h"

ESP8266WiFiMulti WiFiMulti;
WebSocketsClient webSocket;

#define SERIAL_MONITOR          Serial

#define PIR_SENSOR_INTERVAL     1000
#define HEARTBEAT_INTERVAL      25000

#define toDigit(c) (c - 0x30)

#define PIR_SENSOR_PIN          D2

const char * wsServer = "192.168.137.61";
const int wsPort = 3000;
const char * ssid = "";
const char * pass = "";

uint64_t pirSensorTimestamp = 0;
uint64_t messageTimestamp = 0;
uint64_t heartbeatTimestamp = 0;
bool isConnected = false;

uint8_t pirSensorLastState = 0;

// The shared secret is 6GN2ITLOKDAEL2QN
uint8_t hmacKey[] = { 0x34, 0x2e, 0x29, 0x76, 0xb8, 0xa3, 0x54, 0xea, 0x8b, 0x57 }; // <- Conversions.base32ToHexadecimal(secret);
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
                if(payload[4] == 0x57 && payload[5] == 0x68 && payload[6] == 0x6F) {
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

            if(length > 15) {
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
                    // 100000010H -> disarmed (pin 17)
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
            }
            break;
        }
        case WStype_BIN:
        {
            SERIAL_MONITOR.printf("[WSc] get binary length: %u\n", length);
            hexdump(payload, length);
            // send data to server
            // webSocket.sendBIN(payload, length);
            break;
        }
        case WStype_ERROR:
        {
            SERIAL_MONITOR.printf("[WSc] Error: %s\n", payload);
            break;
        }
    }

}

void loopSensor() {
    uint64_t now = millis();
    if(now - pirSensorTimestamp > PIR_SENSOR_INTERVAL && isConnected) {
        pirSensorTimestamp = now;
        uint8_t val = digitalRead(PIR_SENSOR_PIN);
        if(val != pirSensorLastState) {
            char payload[100];
            snprintf(payload, 100, "42[\"state\",{\"sensors\":[{\"pin\":%d,\"value\":%d}]}]", PIR_SENSOR_PIN, val);
            webSocket.sendTXT(payload);
            pirSensorLastState = val;
            SERIAL_MONITOR.printf("42[\"state\",{\"sensors\":[{\"pin\":%d,\"value\":%d}]}]\n", PIR_SENSOR_PIN, val);
        }
    }
}

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
    //SERIAL_MONITOR.setDebugOutput(true);

    SERIAL_MONITOR.println();

    for(uint8_t t = 4; t > 0; t--) {
      SERIAL_MONITOR.printf("[SETUP] BOOT WAIT %d...\n", t);
      SERIAL_MONITOR.flush();
      delay(1000);
    }

    WiFiMulti.addAP(ssid, pass);

    SERIAL_MONITOR.print("[SETUP] Connecting to ");
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

    pinMode(PIR_SENSOR_PIN, INPUT);
    pirSensorLastState = digitalRead(PIR_SENSOR_PIN);

    SERIAL_MONITOR.println("[SETUP] DONE!");
    SERIAL_MONITOR.println();
}

void loop() {
    webSocket.loop();
    loopSensor();
    heartbeat();
}