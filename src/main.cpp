/*****************************************************
 * Includes
 * ***************************************************/

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <Hash.h>
#include "sha1.h"
#include "TOTP.h"
#include "settings.h"

/*****************************************************
 * DEFINE
 * ***************************************************/

#define DEBUG
// #define OUTPUT_DEVICE

// MQTT MESSAGE BUFFER SIZE
#define MSG_BUFFER_SIZE	(50)

#ifdef OUTPUT_DEVICE
    #define SYSTEM_STATE_CHANGED_CODE       2
    #define SYSTEM_ARMED_CODE               22
    #define SYSTEM_DISARMED_CODE            23
    #define SYSTEM_ALARMED_CODE             24
    #define SYSTEM_ALERT_CODE               25
    #define MAX_ALERTS_CODE                 28
    #define MAX_UNAUTHORIZED_CODE           29
#endif
#define CLIENT_ONLINE_CODE                  30

/*****************************************************
 * WiFi, MQTT
 * ***************************************************/

WiFiClient espClient;
PubSubClient mqttClient(espClient);
unsigned long lastMsg = 0;
unsigned long lastReconnectAttempt = 0;
uint8_t disconnectedCount = 0;
char msg[MSG_BUFFER_SIZE];
const uint16_t reconnectDelay = 5000; // 5 seconds

/*****************************************************
 * SENSORS
 * ***************************************************/

#define PIR_SENSOR_1_ENABLED
// #define PIR_SENSOR_2_ENABLED
// #define PROX_SENSOR_ENABLED

#define SERIAL_MONITOR          Serial

#if defined(PIR_SENSOR_1_ENABLED) || defined(PIR_SENSOR_2_ENABLED)
    #define PIR_SENSOR_INTERVAL     1000
#endif

#ifdef PROX_SENSOR_ENABLED
    #define PROX_SENSOR_INTERVAL    500
#endif

#ifdef PIR_SENSOR_1_ENABLED
    #ifdef ESP12
        #define PIR_SENSOR_1_PIN            D6
    #else
        #define PIR_SENSOR_1_PIN            3
    #endif
#endif

#ifdef PIR_SENSOR_2_ENABLED
    #define PIR_SENSOR_2_PIN            D0
#endif

#ifdef PROX_SENSOR_ENABLED
    #define PROX_SENSOR_TRIG_PIN        D1
    #define PROX_SENSOR_ECHO_PIN        D2

    #define PROX_SENSOR_THRESHOLD       15
#endif

#if defined (PIR_SENSOR_1_ENABLED) || defined (PIR_SENSOR_2_ENABLED)
    uint64_t pirSensorTimestamp[2] = { 0, 0 };
    uint8_t pirSensorLastState[2] = { 0, 0 };
#endif

#ifdef PROX_SENSOR_ENABLED
    uint64_t proxSensorTimestamp = 0;
    uint8_t proxSensorLastDist = 0;
#endif

/*****************************************************
 * TOTP
 * ***************************************************/
const int timeStep = 60;
unsigned long serverTime = 0;
unsigned long captureAt = 0;

TOTP totp = TOTP(hmacKey, keyLen, timeStep);
char code[7];

int toDigit(uint8_t c) { // TODO
    if (c >= 0x30 && c <= 0x39) { 
        return c - 0x30;
    } else if (c >= 0x41 && c <= 0x46) {
        return c - 0x37;
    } else if (c >= 0x61 && c <= 0x66) {
        return c - 0x57;
    } else {
        return 0;
    }
}

void updateCode() {
    long epoch = serverTime + (millis() / 1000) - captureAt;
    char * newCode = totp.getCode(epoch);
    if(strcmp(code, newCode) != 0) {
        strcpy(code, newCode);
    } 
}

/*void handleTimeMessage(uint8_t * payload) {
    uint8_t index = 4;
    if(payload[index++] == 0x54 && payload[index++] == 0x69 && payload[index++] == 0x6D && payload[index++] == 0x65) {
        uint16_t i = 10;
        unsigned long time = toDigit(payload[i++]);
        for(; i < TIME_MESSAGE_LENGTH - 1; i++) {
            time = time * 10 + toDigit(payload[i]);
        }
        serverTime = time;
        captureAt = millis() / 1000;
    }
}*/

/*void handelClientOnline(uint8_t * payload, size_t length) {
    uint8_t i = 4;
    uint8_t event = toDigit(payload[i++]);
    while(payload[i] != 0x22 && i < length) { // '\""'
        event *= 10;
        event += toDigit(payload[i++]);
    }

    #ifdef DEBUG
        SERIAL_MONITOR.printf("\nEvent: %d\n", event);
    #endif

    if(event == CLIENT_ONLINE_CODE) {
        uint8_t j = i + 21; // TODO: magic number

        if(j >= length) {
            return;
        }

        uint32_t id = toDigit(payload[j++]);
        while(payload[j] != 0x22 && j < length) {
            id *= 10;
            id += toDigit(payload[j++]);
        }

        uint32_t chipId = ESP.getChipId();
        if (id == chipId) {
            #ifdef PIR_SENSOR_1_ENABLED
                uint8_t val = digitalRead(PIR_SENSOR_1_PIN);
                char payload[100];
                snprintf(payload, 100, "42[\"state\",{\"sensors\":[{\"pin\":%d,\"value\":%d}]}]", PIR_SENSOR_1_PIN, val);
                webSocket.sendTXT(payload);
                pirSensorLastState[i] = val;
                #ifdef DEBUG
                    SERIAL_MONITOR.println(payload);
                #endif
            #endif

            #ifdef PIR_SENSOR_2_ENABLED
                uint8_t val = digitalRead(PIR_SENSOR_2_PIN);
                char payload[100];
                snprintf(payload, 100, "42[\"state\",{\"sensors\":[{\"pin\":%d,\"value\":%d}]}]", PIR_SENSOR_2_PIN, val);
                webSocket.sendTXT(payload);
                pirSensorLastState[i] = val;
                #ifdef DEBUG
                    SERIAL_MONITOR.println(payload);
                #endif
            #endif

            #ifdef PROX_SENSOR_ENABLED
                // TODO
            #endif
        }
    } 
}*/

/*****************************************************
 * OUTPUT DEVICE
 * ***************************************************/

#ifdef OUTPUT_DEVICE
struct System {
    uint8_t state;
    uint8_t mode;
    uint16_t leftTime;
    size_t count;
    uint16_t sensors[99];
};

System getSystem(uint8_t * payload, uint8_t index) {
    uint8_t state = toDigit(payload[index++]);
    uint8_t mode = toDigit(payload[index++]);
    uint16_t leftTime = (toDigit(payload[index++]) * 10) + toDigit(payload[index++]);
    uint16_t count = (toDigit(payload[index++]) * 10) + toDigit(payload[index++]);
    uint16_t sensors[count];
    if(count > 0) {
        for(uint8_t i = 0; i < count; i++) {
            uint16_t l = (toDigit(payload[index++]) * 10) + toDigit(payload[index++]);
            sensors[i] = l;
        }
        /*for(uint16_t i = index; i < index + count * 2; i++) {
            uint16_t l = (toDigit(payload[i++]) * 10) + toDigit(payload[i]);
            sensors[i - index] = l;
        }*/
    }

    System system = {
        state,
        mode,
        leftTime,
        count,
        *sensors
    };

    return system;
}

void onSystemStateChanged(uint8_t * payload) {
    System system = getSystem(payload, 8);
    #ifdef DEBUG
        SERIAL_MONITOR.println("SYSTEM_STATE_CHANGED");
        SERIAL_MONITOR.printf(" - State: %d\n", system.state);
        SERIAL_MONITOR.printf(" - Mode: %d\n", system.mode);
        SERIAL_MONITOR.printf(" - Left Time: %d\n", system.leftTime);
        SERIAL_MONITOR.printf(" - Count: %d\n", system.count);
        if(system.count > 0) {
            for(uint16_t i = 0; i < system.count; i++) {
                SERIAL_MONITOR.printf("\t %d Sensor location: %d\n", (i + 1), system.sensors[i]);
            }
        }
    #endif
}

void onSystemArmed(uint8_t * payload) {
    System system = getSystem(payload, 9);
    #ifdef DEBUG
        SERIAL_MONITOR.println("SYSTEM_ARMED");
        SERIAL_MONITOR.printf(" - State: %d\n", system.state);
        SERIAL_MONITOR.printf(" - Mode: %d\n", system.mode);
        SERIAL_MONITOR.printf(" - Left Time: %d\n", system.leftTime);
        SERIAL_MONITOR.printf(" - Count: %d\n", system.count);
        if(system.count > 0) {
            for(uint16_t i = 0; i < system.count; i++) {
                SERIAL_MONITOR.printf("\t %d Sensor location: %d\n", (i + 1), system.sensors[i]);
            }
        }
    #endif
}

void onSystemDisarmed(uint8_t * payload) {
    System system = getSystem(payload, 9);
    #ifdef DEBUG
        SERIAL_MONITOR.println("SYSTEM_DISARMED");
        SERIAL_MONITOR.printf(" - State: %d\n", system.state);
        SERIAL_MONITOR.printf(" - Mode: %d\n", system.mode);
        SERIAL_MONITOR.printf(" - Left Time: %d\n", system.leftTime);
        SERIAL_MONITOR.printf(" - Count: %d\n", system.count);
        if(system.count > 0) {
            for(uint16_t i = 0; i < system.count; i++) {
                SERIAL_MONITOR.printf("\t %d Sensor location: %d\n", (i + 1), system.sensors[i]);
            }
        }
    #endif
}

void onSystemAlarmed(uint8_t * payload) {
    System system = getSystem(payload, 9);
    #ifdef DEBUG
        SERIAL_MONITOR.println("SYSTEM_ALARMED");
        SERIAL_MONITOR.printf(" - State: %d\n", system.state);
        SERIAL_MONITOR.printf(" - Mode: %d\n", system.mode);
        SERIAL_MONITOR.printf(" - Left Time: %d\n", system.leftTime);
        SERIAL_MONITOR.printf(" - Count: %d\n", system.count);
        if(system.count > 0) {
            for(uint16_t i = 0; i < system.count; i++) {
                SERIAL_MONITOR.printf("\t %d Sensor location: %d\n", (i + 1), system.sensors[i]);
            }
        }
    #endif
}

void onSystemAlert(uint8_t * payload) {
    System system = getSystem(payload, 9);
    #ifdef DEBUG
        SERIAL_MONITOR.println("SYSTEM_ALERT");
        SERIAL_MONITOR.printf(" - State: %d\n", system.state);
        SERIAL_MONITOR.printf(" - Mode: %d\n", system.mode);
        SERIAL_MONITOR.printf(" - Left Time: %d\n", system.leftTime);
        SERIAL_MONITOR.printf(" - Count: %d\n", system.count);
        if(system.count > 0) {
            for(uint16_t i = 0; i < system.count; i++) {
                SERIAL_MONITOR.printf("\t %d Sensor location: %d\n", (i + 1), system.sensors[i]);
            }
        }
    #endif
}

void onMaxAlerts(uint8_t * payload) {
    System system = getSystem(payload, 9);
    #ifdef DEBUG
        SERIAL_MONITOR.println("MAX_ALERTS");
        SERIAL_MONITOR.printf(" - State: %d\n", system.state);
        SERIAL_MONITOR.printf(" - Mode: %d\n", system.mode);
        SERIAL_MONITOR.printf(" - Left Time: %d\n", system.leftTime);
        SERIAL_MONITOR.printf(" - Count: %d\n", system.count);
        if(system.count > 0) {
            for(uint16_t i = 0; i < system.count; i++) {
                SERIAL_MONITOR.printf("\t %d Sensor location: %d\n", (i + 1), system.sensors[i]);
            }
        }
    #endif
}

void onMaxUnauthorized(uint8_t * payload) {
    System system = getSystem(payload, 9);
    #ifdef DEBUG
        SERIAL_MONITOR.println("MAX_UNAUTHORIZED_INTENTS");
        SERIAL_MONITOR.printf(" - State: %d\n", system.state);
        SERIAL_MONITOR.printf(" - Mode: %d\n", system.mode);
        SERIAL_MONITOR.printf(" - Left Time: %d\n", system.leftTime);
        SERIAL_MONITOR.printf(" - Count: %d\n", system.count);
        if(system.count > 0) {
            for(uint16_t i = 0; i < system.count; i++) {
                SERIAL_MONITOR.printf("\t %d Sensor location: %d\n", (i + 1), system.sensors[i]);
            }
        }
    #endif
}
#endif

/*
void webSocketEvent(WStype_t type, uint8_t * payload, size_t length) {
    switch(type) 
    {
        case WStype_DISCONNECTED:
        {
            isConnected = false;
            disconnectedCount = disconnectedCount + 1;
            #ifdef DEBUG
                SERIAL_MONITOR.printf("Disconnected count: %d\n", disconnectedCount);
            #endif
            if (disconnectedCount > 12) {
                ESP.restart();
            }
            #ifdef DEBUG
                SERIAL_MONITOR.printf("[WSc] Disconnected!\n");
            #endif
            break;
        }
        case WStype_CONNECTED:
        {
            isConnected = true;
	        webSocket.sendTXT("5");
            #ifdef DEBUG
                SERIAL_MONITOR.printf("[WSc] Connected to url: %s\n",  payload);
            #endif
            break;
        }
        case WStype_TEXT:
        {
            #ifdef DEBUG
                SERIAL_MONITOR.println("");
                SERIAL_MONITOR.println("*********************");
                SERIAL_MONITOR.printf("Payload: %s\n", payload);
                SERIAL_MONITOR.printf("Length: %d\n", length);
                SERIAL_MONITOR.println("");
            #endif

            switch (length) {
                case 1: 
                {
                    if(isConnected == false) {
                        disconnectedCount = disconnectedCount + 1;
                        #ifdef DEBUG
                            SERIAL_MONITOR.printf("Disconnected count: %d\n", disconnectedCount);
                        #endif
                        if (disconnectedCount > 3) {
                            webSocket.disconnect();
                            ESP.restart();
                        }
                    }
                }
                case WHO_MESSAGE_LENGTH: // MessageType: Who
                    handleWhoMessage(payload);
                    break;
                case TIME_MESSAGE_LENGTH: // MessageType: Time
                    handleTimeMessage(payload);
                    break;
                case CLIENT_ONLINE_LENGTH: // MessageType: 30 | CLIENT_ONLINE
                    handelClientOnline(payload, length);
                    break;
                default:
                {
                    #ifdef OUTPUT_DEVICE
                    if(length > 15 && length < 35) { // TODO: supported events
                        uint8_t i = 4;
                        uint8_t event = toDigit(payload[i++]);
                        while(payload[i] != 0x22 && i < length) { // '\""'
                            event *= 10;
                            event += toDigit(payload[i++]);
                        }

                        #ifdef DEBUG
                            SERIAL_MONITOR.printf("\nEvent: %d\n", event);
                        #endif

                        // CODES
                        // 00000000 -> ready
                        // 10000001 0H -> disarmed (pin 17)
                        // 20000A00 -> leaving
                        // 30000000 -> armed
                        // 400A0001 0H -> entering
                        // 50000000 -> alarmed
                        // 6XXXXXXX -> programing
                        switch (event)
                        {
                            case SYSTEM_STATE_CHANGED_CODE:
                                onSystemStateChanged(payload);
                                break;
                            case SYSTEM_ARMED_CODE:
                                onSystemArmed(payload);
                                break;
                            case SYSTEM_DISARMED_CODE:
                                onSystemDisarmed(payload);
                                break;
                            case SYSTEM_ALARMED_CODE:
                                onSystemAlarmed(payload);
                                break;
                            case SYSTEM_ALERT_CODE:
                                onSystemAlert(payload);
                                break;
                            case MAX_ALERTS_CODE:
                                onMaxAlerts(payload);
                                break;
                            case MAX_UNAUTHORIZED_CODE:
                                onMaxUnauthorized(payload);
                                break;
                            default:
                                SERIAL_MONITOR.println("Unhandled event");
                                break;
                        }
                    }
                    #endif
                    break;
                }
            }
            break;
        }
        case WStype_ERROR:
        {
            #ifdef DEBUG
                SERIAL_MONITOR.printf("[WSc] Error: %s\n", payload);
            #endif
            break;
        }
    }

}
*/

#if defined(PIR_SENSOR_1_ENABLED) || defined (PIR_SENSOR_2_ENABLED)
void loopPirSensor(uint8_t i, uint8_t pin) {
    if(mqttClient.connected()) {
        uint64_t now = millis();
        if(now - pirSensorTimestamp[i] > PIR_SENSOR_INTERVAL) {
            pirSensorTimestamp[i] = now;
            uint8_t val = digitalRead(pin);
            if(val != pirSensorLastState[i]) {
                StaticJsonDocument<100> root;
                JsonArray sensors = root.createNestedArray("sensors");
                JsonObject sensor_1 = sensors.createNestedObject();
                sensor_1["mac"] = WiFi.macAddress();
                sensor_1["pin"] = pin;
                sensor_1["value"] = val;
                char buffer[256];
                size_t n = serializeJson(root, buffer);
                char state_topic[50]; // State topic
                sprintf(state_topic, "/ats/devices/device%d/state", ESP.getChipId());
                mqttClient.publish(state_topic, buffer, n);
                pirSensorLastState[i] = val;
                #ifdef DEBUG
                    SERIAL_MONITOR.println();
                    SERIAL_MONITOR.println(state_topic);
                    serializeJsonPretty(root, SERIAL_MONITOR);
                #endif
            }
        }
    }
}
#endif

#ifdef PROX_SENSOR_ENABLED
void loopProxSensor(uint8_t trigger, uint8_t echo) {
    if(mqttClient.connected()) {
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
            int distance = duration * 0.034 / 2;
            // Prints the distance on the Serial Monitor
            #ifdef DEBUG
                SERIAL_MONITOR.print("Distance: ");
                SERIAL_MONITOR.println(distance);
            #endif
            

            if(distance != proxSensorLastDist) {
                uint8_t val = 0;
                if (distance < PROX_SENSOR_THRESHOLD) {
                    val = 1;
                }
                StaticJsonDocument<100> root;
                JsonArray sensors = root.createNestedArray("sensors");
                JsonObject sensor_1 = sensors.createNestedObject();
                sensor_1["mac"] = WiFi.macAddress();
                sensor_1["pin"] = echo;
                sensor_1["value"] = val;
                char buffer[256];
                size_t n = serializeJson(root, buffer);
                mqttClient.publish(state_topic, buffer, n);
                proxSensorLastDist = val;
                #ifdef DEBUG
                    SERIAL_MONITOR.println();
                    SERIAL_MONITOR.println(state_topic);
                    serializeJsonPretty(root, SERIAL_MONITOR);
                #endif
            }
        }
    }
}
#endif

void mqtt_callback(char* topic, byte* payload, unsigned int length) {
    #ifdef DEBUG
        SERIAL_MONITOR.print(F("Message arrived ["));
        SERIAL_MONITOR.print(topic);
        SERIAL_MONITOR.print(F("] "));
        for (unsigned int i = 0; i < length; i++) {
            SERIAL_MONITOR.print((char)payload[i]);
        }
        SERIAL_MONITOR.println();
    #endif

    // TODO: ....
    // StaticJsonDocument<256> doc;
    // deserializeJson(doc, payload, length);

}

boolean mqtt_reconnect() {
    #ifdef DEBUG
        SERIAL_MONITOR.println(F("Attempting MQTT connection..."));
    #endif
    // Attempt to connect
    char client_id[30]; // Client ID
    sprintf(client_id, "ats_client_%d", ESP.getChipId());
    char device_id[30]; // Device ID
    sprintf(device_id, "device%d", ESP.getChipId());
    char will_topic[50]; // Will topic
    sprintf(will_topic, "/ats/devices/device%d/lwt", ESP.getChipId());
    const int will_qos = 0;
    const bool will_retain = true;
    const char will_message[] = "offline";
    #ifdef DEBUG
        SERIAL_MONITOR.print(F("ClientId: "));
        SERIAL_MONITOR.println(client_id);
        SERIAL_MONITOR.print(F("DeviceId: "));
        SERIAL_MONITOR.println(device_id);
    #endif
    if (mqttClient.connect(client_id, mqtt_user, mqtt_pass, will_topic, will_qos, will_retain, will_message, false)) {
        #ifdef DEBUG
            SERIAL_MONITOR.println(F("connected"));
        #endif
        // Once connected, publish an announcement...
        mqttClient.publish(will_topic, "online");
        #ifdef OUTPUT_DEVICE
            // ... and resubscribe
            mqttClient.subscribe("/ats/system/#");
        #endif
    } else {
        #ifdef DEBUG
        SERIAL_MONITOR.print("failed, rc=");
        SERIAL_MONITOR.println(mqttClient.state());
        // -4 > MQTT_CONNECTION_TIMEOUT
        // -3 > MQTT_CONNECTION_LOST
        // -2 > MQTT_CONNECT_FAILED
        // -1 > MQTT_DISCONNECTED
        // 0  > MQTT_CONNECTED
        // 1  > MQTT_CONNECT_BAD_PROTOCOL
        // 2  > MQTT_CONNECT_BAD_CLIENT_ID
        // 3  > MQTT_CONNECT_UNAVAILABLE
        // 4  > MQTT_CONNECT_BAD_CREDENTIALS
        // 5  > MQTT_CONNECT_UNAUTHORIZED
        #endif
    }
    return mqttClient.connected();
}

void setup_wifi() {
    delay(10);
    
    // We start by connecting to a WiFi network
    #ifdef DEBUG
        SERIAL_MONITOR.println();
        SERIAL_MONITOR.print(F("Connecting to "));
        SERIAL_MONITOR.println(ssid);
    #endif

    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid, pass);

    while (WiFi.status() != WL_CONNECTED) {
        #ifdef DEBUG
            SERIAL_MONITOR.print(".");
        #endif
        delay(300);
    }

    randomSeed(micros());

    #ifdef DEBUG
        SERIAL_MONITOR.println();
        SERIAL_MONITOR.println(F("WiFi connected"));
        SERIAL_MONITOR.print(F("IP address: "));
        SERIAL_MONITOR.println(WiFi.localIP());
    #endif
}

void setup_mqtt_server() {
    #ifdef DEBUG
        SERIAL_MONITOR.println();
        SERIAL_MONITOR.print(F("Connecting to MQTT Broker "));
        SERIAL_MONITOR.print(mqtt_server);
        SERIAL_MONITOR.print(F(":"));
        SERIAL_MONITOR.println(mqtt_port);
    #endif
    mqttClient.setServer(mqtt_server, mqtt_port);
    mqttClient.setCallback(mqtt_callback);
}

void async_mqtt_loop() {
    if (!mqttClient.connected()) {
        disconnectedCount += 1;
        long now = millis();
        if (now - lastReconnectAttempt > reconnectDelay) {
            lastReconnectAttempt = now;
            // Attempt to reconnect
            if (mqtt_reconnect()) {
                lastReconnectAttempt = 0;
            } else if (disconnectedCount > 12) {
                ESP.restart();
            }
        }
    } else {
        // Client connected
        disconnectedCount = 0;
        mqttClient.loop();
    }
}

void setup() {
    SERIAL_MONITOR.begin(115200);
    setup_wifi();
    setup_mqtt_server();
    #ifdef PIR_SENSOR_1_ENABLED
        #ifdef DEBUG
            SERIAL_MONITOR.printf("Configuring PIR sensor 1 on PIN %d\n", PIR_SENSOR_1_PIN);
        #endif
        pinMode(PIR_SENSOR_1_PIN, INPUT);
        pirSensorLastState[0] = digitalRead(PIR_SENSOR_1_PIN);
    #endif

    #ifdef PIR_SENSOR_2_ENABLED
        #ifdef DEBUG
            SERIAL_MONITOR.printf("Configuring PIR sensor 2 on PIN %d\n", PIR_SENSOR_2_PIN);
        #endif
        pinMode(PIR_SENSOR_2_PIN, INPUT);
        pirSensorLastState[1] = digitalRead(PIR_SENSOR_2_PIN);
    #endif

    #ifdef PROX_SENSOR_ENABLED
        #ifdef DEBUG
            SERIAL_MONITOR.println(F("Configuring Proximity Sensor"));
        #endif
        pinMode(PROX_SENSOR_TRIG_PIN, OUTPUT);
        pinMode(PROX_SENSOR_ECHO_PIN, INPUT);
    #endif

    #ifdef DEBUG
        SERIAL_MONITOR.println(F("[SETUP] DONE!"));
        SERIAL_MONITOR.printf("[%s] device%d ready\n", WiFi.macAddress().c_str(), ESP.getChipId());
        SERIAL_MONITOR.println();
    #endif
    delay(500);
}

void loop() {
    async_mqtt_loop();

    #ifdef PIR_SENSOR_1_ENABLED
        loopPirSensor(0, PIR_SENSOR_1_PIN);
    #endif

    #ifdef PIR_SENSOR_2_ENABLED
        loopPirSensor(1, PIR_SENSOR_2_PIN);
    #endif

    #ifdef PROX_SENSOR_ENABLED
        loopProxSensor(PROX_SENSOR_TRIG_PIN, PROX_SENSOR_ECHO_PIN);
    #endif
}