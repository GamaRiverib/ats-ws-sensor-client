#include <Arduino.h>

#include <ESP8266WiFi.h>
#include <ESP8266WiFiMulti.h>

#include <WebSocketsClient.h>

#include <Hash.h>

#include "sha1.h"
#include "TOTP.h"

#include <Adafruit_NeoPixel.h>

ESP8266WiFiMulti WiFiMulti;
WebSocketsClient webSocket;

#define DEBUG

// #define PIR_SENSOR_1_ENABLED
// #define PIR_SENSOR_2_ENABLED
// #define PROX_SENSOR_ENABLED

#define SERIAL_MONITOR          Serial

#if defined(PIR_SENSOR_1_ENABLED) || defined(PIR_SENSOR_2_ENABLED)
    #define PIR_SENSOR_INTERVAL     1000
#endif

#ifdef PROX_SENSOR_ENABLED
    #define PROX_SENSOR_INTERVAL    500
#endif

#define HEARTBEAT_INTERVAL      20000

#ifdef PIR_SENSOR_1_ENABLED
    #ifdef ESP12
        #define PIR_SENSOR_1_PIN            D0
    #else
        #define PIR_SENSOR_1_PIN            3
    #endif
#endif

#ifdef PIR_SENSOR_2_ENABLED
    #define PIR_SENSOR_2_PIN            D6
#endif

#ifdef PROX_SENSOR_ENABLED
    #define PROX_SENSOR_TRIG_PIN        D1
    #define PROX_SENSOR_ECHO_PIN        D2

    #define PROX_SENSOR_THRESHOLD       15
#endif

#define WHO_MESSAGE_LENGTH              12
#define TIME_MESSAGE_LENGTH             21

#define SYSTEM_STATE_CHANGED_CODE       2
#define SYSTEM_ARMED_CODE               22
#define SYSTEM_DISARMED_CODE            23
#define SYSTEM_ALARMED_CODE             24
#define SYSTEM_ALERT_CODE               25
#define MAX_ALERTS_CODE                 28
#define MAX_UNAUTHORIZED_CODE           29

const char * wsServer = "192.168.137.1";
const int wsPort = 3000;
const char * ssid = "NVKJGRI";
const char * pass = "Novutek01";

#define PIXEL_COUNT              12

#ifdef ESP12
    #define PIXEL_PIN            D5 // GPIO14
#else
    #define PIXEL_PIN            3
#endif

Adafruit_NeoPixel strip(PIXEL_COUNT, PIXEL_PIN, NEO_GRB + NEO_KHZ800);

#define COLOR_SATURATION         128

uint32_t redColor = strip.Color(COLOR_SATURATION, 0, 0);
uint32_t greenColor = strip.Color(0, COLOR_SATURATION, 0);
uint32_t blueColor = strip.Color(0, 0, COLOR_SATURATION);
uint32_t yellowColor = strip.Color(COLOR_SATURATION, COLOR_SATURATION, 0);
uint32_t orangeColor = strip.Color(COLOR_SATURATION, COLOR_SATURATION / 2, 0);
uint32_t whiteColor = strip.Color(COLOR_SATURATION, COLOR_SATURATION, COLOR_SATURATION);
uint32_t blackColor = strip.Color(0, 0, 0);

enum StripEffect {
    OFF,
    ON,
    COLOR,
    TIMER,
    CYLON,
    STROBE,
    FADE
};

StripEffect currentEffect;

uint64_t heartbeatTimestamp = 0;
bool isConnected = false;
uint8_t disconnectedCount = 0;

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
// The shared secret is G6JASFJQPH0O80PH -> 0x81, 0xA6, 0xAE, 0x3E, 0x7A, 0xCC, 0x41, 0x84, 0x03, 0x31
// The shared secret is MM6N67MLMVNBF51E -> 0xB5, 0x8D, 0x73, 0x1E, 0xD5, 0xB7, 0xEE, 0xB7, 0x94, 0x2E
// The shared secret is C8FNBGOG4VPO55FA -> 0x62, 0x1F, 0x75, 0xC3, 0x10, 0x27, 0xF3, 0x82, 0x95, 0xEA
uint8_t hmacKey[] = { 0x1D, 0x40, 0xC8, 0x75, 0x96, 0xDE, 0x83, 0xDD, 0xAE, 0x7F }; // <- Conversions.base32ToHexadecimal(secret);
const int keyLen = 10;
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

void handleWhoMessage(uint8_t * payload) {
    uint8_t index = 4;
    if(payload[index++] == 0x57 && payload[index++] == 0x68 && payload[index++] == 0x6F) {
        updateCode();
        char response[100];
        snprintf(response, 100, "42[\"is\",{\"code\":%s,\"clientId\":\"device%d\",\"mac\":\"%s\"}]", code, ESP.getChipId(), WiFi.macAddress().c_str());
        webSocket.sendTXT(response);
        #ifdef DEBUG
            SERIAL_MONITOR.println(response);
        #endif
    }
}

void handleTimeMessage(uint8_t * payload) {
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
}

typedef struct RGBColor {
    uint8_t red;
    uint8_t green;
    uint8_t blue;
} RGBColor;

RGBColor getRGBColor(uint32_t color) {
    uint8_t r = (color >> 16) & 0xFF;
    uint8_t g = (color >> 8) & 0xFF;
    uint8_t b = color & 0xFF;
    RGBColor c = { r, g, b };
    return c;
}

struct System {
    uint8_t state;
    uint8_t mode;
    uint16_t leftTime;
    size_t count;
    uint16_t sensors[98];
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

void stripSetAllPixels(uint32_t color) {
    uint16_t count = strip.numPixels();
    uint16_t i = 0;
    for(; i < count; i++) {
        strip.setPixelColor(i, color);
    }
}

uint64_t timer_timestamp = 0;
uint64_t timer_counter = 0;

void timer() {
    uint64_t now = millis();
    if (now - timer_timestamp >= 1000 && timer_counter > 0) {
        timer_timestamp = now;
        timer_counter--;
        #ifdef DEBUG
            SERIAL_MONITOR.printf("Countdown: %d\n", timer_counter);
        #endif
    }
}

uint64_t effect_timer_initial_count = 60; // SECONDS
uint64_t effect_timer_step = effect_timer_initial_count / strip.numPixels() * 1000; // MILLISECONDS
uint64_t effect_timer_delay = 0;

void effectTimer() {
    if(effect_timer_delay > 0) {
        effect_timer_delay--;
        return;
    }

    effect_timer_delay = effect_timer_step;

    stripSetAllPixels(blackColor);
    uint64_t t = timer_counter * strip.numPixels() / effect_timer_initial_count;
    uint8_t i = 0;
    for(; i < t; i++) {
        strip.setPixelColor(i, orangeColor);
    }
    strip.show();
}

#define EFFECT_CYLON_SPEED          300
#define EFFECT_CYLON_EYE_SIZE       1

bool effect_cylon_dir = true;
uint16_t effect_cylon_counter = 0;
uint64_t effect_cylon_timestamp = 0;

void effectCylon() {

    uint64_t now = millis();
    if (now - effect_cylon_timestamp >= EFFECT_CYLON_SPEED) {
        effect_cylon_timestamp = now;

        RGBColor rgb = getRGBColor(redColor);

        uint8_t r = rgb.red / 10;
        uint8_t g = rgb.green / 10;
        uint8_t b = rgb.blue / 10;
        uint32_t color = strip.Color(r, g, b);

        uint16_t pixel = effect_cylon_counter;
        uint16_t length = strip.numPixels();

        if(effect_cylon_dir) {
            effect_cylon_counter++;
            effect_cylon_dir = pixel < (length - EFFECT_CYLON_EYE_SIZE - 3);
        } else {
            effect_cylon_counter--;
            effect_cylon_dir = pixel <= 1;
        }

        stripSetAllPixels(blackColor);
        strip.setPixelColor(pixel, color);
        uint8_t i = 1;
        for(; i <= EFFECT_CYLON_EYE_SIZE; i++) {
            strip.setPixelColor(pixel + i, redColor);
        }
        strip.setPixelColor(pixel + EFFECT_CYLON_EYE_SIZE + 1, color);
        strip.show();

    }
}

#define EFFECT_STROBE_SPEED          500
bool effect_strobe_state = false;
uint64_t effect_strobe_timestamp = 0;

void effectStrobe() {
    uint64_t now = millis();
    if (now - effect_strobe_timestamp >= EFFECT_STROBE_SPEED) {
        effect_strobe_timestamp = now;
        if(effect_strobe_state) {
            stripSetAllPixels(redColor);
            strip.show();
        } else {
            stripSetAllPixels(blackColor);
            strip.show();
        }
        effect_strobe_state = !effect_strobe_state;
    }
}

#define EFFECT_FADE_SPEED          10
uint64_t effect_fade_timestamp = 0;
bool effect_fade_dir = true;
uint8_t effect_fade_counter = 0;
uint32_t effect_fade_color = redColor;

void effectFade() {
    uint64_t now = millis();
    if (now - effect_fade_timestamp >= EFFECT_FADE_SPEED) {
        effect_fade_timestamp = now;

        if(effect_fade_dir) {
            effect_fade_dir = effect_fade_counter < 254;
            effect_fade_counter++;
        } else {
            effect_fade_dir = effect_fade_counter < 2;
            effect_fade_counter--;
        }

        RGBColor rgb = getRGBColor(effect_fade_color);

        uint8_t r = (effect_fade_counter / 256.0) * rgb.red;
        uint8_t g = (effect_fade_counter / 256.0) * rgb.green;
        uint8_t b = (effect_fade_counter / 256.0) * rgb.blue;
        uint32_t c = strip.Color(r, g, b);
        stripSetAllPixels(c);
        strip.show();
    }
}

void loopStrip() {
    if(!isConnected) {
        effect_fade_color = yellowColor;
        currentEffect = FADE;
        effectFade();
    } else {
        switch (currentEffect)
        {
            case StripEffect::OFF:
            case StripEffect::ON:
            case StripEffect::COLOR:
                break;
            case StripEffect::TIMER:
                effectTimer();
                break;
            case StripEffect::CYLON:
                effectCylon();
                break;
            case StripEffect::STROBE:
                effectStrobe();
                break;
            case StripEffect::FADE:
                effectFade();
                break;
            default:
                break;
        }
    }
}

void onSystemStateChanged(uint8_t * payload) {
    System system = getSystem(payload, 8);
    /**
     * READY = 0,
     * DISARMED = 1,
     * LEAVING = 2,
     * ARMED = 3,
     * ENTERING = 4,
     * ALARMED = 5,
     * PROGRAMMING = 6
     */
    switch(system.state) {
        case 0: // READY
        {
            stripSetAllPixels(greenColor);
            strip.show();
            currentEffect = StripEffect::COLOR;
            break;
        }
        case 1: // DISARMED
        {
            stripSetAllPixels(blueColor);
            strip.show();
            currentEffect = StripEffect::COLOR;
            break;
        }
        case 2: // LEAVING
        case 4: // ENTERING
        {
            timer_counter = system.leftTime;
            effect_timer_initial_count = system.leftTime;
            if (effect_timer_initial_count < strip.numPixels()) {
                effect_timer_step = 500;
            } else {
                effect_timer_step = effect_timer_initial_count / strip.numPixels() * 1000;
            }
            effect_timer_delay = effect_timer_step;
            #ifdef DEBUG
                SERIAL_MONITOR.printf("Step: %l\n", effect_timer_step);
                SERIAL_MONITOR.printf("Initial count: %l\n", effect_timer_initial_count);
            #endif
            currentEffect = StripEffect::TIMER;
            break;
        }
        case 3: // ARMED
        {
            currentEffect = StripEffect::CYLON;
            break;
        }
        case 5: // ALARMED
        {
            currentEffect = StripEffect::STROBE;
            break;
        }
        case 6: // PROGRAMMING
        {
            stripSetAllPixels(blueColor);
            strip.show();
            currentEffect = StripEffect::COLOR;
            break;
        }
    }
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

void onSystemAlert(uint8_t * payload) {
    System system = getSystem(payload, 9);
    // TODO: strip -> fade effect yellow
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
    // TODO: strip -> fade effect red
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
    // TODO: strip -> fade effect red
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

void webSocketEvent(WStype_t type, uint8_t * payload, size_t length) {
    switch(type) 
    {
        case WStype_DISCONNECTED:
        {
            isConnected = false;
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
                default:
                {
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
                            case SYSTEM_DISARMED_CODE:
                            case SYSTEM_ALARMED_CODE:
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
                #ifdef DEBUG
                    SERIAL_MONITOR.println(payload);
                #endif
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
            #ifdef DEBUG
                SERIAL_MONITOR.print("Distance: ");
                SERIAL_MONITOR.println(distance);
            #endif
            

            if(distance != proxSensorLastDist) {
                char payload[100];
                uint8_t val = 0;
                if (distance < PROX_SENSOR_THRESHOLD) {
                    val = 1;
                }
                snprintf(payload, 100, "42[\"state\",{\"sensors\":[{\"pin\":%d,\"value\":%d}]}]", echo, val);
                webSocket.sendTXT(payload);
                proxSensorLastDist = val;
                #ifdef DEBUG
                    SERIAL_MONITOR.println(payload);
                #endif
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
            #ifdef DEBUG
                SERIAL_MONITOR.println(F("Sending heartbeat..."));
            #endif
        }
    }
}

void setup() {
    SERIAL_MONITOR.begin(115200);

    #ifdef DEBUG
        SERIAL_MONITOR.println();
        SERIAL_MONITOR.println(F("Starting..."));
    #endif

    WiFiMulti.addAP(ssid, pass);

    #ifdef DEBUG
        SERIAL_MONITOR.print(F("[SETUP] Connecting to "));
        SERIAL_MONITOR.print(ssid);
    #endif
    //WiFi.disconnect();
    while(WiFiMulti.run() != WL_CONNECTED) {
        #ifdef DEBUG
            SERIAL_MONITOR.print(".");
        #endif
        delay(100);
    }

    #ifdef DEBUG
        SERIAL_MONITOR.println();
        SERIAL_MONITOR.print(F("Connecting to server "));
        SERIAL_MONITOR.print(wsServer);
        SERIAL_MONITOR.print(F(":"));
        SERIAL_MONITOR.println(wsPort);
    #endif
    webSocket.beginSocketIO(wsServer, wsPort);
    //webSocket.setAuthorization("user", "Password"); // HTTP Basic Authorization
    webSocket.onEvent(webSocketEvent);

    #ifdef PIR_SENSOR_1_ENABLED
        #ifdef DEBUG
            SERIAL_MONITOR.println(F("Configuring Pir Sensor 1"));
        #endif
        pinMode(PIR_SENSOR_1_PIN, INPUT);
        pirSensorLastState[0] = digitalRead(PIR_SENSOR_1_PIN);
    #endif

    #ifdef PIR_SENSOR_2_ENABLED
        #ifdef DEBUG
            SERIAL_MONITOR.println(F("Configuring Pir Sensor 2"));
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

    // this resets all the neopixels to an off state
    strip.begin();
    strip.show();
    currentEffect = StripEffect::OFF;

    #ifdef DEBUG
        SERIAL_MONITOR.println(F("[SETUP] DONE!"));
        SERIAL_MONITOR.printf("[%s] device%d ready\n", WiFi.macAddress().c_str(), ESP.getChipId());
        SERIAL_MONITOR.println();
    #endif
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

    timer();

    loopStrip();
}