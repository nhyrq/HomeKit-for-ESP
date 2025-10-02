/*********************************************************************************
 *  MIT License
 *  
 *  Copyright (c) 2020-2025 Gregg E. Berman
 *  
 *  https://github.com/HomeKit/HomeKit
 *  
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *  
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *  
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 *  
 ********************************************************************************/
 
#pragma once

#include "version.h"

#pragma GCC diagnostic ignored "-Wpmf-conversions"                // eliminates warning messages from use of pointers to member functions to detect whether update() and loop() are overridden by user
#pragma GCC diagnostic ignored "-Wunused-result"                  // eliminates warning message regarded unused result from call to crypto_scalarmult_curve25519()

#include <Arduino.h>
#include <unordered_map>
#include <vector>
#include <list>
#include <shared_mutex>
#include <nvs.h>
#include <ArduinoOTA.h>
#include <ETH.h>
#include <esp_now.h>
#include <mbedtls/base64.h>
#include <esp_ota_ops.h>

#include "src/extras/Blinker.h"
#include "src/extras/Pixel.h"
#include "src/extras/RFControl.h"
#include "src/extras/PwmPin.h"
#include "src/extras/StepperControl.h"

#include "Settings.h"
#include "Utils.h"
#include "Network_HK.h"
#include "HAPConstants.h"
#include "HapQR.h"
#include "Characteristics.h"
#include "TLV8.h"

using std::vector;
using std::unordered_map;
using std::list;
using std::string;

enum {
  GET_AID=1,
  GET_META=2,
  GET_PERMS=4,
  GET_TYPE=8,
  GET_EV=16,
  GET_DESC=32,
  GET_NV=64,
  GET_VALUE=128,
  GET_STATUS=256
};

typedef boolean BOOL_t;
typedef uint8_t UINT8_t;
typedef uint16_t UINT16_t;
typedef uint32_t UINT32_t;
typedef uint64_t UINT64_t;
typedef int32_t INT_t;
typedef double FLOAT_t;
typedef const char * STRING_t;
typedef const TLV8 & TLV_ENC_t;
typedef std::pair<const uint8_t *, size_t> DATA_t;

static DATA_t NULL_DATA={NULL,0};
static TLV8 NULL_TLV{};

///////////////////////////////
// Macros to lock/unlock poll() mutex

#define homeKitPAUSE std::shared_lock pollLock(homeKit.getMutex());
#define homeKitRESUME if(pollLock.owns_lock()){pollLock.unlock();}

///////////////////////////////

extern "C" bool verifyRollbackLater();    // declare pre-defined Arduino-ESP32 version, unless over-ridden in user sketch with #include "KitRollback.h"

///////////////////////////////

#define STATUS_UPDATE(LED_UPDATE,MESSAGE_UPDATE)  {homeKit.statusLED->LED_UPDATE;if(homeKit.statusCallback)homeKit.statusCallback(MESSAGE_UPDATE);}

enum HK_STATUS {
  HK_WIFI_NEEDED,                         // WiFi Credentials have not yet been set/stored
  HK_WIFI_CONNECTING,                     // HomeKit is trying to connect to the network specified in the stored WiFi Credentials
  HK_PAIRING_NEEDED,                      // HomeKit is connected to central WiFi network, but device has not yet been paired to HomeKit
  HK_PAIRED,                              // HomeKit is connected to central WiFi network and the device has been paired to HomeKit
  HK_ENTERING_CONFIG_MODE,                // User has requested the device to enter into Command Mode
  HK_CONFIG_MODE_EXIT,                    // HomeKit is in Command Mode with "Exit Command Mode" specified as choice
  HK_CONFIG_MODE_REBOOT,                  // HomeKit is in Command Mode with "Reboot" specified as choice
  HK_CONFIG_MODE_LAUNCH_AP,               // HomeKit is in Command Mode with "Launch Access Point" specified as choice
  HK_CONFIG_MODE_UNPAIR,                  // HomeKit is in Command Mode with "Unpair Device" specified as choice
  HK_CONFIG_MODE_ERASE_WIFI,              // HomeKit is in Command Mode with "Erase WiFi Credentials" specified as choice
  HK_CONFIG_MODE_EXIT_SELECTED,           // User has selected "Exit Command Mode" 
  HK_CONFIG_MODE_REBOOT_SELECTED,         // User has select "Reboot" from the Command Mode
  HK_CONFIG_MODE_LAUNCH_AP_SELECTED,      // User has selected "Launch AP Access" from the Command Mode
  HK_CONFIG_MODE_UNPAIR_SELECTED,         // User has seleected "Unpair Device" from the Command Mode
  HK_CONFIG_MODE_ERASE_WIFI_SELECTED,     // User has selected "Erase WiFi Credentials" from the Command Mode
  HK_REBOOTING,                           // HomeKit is in the process of rebooting the device
  HK_FACTORY_RESET,                       // HomeKit is in the process of performing a Factory Reset of device
  HK_AP_STARTED,                          // HomeKit has started the Access Point but no one has yet connected
  HK_AP_CONNECTED,                        // The Access Point is started and a user device has been connected
  HK_AP_TERMINATED,                       // HomeKit has terminated the Access Point 
  HK_OTA_STARTED,                         // HomeKit is in the process of receiving an Over-the-Air software update
  HK_WIFI_SCANNING,                       // HomeKit is in the process of scanning for WiFi networks
  HK_ETH_CONNECTING                       // HomeKit is trying to connect to an Ethernet network
};

//////////////////////////////////////////////////////////
// Paired Controller Structure for Permanently-Stored Data

class Controller {
  friend class HAPClient;
  
  boolean allocated=false;        // DEPRECATED (but needed for backwards compatability with original NVS storage of Controller info)
  boolean admin;                  // Controller has admin privileges
  uint8_t ID[36];                 // Pairing ID
  uint8_t LTPK[32];               // Long Term Ed2519 Public Key

  public:

  Controller(uint8_t *id, uint8_t *ltpk, boolean ad){
    allocated=true;
    admin=ad;
    memcpy(ID,id,36);
    memcpy(LTPK,ltpk,32);
  }

  Controller(){}

  const uint8_t *getID() const {return(ID);}
  const uint8_t *getLTPK() const {return(LTPK);}
  boolean isAdmin() const {return(admin);}

};

///////////////////////////////

// Forward-Declarations

struct Kit;
struct KitAccessory;
struct KitService;
struct KitCharacteristic;
struct KitBuf;
struct KitButton;
struct KitUserCommand;

struct HAPClient;

extern Kit homeKit;

////////////////////////////////////////////////////////
// INTERNAL HOMESPAN STRUCTURES - NOT FOR USER ACCESS //
////////////////////////////////////////////////////////

struct KitPartition{
  char magicCookie[32];
  uint8_t reserved[224];
};

///////////////////////////////

struct KitConfig{                         
  int configNumber=0;                         // configuration number - broadcast as Bonjour "c#" (computed automatically)
  uint8_t hashCode[48]={0};                   // SHA-384 hash of Kit Database stored as a form of unique "signature" to know when to update the config number upon changes
};

///////////////////////////////

struct KitBuf{                               // temporary storage buffer for use with putCharacteristicsURL() and checkTimedResets() 
  uint32_t aid=0;                             // updated aid 
  uint32_t iid=0;                             // updated iid
  boolean wr=false;                           // flag to indicate write-response has been requested
  char *val=NULL;                             // updated value (optional, though either at least 'val' or 'ev' must be specified)
  char *ev=NULL;                              // updated event notification flag (optional, though either at least 'val' or 'ev' must be specified)
  StatusCode status;                          // return status (HAP Table 6-11)
  KitCharacteristic *characteristic=NULL;    // Characteristic to update (NULL if not found)
};

typedef vector<KitBuf, Mallocator<KitBuf>> KitBufVec;
  
///////////////////////////////

struct KitWebLog{                            // optional web status/log data
  boolean isEnabled=false;                    // flag to inidicate WebLog has been enabled
  uint16_t maxEntries=0;                      // max number of log entries;
  int nEntries=0;                             // total cumulative number of log entries
  const char *timeServer=NULL;                // optional time server to use for acquiring clock time
  const char *timeZone;                       // optional time-zone specification
  boolean timeInit=false;                     // flag to indicate time has been initialized
  char bootTime[33]="Unknown";                // boot time
  char *statusURL=NULL;                       // URL of status log
  char *faviconURL=NULL;                      // optional URL for favicon PNG image
  uint32_t waitTime=120000;                   // number of milliseconds to wait for initial connection to time server
  String css="";                              // optional user-defined style sheet for web log
  std::shared_mutex mux;                      // shared read/write lock
    
  struct log_t {                              // log entry type
    uint64_t upTime;                          // number of seconds since booting
    struct tm clockTime;                      // clock time
    char *message;                            // pointers to log entries of arbitrary size
    String clientIP;                          // IP address of client making request (or "0.0.0.0" if not applicable)
  } *log=NULL;                                // array of log entries 

  void init(uint16_t maxEntries, const char *serv, const char *tz, const char *url);
  static void initTime(void *args);  
  void vLog(boolean sysMsg, const char *fmr, va_list ap);
  int check(const char *uri);
};

///////////////////////////////

struct KitOTA{                               // manages OTA process
  
  char otaPwd[33]="";                         // MD5 Hash of OTA password, represented as a string of hexidecimal characters

  static boolean enabled;                     // enables OTA - default if not enabled
  static boolean auth;                        // indicates whether OTA password is required
  static int otaPercent;
  static boolean safeLoad;                    // indicates whether OTA update should reject any application update that is not another HomeKit sketch
  
  int init(boolean auth, boolean safeLoad, const char *pwd);
  int setPassword(const char *pwd);
  static void start();
  static void end();
  static void progress(uint32_t progress, uint32_t total);
  static void error(ota_error_t err);
};

//////////////////////////////////////
//   USER API CLASSES BEGINS HERE   //
//////////////////////////////////////

class Kit{

  friend class KitAccessory;
  friend class KitService;
  friend class KitCharacteristic;
  friend class KitUserCommand;
  friend class KitButton;
  friend class KitWebLog;
  friend class KitOTA;
  friend class Network_HK;
  friend class HAPClient;
  friend void init();
  
  char *displayName;                            // display name for this device - broadcast as part of Bonjour MDNS
  char *hostNameBase;                           // base of hostName of this device - full host name broadcast by Bonjour MDNS will have 6-byte accessoryID as well as '.local' automatically appended
  char *hostNameSuffix=NULL;                    // optional "suffix" of hostName of this device.  If specified, will be used as the hostName suffix instead of the 6-byte accessoryID
  char *hostName=NULL;                          // derived full hostname
  char *modelName;                              // model name of this device - broadcast as Bonjour field "md" 
  char category[3]="";                          // category ID of primary accessory - broadcast as Bonjour field "ci" (HAP Section 13)
  unsigned long snapTime;                       // current time (in millis) snapped before entering Service loops() or updates()
  boolean isInitialized=false;                  // flag indicating HomeKit has been initialized
  boolean isBridge=true;                        // flag indicating whether device is configured as a bridge (i.e. first Accessory contains nothing but AccessoryInformation and HAPProtocolInformation)
  HapQR qrCode;                                 // optional QR Code to use for pairing
  const char *sketchVersion="n/a";              // version of the sketch
  char pairingCodeCommand[12]="";               // user-specified Pairing Code - only needed if Pairing Setup Code is specified in sketch using setPairingCode()
  String lastClientIP="0.0.0.0";                // IP address of last client accessing device through encrypted channel
  boolean newCode;                              // flag indicating new application code has been loaded (based on keeping track of app SHA256)
  boolean serialInputDisabled=false;            // flag indiating that serial input is disabled
  uint8_t rebootCount=0;                        // counts number of times device was rebooted (used in optional Reboot callback)
  uint32_t rebootCallbackTime;                  // length of time to wait (in milliseconds) before calling optional Reboot callback
  boolean ethernetEnabled=false;                // flag to indicate whether Ethernet is being used instead of WiFi
  boolean initialPollingCompleted=false;        // flag to indicate whether polling task has initially completed
  boolean forceConfigIncrement=false;           // flag to indicate whether configuration number (MDNS C# value) should be incremented even if database config has not changed
  char *compileTime=NULL;                       // optional compile time string --- can be set with call to setCompileTime()
   
  nvs_handle charNVS;                           // handle for non-volatile-storage of Characteristics data
  nvs_handle wifiNVS=0;                         // handle for non-volatile-storage of WiFi data
  nvs_handle otaNVS;                            // handle for non-volatile storage of OTA data
  nvs_handle srpNVS;                            // handle for non-volatile storage of SRP data
  nvs_handle hapNVS;                            // handle for non-volatile-storage of HAP data

  int connected=0;                              // WiFi connection status (increments upon each connect and disconnect)
  HK_ExpCounter wifiTimeCounter;                // exponentially-increasing wait time counter between WiFi connection attempts
  unsigned long alarmConnect=0;                 // time after which WiFi connection attempt should be tried again

  static constexpr char delims[]="\"{[:,]}"; 
  static const uint8_t DELIM = 0xF5;
  static const uint8_t END_DELIM = DELIM+strlen(delims)-1;  
  
  void (*wifiBegin)(const char *s, const char *p)=[](const char *s, const char *p){WiFi.begin(s,p);};     // default call to WiFi.begin()
 
  uint32_t rescanInitialTime=0;
  uint32_t rescanPeriodicTime=0;
  int rescanThreshold;
  unsigned long rescanAlarm;
  enum {RESCAN_IDLE, RESCAN_PENDING, RESCAN_RUNNING} rescanStatus=RESCAN_IDLE;
  unordered_map<string, string> bssidNames;
  
  const char *defaultSetupCode=DEFAULT_SETUP_CODE;            // Setup Code used for pairing
  uint16_t autoOffLED=0;                                      // automatic turn-off duration (in seconds) for Status LED
  int logLevel=DEFAULT_LOG_LEVEL;                             // level for writing out log messages to serial monitor
  unsigned long comModeLife=DEFAULT_COMMAND_TIMEOUT*1000;     // length of time (in milliseconds) to keep Command Mode alive before resuming normal operations
  uint16_t tcpPortNum=DEFAULT_TCP_PORT;                       // port for TCP communications between HomeKit and HomeKit
  char qrID[5]="";                                            // Setup ID used for pairing with QR Code
  void (*wifiCallback)()=NULL;                                // optional callback function to invoke once WiFi connectivity is initially established *** TO BE DEPRECATED ***
  void (*connectionCallback)(int)=NULL;                       // optional callback function to invoke every time WiFi or Ethernet connectivity is established or re-established
  void (*weblogCallback)(String &)=NULL;                      // optional callback function to invoke after header table in Web Log is produced
  void (*pairCallback)(boolean isPaired)=NULL;                // optional callback function to invoke when pairing is established (true) or lost (false)
  boolean autoStartAPEnabled=false;                           // enables auto start-up of Access Point when WiFi Credentials not found
  void (*apFunction)()=NULL;                                  // optional function to invoke when starting Access Point
  void (*statusCallback)(HK_STATUS status)=NULL;              // optional callback when HomeKit status changes
  void (*rebootCallback)(uint8_t)=NULL;                       // optional callback when device reboots
  void (*controllerCallback)()=NULL;                          // optional callback when Controller is added/removed/changed
  void (*pollingCallback)()=NULL;                             // optional callback when polling task reaching initial completion (only called once)
  void (*getCharacteristicsCallback)(const char *)=NULL;      // optional callback function to invoke every time HomeKit sends a getCharacteristics request
  
  NetworkServer *hapServer;                         // pointer to the HAP Server connection
  Blinker *statusLED;                               // indicates HomeKit status
  Blinkable *statusDevice = NULL;                   // the device used for the Blinker
  PushButton *controlButton = NULL;                 // controls HomeKit configuration and resets
  Network_HK network;                               // configures WiFi and Setup Code via either serial monitor or temporary Access Point
  KitWebLog webLog;                                // optional web status/log
  TaskHandle_t pollTaskHandle = NULL;               // optional task handle to use for poll() function
  TaskHandle_t loopTaskHandle;                      // Arduino Loop Task handle
  boolean verboseWifiReconnect = true;              // set to false to not print WiFi reconnect attempts messages
  std::shared_mutex pollMutex;                      // mutex lock for poll task
  hkWatchdogTimer hkWDT;                            // general homeKit watchdog timer
    
  KitOTA kitOTA;                                  // manages OTA process
  KitConfig hapConfig;                             // track configuration changes to the HAP Accessory database; used to increment the configuration number (c#) when changes found

  list<HAPClient, Mallocator<HAPClient>> hapList;                        // linked-list of HAPClient structures containing HTTP client connections, parsing routines, and state variables
  list<HAPClient, Mallocator<HAPClient>>::iterator currentClient;        // iterator to current client
  vector<KitAccessory *, Mallocator<KitAccessory *>> Accessories;      // vector of pointers to all Accessories
  vector<KitService *, Mallocator<KitService *>> Loops;                // vector of pointer to all Services that have over-ridden loop() methods
  KitBufVec Notifications;                                              // vector of KitBuf objects that store info for Characteristics that are updated with setVal() and require a Notification Event
  vector<KitButton *,  Mallocator<KitButton *>> PushButtons;           // vector of pointer to all PushButtons
  unordered_map<uint64_t, uint32_t> TimedWrites;                         // map of timed-write PIDs and Alarm Times (based on TTLs)  
  unordered_map<char, KitUserCommand *> UserCommands;                   // map of pointers to all UserCommands

  void pollTask();                                                       // poll HAP Clients and process any new HAP requests
  void configureNetwork();                                               // configure Network services (MDNS, WebLog,  OTA, etc.) and start HAP Server
  void commandMode();                                                    // allows user to control and reset HomeKit settings with the control button
  void resetStatus();                                                    // resets statusLED and calls statusCallback based on current HomeKit status
  void reboot();                                                         // reboots device

  void printfAttributes(int flags=GET_VALUE|GET_META|GET_PERMS|GET_TYPE|GET_DESC);   // writes Attributes JSON database to hapOut stream
  
  KitCharacteristic *find(uint32_t aid, uint32_t iid);             // return Characteristic with matching aid and iid (else NULL if not found)
  void printfAttributes(KitBufVec &pVec);                          // writes KitBuf objects to hapOut stream
  boolean printfAttributes(char **ids, int numIDs, int flags);      // writes accessory requested characteristic ids to hapOut stream - returns true if all characteristics are found and readable, else returns false
  void clearNotify(HAPClient *hc);                                  // clear all notifications related to specific client connection
  void printfNotify(KitBufVec &pVec, HAPClient *hc);               // writes notification JSON to hapOut stream based on KitBuf objects and specified connection
  char *escapeJSON(char *jObj);                                     // remove all whitespace not within double-quotes, and converts special characters to unused UTF-8 bytes as a placeholder
  char *unEscapeJSON(char *jObj);                                   // converts UTF-8 placeholder bytes back to original special characters
  char *strstr_r(const char *haystack, const char *needle);         // same as standard-C strstr(), but returns pointer to character AFTER end of matched string (or NULL if no match)
  boolean updateCharacteristics(char *buf, KitBufVec &pVec);       // parses PUT /characteristics JSON request and updates referenced characteristics; returns true on success, false on fail

  static boolean invalidUUID(const char *uuid){
    int x=0;
    sscanf(uuid,"%*8[0-9a-fA-F]%n",&x);       // check for short-form of UUID
    if(strlen(uuid)==x && uuid[0]!='0')
      return(false);
    sscanf(uuid,"%*8[0-9a-fA-F]-%*4[0-9a-fA-F]-%*4[0-9a-fA-F]-%*4[0-9a-fA-F]-%*12[0-9a-fA-F]%n",&x);
    return(strlen(uuid)!=36 || x!=36);
  }

  QueueHandle_t networkEventQueue;                         // queue to transmit network events from callback thread to HomeKit thread
  void networkCallback(const arduino_event_t &event);      // network event handler (works for WiFi as well as Ethernet)

  void init();    // performs all late-stage initializations needed
    
  public:

  Kit();         // constructor

  void begin(Category catID=DEFAULT_CATEGORY,
             const char *displayName=DEFAULT_DISPLAY_NAME,
             const char *hostNameBase=DEFAULT_HOST_NAME,
             const char *modelName=DEFAULT_MODEL_NAME);        
             
  void poll();                                  // calls pollTask() with some error checking
  void processSerialCommand(const char *c);     // process command 'c' (typically from readSerial, though can be called with any 'c')
  
  boolean updateDatabase(boolean updateMDNS=true);           // updates HAP Configuration Number and Loop vector; if updateMDNS=true and config number has changed, re-broadcasts MDNS 'c#' record; returns true if config number changed
  boolean deleteAccessory(uint32_t aid);                     // deletes Accessory with matching aid; returns true if found, else returns false 
  
  Kit& setControlPin(uint8_t pin, PushButton::triggerType_t triggerType=PushButton::TRIGGER_ON_LOW){            // sets Control Pin, with optional trigger type   
    controlButton=new PushButton(pin, triggerType);
    return(*this);
    }
    
  int getControlPin(){return(controlButton?controlButton->getPin():-1);}                 // get Control Pin (returns -1 if undefined)

  Kit& setStatusPin(uint8_t pin){statusDevice=new GenericLED(pin);return(*this);}       // sets Status Device to a simple LED on specified pin
   Kit& setStatusPixel(uint8_t pin,float h=0,float s=100,float v=100){                  // sets Status Device to an RGB Pixel on specified pin
     statusDevice=((new Pixel(pin))->setOnColor(Pixel::HKV(h,s,v)));
     return(*this);
   }
  Kit& setStatusDevice(Blinkable *sDev){statusDevice=sDev;return(*this);}               // sets Status Device to a generic Blinkable object
  
  Kit& setStatusAutoOff(uint16_t duration){autoOffLED=duration;return(*this);}          // sets Status LED auto off (seconds)  
  int getStatusPin(){return(statusLED->getPin());}                                       // get Status Pin (returns -1 if undefined)
  void refreshStatusDevice(){if(statusLED)statusLED->refresh();}                         // refreshes state of Status LED

  Kit& setApSSID(const char *ssid){network.apSSID=ssid;return(*this);}                  // sets Access Point SSID
  Kit& setApPassword(const char *pwd){network.apPassword=pwd;return(*this);}            // sets Access Point Password
  Kit& setApTimeout(uint16_t nSec){network.lifetime=nSec*1000;return(*this);}           // sets Access Point Timeout (seconds)
  Kit& setCommandTimeout(uint16_t nSec){comModeLife=nSec*1000;return(*this);}           // sets Command Mode Timeout (seconds)
  Kit& setLogLevel(int level){logLevel=level;return(*this);}                            // sets Log Level for log messages (0=baseline, 1=intermediate, 2=all, -1=disable all serial input/output)
  int getLogLevel(){return(logLevel);}                                                   // get Log Level
  Kit& setSerialInputDisable(boolean val){serialInputDisabled=val;return(*this);}       // sets whether serial input is disabled (true) or enabled (false)
  boolean getSerialInputDisable(){return(serialInputDisabled);}                          // returns true if serial input is disabled, or false if serial input in enabled
  Kit& setPortNum(uint16_t port){tcpPortNum=port;return(*this);}                        // sets the TCP port number to use for communications between HomeKit and HomeKit
  Kit& setQRID(const char *id);                                                         // sets the Setup ID for optional pairing with a QR Code
  Kit& setSketchVersion(const char *sVer){sketchVersion=sVer;return(*this);}            // set optional sketch version number
  const char *getSketchVersion(){return sketchVersion;}                                  // get sketch version number
  Kit& setConnectionCallback(void (*f)(int)){connectionCallback=f;return(*this);}       // sets an optional user-defined function to call every time WiFi or Ethernet connectivity is established or re-established
  Kit& setPairCallback(void (*f)(boolean isPaired)){pairCallback=f;return(*this);}      // sets an optional user-defined function to call when Pairing is established (true) or lost (false)
  Kit& setApFunction(void (*f)()){apFunction=f;return(*this);}                          // sets an optional user-defined function to call when activating the WiFi Access Point  
  Kit& enableAutoStartAP(){autoStartAPEnabled=true;return(*this);}                      // enables auto start-up of Access Point when WiFi Credentials not found
  Kit& setWifiCredentials(const char *ssid, const char *pwd);                           // sets WiFi Credentials
  Kit& setConnectionTimes(uint32_t minTime, uint32_t maxTime, uint8_t nSteps);          // sets min/max WiFi connection times (in seconds) and number of steps  
  Kit& setStatusCallback(void (*f)(HK_STATUS status)){statusCallback=f;return(*this);}  // sets an optional user-defined function to call when HomeKit status changes
  const char* statusString(HK_STATUS s);                                                 // returns char string for HomeKit status change messages
  Kit& setPairingCode(const char *s, boolean progCall=true);                            // sets the Pairing Code - use is NOT recommended.  Use 'S' from CLI instead
  void deleteStoredValues(){processSerialCommand("V");}                                  // deletes stored Characteristic values from NVS
  Kit& resetIID(uint32_t newIID);                                                       // resets the IID count for the current Accessory to start at newIID
  Kit& setControllerCallback(void (*f)()){controllerCallback=f;return(*this);}          // sets an optional user-defined function to call whenever a Controller is added/removed
  Kit& setWifiBegin(void (*f)(const char *, const char *)){wifiBegin=f;return(*this);}  // sets an optional user-defined function to over-ride WiFi.begin() with additional logic
  Kit& setPollingCallback(void (*f)()){pollingCallback=f;return(*this);}                // sets an optional user-defined function to call upon INITIAL completion of the polling task (only called once)
  Kit& useEthernet(){ethernetEnabled=true;return(*this);}                               // force use of Ethernet instead of WiFi, even if ETH not called or Ethernet card not detected
  Kit& forceNewConfigNumber(){forceConfigIncrement=true;return(*this);}                 // force configuration increment when updateDatabase() is called even if database has not changed 

  Kit& setGetCharacteristicsCallback(void (*f)(const char *)){getCharacteristicsCallback=f;return(*this);}                    // sets an optional callback called whenever HomeKit sends a getCharacteristics request
  Kit& setHostNameSuffix(const char *suffix){asprintf(&hostNameSuffix,"%s",suffix);return(*this);}                            // sets the hostName suffix to be used instead of the 6-byte AccessoryID
  Kit& setCompileTime(const char *compTime=__DATE__ " " __TIME__){asprintf(&compileTime,"%s",compTime);return(*this);}        // sets the compile time to compTime; default is to use compiler-provided date/time
 
  int enableOTA(boolean auth=true, boolean safeLoad=true){return(kitOTA.init(auth, safeLoad, NULL));}   // enables Over-the-Air updates, with (auth=true) or without (auth=false) authorization password  
  int enableOTA(const char *pwd, boolean safeLoad=true){return(kitOTA.init(true, safeLoad, pwd));}      // enables Over-the-Air updates, with custom authorization password (overrides any password stored with the 'O' command)

  void markSketchOK(){esp_ota_mark_app_valid_cancel_rollback();}

  Kit& enableWebLog(uint16_t maxEntries=0, const char *serv=NULL, const char *tz="UTC", const char *url=DEFAULT_WEBLOG_URL){     // enable Web Logging
    webLog.init(maxEntries, serv, tz, url);
    return(*this);
  }

  void addWebLog(boolean sysMsg, const char *fmt, ...){               // add Web Log entry
    va_list ap;
    va_start(ap,fmt);
    webLog.vLog(sysMsg,fmt,ap);
    va_end(ap);    
  }

  Kit& setWebLogCSS(const char *css){webLog.css="\n" + String(css) + "\n";return(*this);}
  Kit& setWebLogCallback(void (*f)(String &)){weblogCallback=f;return(*this);}
  Kit& setWebLogFavicon(const char *favicon=DEFAULT_FAVICON){asprintf(&webLog.faviconURL,"%s",favicon);return(*this);}
  void getWebLog(void (*f)(const char *, void *), void *);
  void assumeTimeAcquired(){webLog.timeInit=true;}

  Kit& setVerboseWifiReconnect(bool verbose=true){verboseWifiReconnect=verbose;return(*this);}

  Kit& setRebootCallback(void (*f)(uint8_t),uint32_t t=DEFAULT_REBOOT_CALLBACK_TIME){rebootCallback=f;rebootCallbackTime=t;return(*this);}

  std::shared_mutex& getMutex(){return(pollMutex);}

  void autoPoll(uint32_t stackSize=8192, uint32_t priority=1, uint32_t core=0){
    xTaskCreateUniversal( [](void *parms){for(;;)homeKit.pollTask();}, "pollTask", stackSize, NULL, priority, &pollTaskHandle, core);
  }

  TaskHandle_t getAutoPollTask(){return(pollTaskHandle);}

  Kit& setTimeServerTimeout(uint32_t tSec){webLog.waitTime=tSec*1000;return(*this);}    // sets wait time (in seconds) for optional web log time server to connect
  
  Kit& enableWiFiRescan(uint32_t iTime=1, uint32_t pTime=0, int thresh=3){              // enables periodic WiFi rescan to search for stronger BSSID
    rescanInitialTime=iTime*60000;
    rescanPeriodicTime=pTime*60000;
    rescanThreshold=thresh;
    return(*this);
  }

  Kit& enableWatchdog(uint16_t nSeconds=CONFIG_ESP_TASK_WDT_TIMEOUT_S){hkWDT.enable(nSeconds);return(*this);}      // enables HomeKit watchdog with timeout of nSeconds
  void disableWatchdog(){hkWDT.disable();}                                                                          // disables HomeKit watchdog
  void resetWatchdog(){hkWDT.reset();}                                                                              // resets HomeKit watchdog

  Kit& addBssidName(String bssid, string name){bssid.toUpperCase();bssidNames[bssid.c_str()]=name;return(*this);}

  list<Controller, Mallocator<Controller>>::const_iterator controllerListBegin();
  list<Controller, Mallocator<Controller>>::const_iterator controllerListEnd();

  IPAddress getUniqueLocalIPv6(NetworkInterface &nif);
  IPAddress getUniqueLocalIPv6(WiFiSTAClass &wifi){return(getUniqueLocalIPv6(wifi.STA));} 

  [[deprecated("This homeKit method has been deprecated and will be removed in a future version.  Please use the more generic setConnectionCallback() method instead.")]]
  Kit& setWifiCallback(void (*f)()){wifiCallback=f;return(*this);}                      // sets an optional user-defined function to call once WiFi connectivity is initially established

  [[deprecated("This homeKit method has been deprecated and will be removed in a future version.  Please use the more generic setConnectionCallback() method instead.")]]
  Kit& setWifiCallbackAll(void (*f)(int)){connectionCallback=f;return(*this);}          // sets an optional user-defined function to call every time WiFi connectivity is established or re-established  
};

///////////////////////////////

class KitAccessory{

  friend class Kit;
  friend class KitService;
  friend class KitCharacteristic;
  friend class KitButton;
    
  uint32_t aid=0;                                               // Accessory Instance ID (HAP Table 6-1)
  uint32_t iidCount=0;                                          // running count of iid to use for Services and Characteristics associated with this Accessory                                 
  vector<KitService *, Mallocator<KitService*>> Services;     // vector of pointers to all Services in this Accessory  

  void printfAttributes(int flags);                             // writes Accessory JSON to hapOut stream

  protected:

  ~KitAccessory();                                             // destructor

  public:

  void *operator new(size_t size){return(HK_MALLOC(size));}     // override new operator to use PSRAM when available
  void operator delete(void *p){free(p);}
  
  KitAccessory(uint32_t aid=0);                                // constructor
  uint32_t getAID(){return(aid);}
};

///////////////////////////////

class KitService{

  friend class Kit;
  friend class KitAccessory;
  friend class KitCharacteristic;

  uint32_t iid=0;                                                                   // Instance ID (HAP Table 6-2)
  const char *type;                                                                 // Service Type
  const char *hapName;                                                              // HAP Name
  boolean hidden=false;                                                             // optional property indicating service is hidden
  boolean primary=false;                                                            // optional property indicating service is primary
  vector<KitCharacteristic *, Mallocator<KitCharacteristic*>> Characteristics;    // vector of pointers to all Characteristics in this Service  
  vector<KitService *, Mallocator<KitService *>> linkedServices;                  // vector of pointers to any optional linked Services
  boolean isCustom;                                                                 // flag to indicate this is a Custom Service
  KitAccessory *accessory=NULL;                                                    // pointer to Accessory containing this Service
  
  void printfAttributes(int flags);                                                 // writes Service JSON to hapOut stream

  protected:
  
  virtual ~KitService();                                                           // destructor
  vector<HapChar *, Mallocator<HapChar*>> req;                                      // vector of pointers to all required HAP Characteristic Types for this Service
  vector<HapChar *, Mallocator<HapChar*>> opt;                                      // vector of pointers to all optional HAP Characteristic Types for this Service

  public:
  
  void *operator new(size_t size){return(HK_MALLOC(size));}                               // override new operator to use PSRAM when available
  void operator delete(void *p){free(p);}
  
  KitService(const char *type, const char *hapName, boolean isCustom=false);             // constructor
  KitService *setPrimary();                                                              // sets the Service Type to be primary and returns pointer to self
  KitService *setHidden();                                                               // sets the Service Type to be hidden and returns pointer to self
  KitService *addLink(KitService *svc);                                                 // adds svc as a Linked Service and returns pointer to self

  template <typename T=KitService *> vector<T, Mallocator<T>> getLinks(const char *hapName=NULL){     // returns linkedServices vector, mapped to <T>, for use as range in "for-each" loops
    vector<T, Mallocator<T>> v;
    for(auto svc : linkedServices){
      if(hapName==NULL || !strcmp(hapName,svc->hapName))
        v.push_back(static_cast<T>(svc));
    }
    return(v);
  }

  uint32_t getIID(){return(iid);}                         // returns IID of Service
  uint32_t getAID(){return(accessory->aid);}              // returns AID of enclosing Accessory

  virtual boolean update() {return(true);}                // placeholder for code that is called when a Service is updated via a Controller.  Must return true/false depending on success of update
  virtual void loop(){}                                   // loops for each Service - called every cycle if over-ridden with user-defined code
  virtual void button(int pin, int pressType){}           // method called for a Service when a button attached to "pin" has a Single, Double, or Long Press, according to pressType
};

///////////////////////////////

class KitCharacteristic{

  friend class Kit;
  friend class KitService;

  union UVal {                                  
    boolean BOOL;
    uint8_t UINT8;
    uint16_t UINT16;
    uint32_t UINT32;
    uint64_t UINT64;
    int32_t INT;
    double FLOAT;
    char * STRING = NULL;
  };

  class EVLIST : public vector<HAPClient *, Mallocator<HAPClient *>>{      // vector of current connections that have subscribed to EV notifications for this Characteristic
    public:
    boolean has(HAPClient *hc);                                     // returns true if pointer to connection hc is subscribed, else returns false
    void add(HAPClient *hc);                                        // adds connection hc as new subscriber, IF not already a subscriber
    void remove(HAPClient *hc);                                     // removes connection hc as a subscriber; okay to remove even if hc was not already a subscriber
  };

  uint32_t iid=0;                          // Instance ID (HAP Table 6-3)
  uint32_t aid=0;                          // AID for the enclosing Accessory
  HapChar *hapChar;                        // pointer to HAP Characteristic structure
  const char *type;                        // Characteristic Type
  const char *hapName;                     // HAP Name
  UVal value;                              // Characteristic Value
  uint8_t perms;                           // Characteristic Permissions
  FORMAT format;                           // Characteristic Format        
  char *desc=NULL;                         // Characteristic Description (optional)
  char *unit=NULL;                         // Characteristic Unit (optional)
  UVal minValue;                           // Characteristic minimum (not applicable for STRING)
  UVal maxValue;                           // Characteristic maximum (not applicable for STRING)
  UVal stepValue;                          // Characteristic step size (not applicable for STRING)
  uint8_t maxLen=0;                        // Characteristic maximum length (only applicable for STRING, 0=default)
  boolean staticRange;                     // Flag that indicates whether Range is static and cannot be changed with setRange()
  boolean customRange=false;               // Flag for custom ranges
  char *validValues=NULL;                  // Optional JSON array of valid values.  Applicable only to uint8 Characteristics
  char *nvsKey=NULL;                       // key for NVS storage of Characteristic value
  boolean isCustom;                        // flag to indicate this is a Custom Characteristic
  boolean setRangeError=false;             // flag to indicate attempt to set Range on Characteristic that does not support changes to Range
  boolean setValidValuesError=false;       // flag to indicate attempt to set Valid Values on Characteristic that does not support changes to Valid Values
  
  uint8_t updateFlag=0;                    // set to either 1 (for normal write) or 2 (for write-response) inside update() when Characteristic is successfully updated via Home App
  unsigned long updateTime=0;              // last time value was updated (in millis) either by PUT /characteristic OR by setVal()
  UVal newValue;                           // the updated value requested by PUT /characteristic
  KitService *service=NULL;               // pointer to Service containing this Characteristic
  EVLIST evList;                           // vector of current connections that have subscribed to EV notifications for this Characteristic 
    
  void printfAttributes(int flags);                           // writes Characteristic JSON to hapOut stream
  StatusCode loadUpdate(char *val, char *ev, boolean wr);     // load updated val/ev from PUT /characteristic JSON request.  Return intitial HAP status code (checks to see if characteristic is found, is writable, etc.)  
  String uvPrint(UVal &u);                                    // returns "printable" String for any type of Characteristic  
  
  void uvSet(UVal &dest, UVal &src);                          // copies UVal src into UVal dest
  void uvSet(UVal &u, STRING_t val);                          // copies string val into UVal u
  void uvSet(UVal &u, DATA_t data);                           // copies DATA data into UVal u (after transforming to a char *)
  void uvSet(UVal &u, TLV_ENC_t tlv);                         // copies TLV8 tlv into UVal u (after transforming to a char *)

  template <typename T> void uvSet(UVal &u, T val){           // copies numeric val into UVal u  
    switch(format){
      case FORMAT::BOOL:
        u.BOOL=(boolean)val;
      break;
      case FORMAT::INT:
        u.INT=(int)val;
      break;
      case FORMAT::UINT8:
        u.UINT8=(uint8_t)val;
      break;
      case FORMAT::UINT16:
        u.UINT16=(uint16_t)val;
      break;
      case FORMAT::UINT32:
        u.UINT32=(uint32_t)val;
      break;
      case FORMAT::UINT64:
        u.UINT64=(uint64_t)val;
      break;
      case FORMAT::FLOAT:
        u.FLOAT=(double)val;
      break;
      default:
      break;
    } // switch
  }
 
  char *getStringGeneric(UVal &val);                                      // gets the specified UVal for string-based Characteristics
  size_t getDataGeneric(uint8_t *data, size_t len, UVal &val);            // gets the specified UVal for data-based Characteristics
  size_t getTLVGeneric(TLV8 &tlv, UVal &val);                             // gets the specified UVal for tlv8-based Characteristics
  
  template <class T> T uvGet(UVal &u){                                    // gets the specified UVal for numeric-based Characteristics
  
    switch(format){   
      case FORMAT::BOOL:
        return((T) u.BOOL);        
      case FORMAT::INT:
        return((T) u.INT);        
      case FORMAT::UINT8:
        return((T) u.UINT8);        
      case FORMAT::UINT16:
        return((T) u.UINT16);        
      case FORMAT::UINT32:
        return((T) u.UINT32);        
      case FORMAT::UINT64:
        return((T) u.UINT64);        
      case FORMAT::FLOAT:
        return((T) u.FLOAT);        
      default:
      break;
    }
    return((T)0);       // included to prevent compiler warnings  
  }

  void setValCheck();                                                     // initial check before setting value of any Characteristic
  void setValFinish(boolean notify);                                      // final processing after setting value of any Characteristic
   
  protected:

  ~KitCharacteristic();                                      // destructor  
   
  template <typename T> void init(T val, boolean nvsStore, T min, T max){

    uvSet(value,val);

    if(nvsStore){
      nvsKey=(char *)HK_MALLOC(16);
      uint16_t t;
      sscanf(type,"%hx",&t);
      sprintf(nvsKey,"%04X%08lX%03lX",t,aid,iid&0xFFF);
      size_t len;    

      if(format<FORMAT::STRING){
        if(nvs_get_u64(homeKit.charNVS,nvsKey,&(value.UINT64))!=ESP_OK) {
          nvs_set_u64(homeKit.charNVS,nvsKey,value.UINT64);                // store data as uint64_t regardless of actual type (it will be read correctly when access through uvGet())         
          nvs_commit(homeKit.charNVS);                                     // commit to NVS  
        }     
      } else {
        if(!nvs_get_str(homeKit.charNVS,nvsKey,NULL,&len)){
          value.STRING = (char *)HK_REALLOC(value.STRING,len);
          nvs_get_str(homeKit.charNVS,nvsKey,value.STRING,&len);
        }
        else {
          nvs_set_str(homeKit.charNVS,nvsKey,value.STRING);               // store string data
          nvs_commit(homeKit.charNVS);                                    // commit to NVS  
        }
      }
    }
  
    uvSet(newValue,value);

    if(format<FORMAT::STRING){
      uvSet(minValue,min);
      uvSet(maxValue,max);
      uvSet(stepValue,0);
    }
          
  } // init()

  public:

  KitCharacteristic(HapChar *hapChar, boolean isCustom=false);                               // KitCharacteristic constructor
  void *operator new(size_t size){return(HK_MALLOC(size));}                                   // override new operator to use PSRAM when available
  void operator delete(void *p){free(p);}

  template <class T=int> T getVal(){return(uvGet<T>(value));}                                 // gets the value for numeric-based Characteristics
  char *getString(){return(getStringGeneric(value));}                                         // gets the value for string-based Characteristics
  size_t getData(uint8_t *data, size_t len){return(getDataGeneric(data,len,value));}          // gets the value for data-based Characteristics
  size_t getTLV(TLV8 &tlv){return(getTLVGeneric(tlv,value));}                                 // gets the value for tlv8-based Characteristics

  template <class T=int> T getNewVal(){return(uvGet<T>(newValue));}                           // gets the newValue for numeric-based Characteristics
  char *getNewString(){return(getStringGeneric(newValue));}                                   // gets the newValue for string-based Characteristics
  size_t getNewData(uint8_t *data, size_t len){return(getDataGeneric(data,len,newValue));}    // gets the newValue for data-based Characteristics
  size_t getNewTLV(TLV8 &tlv){return(getTLVGeneric(tlv,newValue));}                           // gets the newValue for tlv8-based Characteristics

  void setString(const char *val, boolean notify=true);                                       // sets the value and newValue for string-based Characteristic
  void setData(const uint8_t *data, size_t len, boolean notify=true);                         // sets the value and newValue for data-based Characteristic
  void setTLV(const TLV8 &tlv, boolean notify=true);                                          // sets the value and newValue for tlv8-based Characteristic
  
  template <typename T> void setVal(T val, boolean notify=true){                              // sets the value and newValue for numeric-based Characteristics

    setValCheck();
    
    if(!((val >= uvGet<T>(minValue)) && (val <= uvGet<T>(maxValue)))){
      LOG0("\n*** WARNING:  Attempt to update Characteristic::%s with setVal(%g) is out of range [%g,%g].  This may cause device to become non-responsive!\n\n",
      hapName,(double)val,uvGet<double>(minValue),uvGet<double>(maxValue));
    }
   
    uvSet(value,val);
    uvSet(newValue,value);
      
    updateTime=homeKit.snapTime;

    if(notify){
      if(updateFlag!=2){                        // do not broadcast EV if update is being done in context of write-response
        KitBuf sb;                             // create KitBuf object
        sb.characteristic=this;                 // set characteristic          
        sb.status=StatusCode::OK;               // set status
        char dummy[]="";
        sb.val=dummy;                           // set dummy "val" so that printfNotify knows to consider this "update"
        homeKit.Notifications.push_back(sb);   // store KitBuf in Notifications vector  
      }
    
      if(nvsKey){
        nvs_set_u64(homeKit.charNVS,nvsKey,value.UINT64);            // store data as uint64_t regardless of actual type (it will be read correctly when access through uvGet())         
        nvs_commit(homeKit.charNVS);
      }
    }
    
  } // setVal()  
    
  boolean updated();                                  // returns true within update() if Characteristic was updated by Home App 
  unsigned long timeVal();                            // returns time elapsed (in millis) since value was last updated, either by Home App or by using setVal()
  uint32_t getIID();                                  // returns IID of Characteristic
  uint32_t getAID();                                  // returns AID of enclosing Accessory
  boolean foundIn(const char *getCharList);           // returns true if Characteristics is found in getCharList, else returns false

  KitCharacteristic *setPerms(uint8_t perms);        // sets permissions of a Characteristic
  KitCharacteristic *addPerms(uint8_t dPerms);       // add permissions of a Characteristic  
  KitCharacteristic *removePerms(uint8_t dPerms);    // removes permissions of a Characteristic
  KitCharacteristic *setDescription(const char *c);  // sets description of a Characteristic
  KitCharacteristic *setUnit(const char *c);         // set unit of a Characteristic  
  KitCharacteristic *setValidValues(int n, ...);     // sets a list of 'n' valid values allowed for a Characteristic - only applicable if format=INT, UINT8, UINT16, or UINT32
  KitCharacteristic *setMaxStringLength(uint8_t n);  // sets maximum length of STRING Characteristics

  template <typename A, typename B, typename S=int> KitCharacteristic *setRange(A min, B max, S step=0){     // sets the allowed range of a Characteristic

    if(!staticRange){
      uvSet(minValue,min);
      uvSet(maxValue,max);
      uvSet(stepValue,step);  
      customRange=true; 
    } else
      setRangeError=true;
      
    return(this);
    
  } // setRange()
};

///////////////////////////////

class KitButton : public PushButton {

  friend class Kit;
  friend class KitService;
   
  uint16_t singleTime;           // minimum time (in millis) required to register a single press
  uint16_t longTime;             // minimum time (in millis) required to register a long press
  uint16_t doubleTime;           // maximum time (in millis) between single presses to register a double press instead
  KitService *service;          // Service to which this PushButton is attached  
  
  void check();                  // check PushButton and call button() if "pressed"

  protected:
  
  enum buttonType_t {
    HK_BUTTON,
    HK_TOGGLE
  };

  buttonType_t buttonType=HK_BUTTON;      // type of KitButton  
  
  public:
  
  KitButton(int pin, uint16_t longTime=2000, uint16_t singleTime=5, uint16_t doubleTime=200, triggerType_t triggerType=TRIGGER_ON_LOW);
  KitButton(int pin, triggerType_t triggerType, uint16_t longTime=2000, uint16_t singleTime=5, uint16_t doubleTime=200) : KitButton(pin,longTime,singleTime,doubleTime,triggerType){};

};

///////////////////////////////

class KitToggle : public KitButton {

  public:

  KitToggle(int pin, triggerType_t triggerType=TRIGGER_ON_LOW, uint16_t toggleTime=5) : KitButton(pin,triggerType,toggleTime){buttonType=HK_TOGGLE;};
  int position(){return(pressType);}
};

///////////////////////////////

class KitUserCommand {

  friend class Kit;
  
  const char *s;                                            // description of command
  void (*userFunction1)(const char *v)=NULL;                // user-defined function to call
  void (*userFunction2)(const char *v, void *arg)=NULL;     // user-defined function to call with user-defined arg
  void *userArg;

  public:

  KitUserCommand(char c, const char *s, void (*f)(const char *));  
  KitUserCommand(char c, const char *s, void (*f)(const char *, void *), void *arg);  
};

///////////////////////////////

class KitPoint {

  friend class Kit;

  int receiveSize;                            // size (in bytes) of messages to receive
  int sendSize;                               // size (in bytes) of messages to send
  esp_now_peer_info_t peerInfo;               // structure for all ESP-NOW peer data
  QueueHandle_t receiveQueue;                 // queue to store data after it is received
  uint32_t receiveTime=0;                     // time (in millis) of most recent data received
  
  static uint8_t lmk[16];
  static boolean initialized;
  static boolean isHub;
  static boolean useEncryption;
  static vector<KitPoint *, Mallocator<KitPoint *>> KitPoints;
  static uint16_t channelMask;                // channel mask (only used for remote devices)
  static QueueHandle_t statusQueue;           // queue for communication between KitPoint::dataSend and KitPoint::send
  static nvs_handle pointNVS;                 // NVS storage for channel number (only used for remote devices)

  static void dataReceived(const esp_now_recv_info *info, const uint8_t *incomingData, int len);
  static void init(const char *password="HomeKit");
  static void setAsHub(){isHub=true;}
  static uint8_t nextChannel();
  

#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 5, 0)
  static void dataSent(const esp_now_send_info_t *mac, esp_now_send_status_t status) {
#else
  static void dataSent(const uint8_t *mac, esp_now_send_status_t status) {
#endif
    xQueueOverwrite( statusQueue, &status );
  }
  
  public:

  KitPoint(const char *macAddress, int sendSize, int receiveSize, int queueDepth=1, boolean useAPaddress=false);
  static void setPassword(const char *pwd){init(pwd);}
  static void setChannelMask(uint16_t mask);
  static void setEncryption(boolean encrypt){useEncryption=encrypt;}
  boolean get(void *dataBuf);
  boolean send(const void *data);
  uint32_t time(){return(millis()-receiveTime);}
};

/////////////////////////////////////////////////

template <typename T>
class build : public T
{
public:
  std::function<void()> setupFunction;
  std::function<void()> updateFunction;

  // 构造函数，使用模板参数 T 来调用相应派生类的构造函数
  build(std::function<void()> setupFunc, std::function<void()> updateFunc)
      : T(), setupFunction(setupFunc), updateFunction(updateFunc)
  {
    setupFunction();
  }

  bool update()
  {
    updateFunction();
    return true;
  }
};

#include "Kit.h"
