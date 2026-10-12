#pragma once
// Dùng chung cho master (ESP-IDF, C) và node (Arduino, C++).
// Copy file này vào main/ của master và include/ (hoặc src/) của node.
#include <stdint.h>

#define PROTO_MAGIC      0xA5
#define UDP_PORT         4210      // node <-> master qua Wi-Fi LAN
#define MAX_TTL          6         // số lần chuyển tiếp tối đa
#define MAX_HOPS         6         // node xa hơn số hop này thì bỏ qua

enum {
    MSG_BEACON    = 1,   // ESP-NOW broadcast: "tôi cách master N hop"
    MSG_TELEMETRY = 2,   // node -> master (nhiệt độ, lux, trạng thái relay)
    MSG_CMD_RELAY = 3,   // master -> node (bật/tắt relay)
    MSG_ACK       = 4,   // master -> node (UDP) xác nhận đường Wi-Fi còn sống
    MSG_CFG_SET   = 5,   // master -> node: đặt tên / khu vực / loại thiết bị
    MSG_SAFETY_SET = 6,  // master -> node: ngưỡng cảnh báo / ngắt quá nhiệt (+ cờ mở khóa)
    MSG_OTA_CMD    = 7,  // master -> node: kiểm tra / cập nhật firmware (flags & FLAG_OTA_CHECK_ONLY = chỉ kiểm tra)
    MSG_OTA_STATUS = 8,  // node -> master: trạng thái OTA (ota_state, ota_pct, ota_err, fw_ver, fw_new)
};

#define NAME_LEN     32      // tên thiết bị, gồm cả '\0' (tiếng Việt có dấu ~2-3 byte/ký tự)
#define FLAG_NEW     0x01    // bit0 của flags: thiết bị mới, chưa được thiết lập

#define FLAG_OT_WARN    0x02 // TELEMETRY: đang vượt ngưỡng cảnh báo nhiệt độ
#define FLAG_OT_TRIP    0x04 // TELEMETRY: relay đã bị ngắt do quá nhiệt (khóa chốt, phải mở khóa thủ công)
#define FLAG_CLEAR_TRIP 0x08 // SAFETY_SET: yêu cầu mở khóa (node chỉ chấp nhận khi nhiệt độ đã hạ đủ)

// ---------- OTA ----------
#define OTA_CHECK_URL        "https://thanhluan.io.vn/ota/check_update.php"   // TODO: đổi thành URL file PHP kiểm tra phiên bản
#define FLAG_OTA_CHECK_ONLY  0x10  // OTA_CMD: chỉ kiểm tra, không tải

enum {   // ota_state
    OTA_ST_IDLE = 0, OTA_ST_CHECKING, OTA_ST_UP_TO_DATE, OTA_ST_AVAILABLE,
    OTA_ST_DOWNLOADING, OTA_ST_REBOOTING, OTA_ST_FAILED,
    OTA_ST_BUSY,     // node đang cập nhật rồi
    OTA_ST_SENT,     // (chỉ master phát) master đã chuyển lệnh xuống node
};
enum {   // ota_err
    OTA_ERR_NONE = 0, OTA_ERR_NO_WIFI, OTA_ERR_CHECK, OTA_ERR_DOWNLOAD, OTA_ERR_FLASH,
    OTA_ERR_NODE_UNKNOWN, OTA_ERR_SEND, OTA_ERR_NO_RESPONSE,
};

#define LINK_NONE    0       // chưa có đường lên
#define LINK_WIFI    1       // rssi = tín hiệu tới router Wi-Fi
#define LINK_ESPNOW  2       // rssi = tín hiệu tới node cha / master qua ESP-NOW

// Một gói duy nhất cho mọi loại tin (79 byte, vừa ESP-NOW 250 byte)
typedef struct __attribute__((packed)) {
    uint8_t  magic;
    uint8_t  type;
    uint8_t  ttl;
    uint8_t  hops;       // TELEMETRY: số lần đã bị chuyển tiếp | BEACON: số hop tới master
    uint8_t  src[6];     // MAC gốc của node tạo gói
    uint8_t  dst[6];     // CMD: MAC node đích | còn lại: 00..00 (= master)
    uint16_t seq;
} pkt_hdr_t;

typedef struct __attribute__((packed)) {
    pkt_hdr_t h;
    float     temp;      // °C
    float     lux;
    uint8_t   relay;     // TELEMETRY: trạng thái hiện tại | CMD_RELAY: lệnh (1=ON)
    int8_t    rssi;      // TELEMETRY: dBm đường lên của NODE GỐC (giữ nguyên khi relay)
    uint8_t   link;      // TELEMETRY: LINK_NONE / LINK_WIFI / LINK_ESPNOW
    uint8_t   flags;     // TELEMETRY: FLAG_NEW
    uint8_t   area;      // TELEMETRY / CFG_SET: chỉ số khu vực (bảng AREAS ở master)
    uint8_t   dtype;     // TELEMETRY / CFG_SET: chỉ số loại thiết bị (bảng TYPES ở master)
    char      name[NAME_LEN]; // TELEMETRY / CFG_SET: tên do người dùng đặt (UTF-8)
    int16_t   warn_c;    // TELEMETRY / SAFETY_SET: ngưỡng cảnh báo quá nhiệt, °C (0 = tắt)
    int16_t   cut_c;     // TELEMETRY / SAFETY_SET: ngưỡng ngắt relay,        °C (0 = tắt)
    uint32_t  fw_ver;    // TELEMETRY / OTA_STATUS: phiên bản firmware đang chạy
    uint32_t  fw_new;    // OTA_STATUS: phiên bản mới trên server (nếu biết)
    uint8_t   ota_state; // OTA_STATUS: OTA_ST_*
    uint8_t   ota_pct;   // OTA_STATUS: % tải (0..100)
    uint8_t   ota_err;   // OTA_STATUS: OTA_ERR_*
} pkt_t;

// ---------- Provisioning qua BLE ----------
#define BLE_NAME_PREFIX     "SHN-"                                   // node quảng bá tên SHN-xxxxxx
#define PROV_SVC_UUID_STR   "5a1d0001-4c0e-4b6f-9a53-7e5d1a00a001"
#define PROV_CHR_UUID_STR   "5a1d0002-4c0e-4b6f-9a53-7e5d1a00a001"
#define PROV_MAGIC          0xB1

typedef struct __attribute__((packed)) {
    uint8_t  magic;
    uint8_t  channel;        // kênh Wi-Fi của router (để ESP-NOW cùng kênh)
    uint8_t  master_mac[6];  // MAC STA của master
    uint32_t master_ip;      // IP master (byte order của lwip)
    char     ssid[33];
    char     pass[65];
} prov_blob_t;
