#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include "esp_system.h"
#include "esp_heap_caps.h"
#include "esp_mac.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_now.h"
#include "esp_log.h"
#include "esp_crt_bundle.h"
#include "mqtt_client.h"
#include "lwip/sockets.h"
#include "cJSON.h"
#include "esp_timer.h"
#include "esp_sntp.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"
#include "esp_ota_ops.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/event_groups.h"

#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/util/util.h"

#include "proto.h"

// 1. Cấu hình Wi-Fi
#define WIFI_SSID           "Hoi Chu Tro"
#define WIFI_PASS           "bodeocho"
#define WIFI_CONNECTED_BIT  BIT0

// 2. Cấu hình EMQX qua Cloudflare Tunnel WSS
#define MQTT_BROKER_URI     "wss://mqtt.thanhluan.io.vn/mqtt"
#define MQTT_USERNAME       "esp32_node1"
#define MQTT_PASSWORD       "080305"

#define TOPIC_COMMAND       "home/esp/command"       // payload: "scan"
#define TOPIC_SCAN_RESULT   "home/esp/scan/result"   // Master báo kết quả quét/provision
#define TOPIC_NODE_SET      "home/node/+/set"        // Điều khiển relay: home/node/<MAC>/set (ON|OFF)
#define TOPIC_NODE_CFG      "home/node/+/config"     // Đặt tên: home/node/<MAC>/config {"name","area","type"}
#define TOPIC_NODE_SAFETY   "home/node/+/safety"     // Quá nhiệt: {"warn_c":45,"cut_c":60,"clear":false}
#define TOPIC_RULE_SET      "home/esp/rule/+/set"    // Tự động hóa: home/esp/rule/<0..15>/set (JSON; payload rỗng = xóa)
// Master publish (retained) từng luật ở home/esp/rule/<id>, log hành động ở home/esp/automation/event
// Cảnh báo quá nhiệt: home/node/<MAC>/alert

#define TZ_POSIX            "ICT-7"                  // UTC+7
#define MAX_RULES           16
#define SENSOR_STALE_MS     30000                    // dữ liệu cảm biến cũ hơn mức này thì không dùng để kích luật
#define FW_VERSION          1                        // PHẢI bằng số N trong tên file master_N.bin trên server
#define TOPIC_OTA_CMD       "home/esp/ota/cmd"       // {"target":"master"} | {"target":"node","mac":"<MAC>|all"} [,"check_only":true]
// Phản hồi OTA: home/esp/ota/status (master), home/node/<MAC>/ota (node); phiên bản: home/esp/info (retained), telemetry.fw
// Master forward telemetry của node lên: home/node/<MAC>/telemetry

#define BLE_SCAN_MS         8000
#define MAX_NODES           16
#define BEACON_PERIOD_MS    3000

static const char *TAG = "EMQX_IDF";
static EventGroupHandle_t s_wifi_event_group;
static esp_mqtt_client_handle_t s_mqtt_client = NULL;
static bool s_mqtt_connected = false;

static uint8_t s_my_mac[6];
static const uint8_t BCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// Bảng khu vực / loại thiết bị (chỉ số được lưu trong node -> chỉ nối thêm ở CUỐI bảng)
static const char *AREAS[] = {"unassigned", "living_room", "bedroom", "kitchen", "bathroom", "other"};
static const char *TYPES[] = {"unassigned", "light", "fan", "other"};
#define N_AREAS ((int)(sizeof(AREAS) / sizeof(AREAS[0])))
#define N_TYPES ((int)(sizeof(TYPES) / sizeof(TYPES[0])))

/* ======================================================================
 *  Tiện ích
 * ====================================================================== */
static void mac_to_str(const uint8_t *m, char *out /*13*/) {
    snprintf(out, 13, "%02X%02X%02X%02X%02X%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
}

static bool parse_mac_hex(const char *s, uint8_t *out) {
    for (int i = 0; i < 6; i++) {
        char t[3] = { s[i * 2], s[i * 2 + 1], 0 };
        char *end;
        long v = strtol(t, &end, 16);
        if (*end != 0) return false;
        out[i] = (uint8_t)v;
    }
    return true;
}

static void mqtt_pub_r(const char *topic, const char *payload, int retain) {
    if (!s_mqtt_connected || !s_mqtt_client) return;
    esp_mqtt_client_publish(s_mqtt_client, topic, payload, 0, 1, retain);
}

static void mqtt_pub(const char *topic, const char *payload) {
    mqtt_pub_r(topic, payload, 0);
}

static uint32_t now_ms(void) {
    return (uint32_t)(esp_timer_get_time() / 1000);
}

static bool bytes_is(const char *p, int len, const char *s) {
    return len == (int)strlen(s) && memcmp(p, s, len) == 0;
}

static void log_memory_usage(void) {
    size_t free_heap = esp_get_free_heap_size();
    size_t internal_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);

    ESP_LOGI(TAG, "RAM heap: free=%u bytes (%u KB), min=%u bytes, internal=%u bytes, largest=%u bytes",
             (unsigned)free_heap,
             (unsigned)(free_heap / 1024),
             (unsigned)esp_get_minimum_free_heap_size(),
             (unsigned)internal_free,
             (unsigned)largest_block);

    TaskStatus_t tasks[32];
    UBaseType_t task_count = uxTaskGetSystemState(tasks, 32, NULL);
    ESP_LOGI(TAG, "Task memory usage: %u task(s)", (unsigned)task_count);
    for (UBaseType_t i = 0; i < task_count; i++) {
        size_t stack_free = tasks[i].usStackHighWaterMark * sizeof(StackType_t);
        ESP_LOGI(TAG, "  task=%-16s priority=%u stack_free_min=%u bytes",
                 tasks[i].pcTaskName,
                 (unsigned)tasks[i].uxCurrentPriority,
                 (unsigned)stack_free);
    }
}

/* ======================================================================
 *  Bảng node + gửi lệnh xuống node (UDP hoặc ESP-NOW)
 * ====================================================================== */
typedef struct {
    bool     used;
    uint8_t  mac[6];
    bool     via_udp;           // true: next hop là IP; false: next hop là MAC ESP-NOW
    struct sockaddr_in addr;    // next hop (UDP)
    uint8_t  next_mac[6];       // next hop (ESP-NOW)
    uint8_t  hops;
    // --- báo cáo gần nhất của node ---
    float    temp, lux;
    uint8_t  relay;
    uint8_t  flags;             // cờ lần trước (để phát hiện chuyển trạng thái cảnh báo)
    int16_t  warn_c, cut_c;     // ngưỡng quá nhiệt node đang dùng
    uint32_t last_ms;           // lúc nhận telemetry gần nhất
    // --- relay mong muốn (tự động hóa) để gửi lại nếu mất gói ---
    bool     want_valid, want_on;
    uint8_t  want_tries;
    uint32_t want_ms;
    // --- OTA ---
    uint32_t fw;                // phiên bản firmware node đang chạy
    bool     ota_pending, ota_check_only;
    uint8_t  ota_tries;
    uint32_t ota_ms;
} node_t;

static node_t s_nodes[MAX_NODES];
static int    s_sock = -1;

static node_t *node_find(const uint8_t *mac, bool create) {
    node_t *free_slot = NULL;
    for (int i = 0; i < MAX_NODES; i++) {
        if (s_nodes[i].used) {
            if (memcmp(s_nodes[i].mac, mac, 6) == 0) return &s_nodes[i];
        } else if (!free_slot) {
            free_slot = &s_nodes[i];
        }
    }
    if (create && free_slot) {
        memset(free_slot, 0, sizeof(*free_slot));
        free_slot->used = true;
        memcpy(free_slot->mac, mac, 6);
        return free_slot;
    }
    return NULL;
}

static void ensure_peer(const uint8_t *mac) {
    if (esp_now_is_peer_exist(mac)) return;
    esp_now_peer_info_t p = {0};
    memcpy(p.peer_addr, mac, 6);
    p.channel = 0;                 // 0 = kênh hiện tại của Wi-Fi STA
    p.ifidx   = WIFI_IF_STA;
    p.encrypt = false;
    esp_now_add_peer(&p);
}

// Gửi một gói xuống node theo đường đã học (UDP hoặc ESP-NOW next hop)
static esp_err_t send_to_node(const uint8_t *mac, const pkt_t *p) {
    node_t *n = node_find(mac, false);
    if (!n) return ESP_ERR_NOT_FOUND;

    if (n->via_udp) {
        if (s_sock < 0) return ESP_FAIL;
        int r = sendto(s_sock, p, sizeof(*p), 0, (struct sockaddr *)&n->addr, sizeof(n->addr));
        return r == (int)sizeof(*p) ? ESP_OK : ESP_FAIL;
    }
    ensure_peer(n->next_mac);
    return esp_now_send(n->next_mac, (const uint8_t *)p, sizeof(*p));
}

static void init_cmd_hdr(pkt_t *p, uint8_t type, const uint8_t *dst) {
    memset(p, 0, sizeof(*p));
    p->h.magic = PROTO_MAGIC;
    p->h.type  = type;
    p->h.ttl   = MAX_TTL;
    memcpy(p->h.src, s_my_mac, 6);
    memcpy(p->h.dst, dst, 6);
}

static esp_err_t send_relay_cmd(const uint8_t *mac, bool on) {
    pkt_t p;
    init_cmd_hdr(&p, MSG_CMD_RELAY, mac);
    p.relay = on ? 1 : 0;
    return send_to_node(mac, &p);
}

static int lookup_idx(const cJSON *item, const char **tab, int n) {
    if (!cJSON_IsString(item) || !item->valuestring) return -1;
    for (int i = 0; i < n; i++)
        if (strcmp(item->valuestring, tab[i]) == 0) return i;
    return -1;
}

// Chép tên và cắt sao cho không làm hỏng ký tự UTF-8 ở giữa
static void copy_name_utf8(char *dst, size_t cap, const char *src) {
    size_t n = strlen(src);
    if (n >= cap) {
        n = cap - 1;
        while (n > 0 && ((uint8_t)src[n] & 0xC0) == 0x80) n--;
    }
    memcpy(dst, src, n);
    dst[n] = 0;
}

// home/node/<MAC>/config  {"name":"Đèn bàn","area":"living_room","type":"light"}
static void handle_config(const uint8_t *mac, const char *data, int dl) {
    cJSON *j = cJSON_ParseWithLength(data, dl);
    if (!j) { ESP_LOGW(TAG, "Config JSON loi"); return; }

    const cJSON *name = cJSON_GetObjectItem(j, "name");
    int area  = lookup_idx(cJSON_GetObjectItem(j, "area"), AREAS, N_AREAS);
    int dtype = lookup_idx(cJSON_GetObjectItem(j, "type"), TYPES, N_TYPES);

    if (!cJSON_IsString(name) || !name->valuestring || !name->valuestring[0] || area < 0 || dtype < 0) {
        ESP_LOGW(TAG, "Config khong hop le (can name, area, type)");
    } else {
        pkt_t p;
        init_cmd_hdr(&p, MSG_CFG_SET, mac);
        p.area  = (uint8_t)area;
        p.dtype = (uint8_t)dtype;
        copy_name_utf8(p.name, NAME_LEN, name->valuestring);
        esp_err_t e = send_to_node(mac, &p);
        ESP_LOGI(TAG, "Config -> \"%s\" area=%s type=%s (%s)", p.name, AREAS[area], TYPES[dtype], esp_err_to_name(e));
    }
    cJSON_Delete(j);
}

/* ======================================================================
 *  OTA: master tự cập nhật, hoặc ra lệnh cho node cập nhật; luôn phản hồi trạng thái
 * ====================================================================== */
static const char *OTA_STATE_NAMES[] = {"idle", "checking", "up_to_date", "available", "downloading",
                                        "rebooting", "failed", "busy", "sent"};
static const char *OTA_ERR_NAMES[]   = {"none", "no_wifi", "check_failed", "download_failed", "flash_failed",
                                        "node_unknown", "send_failed", "no_response"};
#define N_OTA_ST  ((int)(sizeof(OTA_STATE_NAMES) / sizeof(OTA_STATE_NAMES[0])))
#define N_OTA_ERR ((int)(sizeof(OTA_ERR_NAMES) / sizeof(OTA_ERR_NAMES[0])))

static volatile bool s_ota_busy = false;
static volatile bool s_ota_check_only = false;

// topic: home/esp/ota/status (master) hoặc home/node/<MAC>/ota (node)
static void publish_ota(const char *topic, const char *target, int state, int pct, int err,
                        uint32_t cur, uint32_t latest) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "target",  target);
    cJSON_AddStringToObject(o, "state",   (state >= 0 && state < N_OTA_ST) ? OTA_STATE_NAMES[state] : "unknown");
    cJSON_AddNumberToObject(o, "pct",     pct);
    cJSON_AddNumberToObject(o, "current", cur);
    cJSON_AddNumberToObject(o, "latest",  latest);
    if (err) cJSON_AddStringToObject(o, "error", (err >= 0 && err < N_OTA_ERR) ? OTA_ERR_NAMES[err] : "unknown");
    char *str = cJSON_PrintUnformatted(o);
    if (str) {
        mqtt_pub(topic, str);
        ESP_LOGI(TAG, "[OTA %s] %s", target, str);
        cJSON_free(str);
    }
    cJSON_Delete(o);
}

static void ota_node_topic(const uint8_t *mac, char *id /*13*/, char *topic /*64*/) {
    mac_to_str(mac, id);
    snprintf(topic, 64, "home/node/%s/ota", id);
}

// Gửi lệnh OTA xuống node và đánh dấu chờ phản hồi (ota_retry sẽ gửi lại nếu node không trả lời)
static void ota_send_node(const uint8_t *mac, bool check_only) {
    char id[13], topic[64];
    ota_node_topic(mac, id, topic);
    node_t *n = node_find(mac, false);
    if (!n) { publish_ota(topic, id, OTA_ST_FAILED, 0, OTA_ERR_NODE_UNKNOWN, 0, 0); return; }

    pkt_t p;
    init_cmd_hdr(&p, MSG_OTA_CMD, mac);
    if (check_only) p.flags |= FLAG_OTA_CHECK_ONLY;
    esp_err_t e = send_to_node(mac, &p);
    if (e != ESP_OK) { publish_ota(topic, id, OTA_ST_FAILED, 0, OTA_ERR_SEND, n->fw, 0); return; }

    n->ota_pending    = true;
    n->ota_check_only = check_only;
    n->ota_tries      = 1;
    n->ota_ms         = now_ms();
    publish_ota(topic, id, OTA_ST_SENT, 0, OTA_ERR_NONE, n->fw, 0);       // master đã chuyển lệnh
}

static void ota_retry(node_t *n, uint32_t now) {
    if (!n->ota_pending || now - n->ota_ms < 6000) return;
    char id[13], topic[64];
    ota_node_topic(n->mac, id, topic);
    if (n->ota_tries >= 3) {
        n->ota_pending = false;
        publish_ota(topic, id, OTA_ST_FAILED, 0, OTA_ERR_NO_RESPONSE, n->fw, 0);
        return;
    }
    n->ota_tries++;
    n->ota_ms = now;
    pkt_t p;
    init_cmd_hdr(&p, MSG_OTA_CMD, n->mac);
    if (n->ota_check_only) p.flags |= FLAG_OTA_CHECK_ONLY;
    send_to_node(n->mac, &p);
}

static int http_get_text(const char *url, char *buf, size_t cap) {
    esp_http_client_config_t cfg = {
        .url = url,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = 10000,
    };
    esp_http_client_handle_t c = esp_http_client_init(&cfg);
    if (!c) return -1;
    int total = -1;
    if (esp_http_client_open(c, 0) == ESP_OK) {
        esp_http_client_fetch_headers(c);
        if (esp_http_client_get_status_code(c) == 200) {
            total = 0;
            while (total < (int)cap - 1) {
                int r = esp_http_client_read(c, buf + total, cap - 1 - total);
                if (r <= 0) break;
                total += r;
            }
            buf[total] = 0;
        }
        esp_http_client_close(c);
    }
    esp_http_client_cleanup(c);
    return total;
}

static void master_ota_status(int state, int pct, int err, uint32_t latest) {
    publish_ota("home/esp/ota/status", "master", state, pct, err, FW_VERSION, latest);
}

static void master_ota_run(bool check_only) {
    master_ota_status(OTA_ST_CHECKING, 0, OTA_ERR_NONE, 0);

    char url[200], body[512];
    snprintf(url, sizeof(url), "%s?type=master&v=%d", OTA_CHECK_URL, FW_VERSION);
    if (http_get_text(url, body, sizeof(body)) < 0) { master_ota_status(OTA_ST_FAILED, 0, OTA_ERR_CHECK, 0); return; }

    cJSON *j = cJSON_Parse(body);
    if (!j) { master_ota_status(OTA_ST_FAILED, 0, OTA_ERR_CHECK, 0); return; }
    bool has = cJSON_IsTrue(cJSON_GetObjectItem(j, "has_update"));
    const cJSON *lv = cJSON_GetObjectItem(j, "latest_version");
    const cJSON *bu = cJSON_GetObjectItem(j, "bin_url");
    uint32_t latest = cJSON_IsNumber(lv) ? (uint32_t)lv->valuedouble : 0;
    char bin[200] = {0};
    if (has && cJSON_IsString(bu) && bu->valuestring) strlcpy(bin, bu->valuestring, sizeof(bin));
    cJSON_Delete(j);

    if (!has)     { master_ota_status(OTA_ST_UP_TO_DATE, 0, OTA_ERR_NONE, FW_VERSION); return; }
    if (!bin[0])  { master_ota_status(OTA_ST_FAILED, 0, OTA_ERR_CHECK, latest); return; }
    if (check_only) { master_ota_status(OTA_ST_AVAILABLE, 0, OTA_ERR_NONE, latest); return; }

    ESP_LOGI(TAG, "OTA master: tai %s (v%d -> v%u)", bin, FW_VERSION, (unsigned)latest);
    master_ota_status(OTA_ST_DOWNLOADING, 0, OTA_ERR_NONE, latest);

    esp_http_client_config_t hc = {
        .url = bin,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = 15000,
        .keep_alive_enable = true,
    };
    esp_https_ota_config_t oc = { .http_config = &hc };
    esp_https_ota_handle_t h = NULL;
    if (esp_https_ota_begin(&oc, &h) != ESP_OK) { master_ota_status(OTA_ST_FAILED, 0, OTA_ERR_DOWNLOAD, latest); return; }

    int total = esp_https_ota_get_image_size(h);
    int last = -10;
    esp_err_t e;
    while ((e = esp_https_ota_perform(h)) == ESP_ERR_HTTPS_OTA_IN_PROGRESS) {
        if (total > 0) {
            int pct = (int)((int64_t)esp_https_ota_get_image_len_read(h) * 100 / total);
            if (pct >= last + 10) {
                last = pct - pct % 10;
                master_ota_status(OTA_ST_DOWNLOADING, pct, OTA_ERR_NONE, latest);
            }
        }
    }

    if (e == ESP_OK && esp_https_ota_is_complete_data_received(h)) {
        if (esp_https_ota_finish(h) == ESP_OK) {
            master_ota_status(OTA_ST_REBOOTING, 100, OTA_ERR_NONE, latest);
            vTaskDelay(pdMS_TO_TICKS(2000));              // chờ MQTT gửi xong trạng thái
            esp_restart();
        }
        master_ota_status(OTA_ST_FAILED, 0, OTA_ERR_FLASH, latest);     // sai chữ ký/ảnh hỏng
    } else {
        esp_https_ota_abort(h);
        ESP_LOGE(TAG, "OTA master loi: %s", esp_err_to_name(e));
        master_ota_status(OTA_ST_FAILED, 0, OTA_ERR_DOWNLOAD, latest);
    }
}

static void ota_task(void *arg) {
    master_ota_run(s_ota_check_only);
    s_ota_busy = false;
    vTaskDelete(NULL);
}

// home/esp/ota/cmd
//   {"target":"master"}                                  cập nhật master (nếu có bản mới)
//   {"target":"node","mac":"AABBCCDDEEFF"}               cập nhật 1 node   ("mac":"all" = mọi node đã biết)
//   thêm "check_only":true để chỉ kiểm tra, không cài
static void handle_ota_cmd(const char *data, int dl) {
    cJSON *j = cJSON_ParseWithLength(data, dl);
    if (!j) { ESP_LOGW(TAG, "OTA cmd JSON loi"); return; }
    const cJSON *tg = cJSON_GetObjectItem(j, "target");
    const cJSON *mc = cJSON_GetObjectItem(j, "mac");
    bool check_only = cJSON_IsTrue(cJSON_GetObjectItem(j, "check_only"));

    if (cJSON_IsString(tg) && tg->valuestring && strcmp(tg->valuestring, "master") == 0) {
        if (s_ota_busy) {
            master_ota_status(OTA_ST_BUSY, 0, OTA_ERR_NONE, 0);
        } else {
            s_ota_busy = true;
            s_ota_check_only = check_only;
            if (xTaskCreate(ota_task, "ota", 10240, NULL, 3, NULL) != pdPASS) {
                s_ota_busy = false;
                master_ota_status(OTA_ST_FAILED, 0, OTA_ERR_DOWNLOAD, 0);
            }
        }
    } else if (cJSON_IsString(tg) && tg->valuestring && strcmp(tg->valuestring, "node") == 0
               && cJSON_IsString(mc) && mc->valuestring) {
        if (strcmp(mc->valuestring, "all") == 0) {
            for (int i = 0; i < MAX_NODES; i++)
                if (s_nodes[i].used) ota_send_node(s_nodes[i].mac, check_only);
        } else {
            uint8_t mac[6];
            if (strlen(mc->valuestring) == 12 && parse_mac_hex(mc->valuestring, mac)) ota_send_node(mac, check_only);
            else ESP_LOGW(TAG, "OTA: MAC khong hop le");
        }
    } else {
        ESP_LOGW(TAG, "OTA cmd khong hop le (target master|node)");
    }
    cJSON_Delete(j);
}

/* ======================================================================
 *  Gửi relay có xác nhận + bảo vệ quá nhiệt (cấu hình) + tự động hóa
 * ====================================================================== */

// Gửi lệnh relay và nhớ trạng thái mong muốn; reconcile_nodes() gửi lại nếu node chưa khớp
static esp_err_t request_relay(const uint8_t *mac, bool on) {
    node_t *n = node_find(mac, false);
    if (!n) return ESP_ERR_NOT_FOUND;
    n->want_valid = true;
    n->want_on    = on;
    n->want_tries = 1;
    n->want_ms    = now_ms();
    return send_relay_cmd(mac, on);
}

static void reconcile_nodes(void) {
    uint32_t now = now_ms();
    for (int i = 0; i < MAX_NODES; i++) {
        node_t *n = &s_nodes[i];
        if (!n->used) continue;
        ota_retry(n, now);
        if (!n->want_valid) continue;
        if (n->relay == (n->want_on ? 1 : 0)) { n->want_valid = false; continue; }          // đã khớp
        if (n->want_on && (n->flags & FLAG_OT_TRIP)) { n->want_valid = false; continue; }    // node đang khóa quá nhiệt
        if (now - n->want_ms < 4000) continue;
        if (n->want_tries >= 3) {
            ESP_LOGW(TAG, "Relay khong dat trang thai mong muon sau 3 lan, bo qua");
            n->want_valid = false;
            continue;
        }
        n->want_tries++;
        n->want_ms = now;
        send_relay_cmd(n->mac, n->want_on);
    }
}

// home/node/<MAC>/safety  {"warn_c":45,"cut_c":60,"clear":false}   (khóa nào vắng mặt thì giữ giá trị node đang dùng)
static void handle_safety(const uint8_t *mac, const char *data, int dl) {
    node_t *n = node_find(mac, false);
    if (!n) { ESP_LOGW(TAG, "Safety: chua biet node nay (cho node gui telemetry)"); return; }
    cJSON *j = cJSON_ParseWithLength(data, dl);
    if (!j) { ESP_LOGW(TAG, "Safety JSON loi"); return; }

    int warn = n->warn_c, cut = n->cut_c;
    bool ok = true;
    const cJSON *w = cJSON_GetObjectItem(j, "warn_c");
    const cJSON *c = cJSON_GetObjectItem(j, "cut_c");
    if (w) { if (cJSON_IsNumber(w)) warn = (int)w->valuedouble; else ok = false; }
    if (c) { if (cJSON_IsNumber(c)) cut  = (int)c->valuedouble;  else ok = false; }
    if (warn < 0 || warn > 150 || cut < 0 || cut > 150) ok = false;
    if (warn > 0 && cut > 0 && warn >= cut) ok = false;

    if (!ok) {
        ESP_LOGW(TAG, "Safety khong hop le (0..150, warn < cut, 0 = tat)");
    } else {
        pkt_t p;
        init_cmd_hdr(&p, MSG_SAFETY_SET, mac);
        p.warn_c = (int16_t)warn;
        p.cut_c  = (int16_t)cut;
        if (cJSON_IsTrue(cJSON_GetObjectItem(j, "clear"))) p.flags |= FLAG_CLEAR_TRIP;
        esp_err_t e = send_to_node(mac, &p);
        ESP_LOGI(TAG, "Safety warn=%d cut=%d clear=%d (%s)", warn, cut, (p.flags & FLAG_CLEAR_TRIP) ? 1 : 0, esp_err_to_name(e));
    }
    cJSON_Delete(j);
}

/* ---- Thời gian (SNTP, UTC+7) ---- */
static void time_start(void) {
    setenv("TZ", TZ_POSIX, 1);
    tzset();
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "pool.ntp.org");
    esp_sntp_setservername(1, "time.google.com");
    esp_sntp_init();
}

static bool time_valid(void) {
    time_t t;
    time(&t);
    return t > 1700000000;       // đã đồng bộ NTP (sau năm 2023)
}

/* ---- Luật tự động hóa (lưu NVS, chạy tại master) ---- */
enum { RULE_TIME = 1, RULE_SENSOR = 2 };
enum { METRIC_TEMP = 0, METRIC_LIGHT = 1 };
enum { OP_GT = 0, OP_LT = 1 };

typedef struct {
    uint8_t  used, enabled, type;
    uint8_t  action;           // 1 = BẬT, 0 = TẮT
    uint8_t  target[6];        // node bị điều khiển
    uint8_t  days;             // RULE_TIME: bit0 = CN ... bit6 = T7 (khớp tm_wday)
    uint8_t  src[6];           // RULE_SENSOR: node nguồn cảm biến
    uint8_t  metric, op, revert;
    int16_t  at_min;           // RULE_TIME: số phút từ 00:00
    int16_t  win_from, win_to; // RULE_SENSOR: khung giờ (phút), -1 = không giới hạn
    float    value, hyst;
} rule_t;

typedef struct { bool active; int32_t last_key; } rule_rt_t;   // trạng thái chạy, không lưu NVS

static rule_t            s_rules[MAX_RULES];
static rule_rt_t         s_rt[MAX_RULES];
static SemaphoreHandle_t s_rules_mux;

static void rules_save(void) {
    nvs_handle_t h;
    if (nvs_open("auto", NVS_READWRITE, &h) != ESP_OK) return;
    nvs_set_blob(h, "rules", s_rules, sizeof(s_rules));
    nvs_commit(h);
    nvs_close(h);
}

static void rules_load(void) {
    memset(s_rules, 0, sizeof(s_rules));
    nvs_handle_t h;
    if (nvs_open("auto", NVS_READONLY, &h) == ESP_OK) {
        static rule_t tmp[MAX_RULES];
        size_t n = sizeof(tmp);
        if (nvs_get_blob(h, "rules", tmp, &n) == ESP_OK && n == sizeof(tmp)) memcpy(s_rules, tmp, sizeof(tmp));
        nvs_close(h);
    }
    for (int i = 0; i < MAX_RULES; i++) { s_rt[i].active = false; s_rt[i].last_key = -1; }
}

static int parse_hm(const cJSON *it) {          // "HH:MM" -> phút, -1 nếu sai
    if (!cJSON_IsString(it) || !it->valuestring) return -1;
    int h, m;
    if (sscanf(it->valuestring, "%d:%d", &h, &m) != 2) return -1;
    if (h < 0 || h > 23 || m < 0 || m > 59) return -1;
    return h * 60 + m;
}

static bool parse_mac_item(const cJSON *it, uint8_t *out) {
    return cJSON_IsString(it) && it->valuestring && strlen(it->valuestring) == 12 && parse_mac_hex(it->valuestring, out);
}

static bool parse_rule(const cJSON *j, rule_t *r) {
    memset(r, 0, sizeof(*r));
    r->used    = 1;
    r->enabled = cJSON_IsFalse(cJSON_GetObjectItem(j, "en")) ? 0 : 1;

    const cJSON *act = cJSON_GetObjectItem(j, "action");
    if (!cJSON_IsString(act) || !act->valuestring) return false;
    if (strcmp(act->valuestring, "on") == 0)       r->action = 1;
    else if (strcmp(act->valuestring, "off") == 0) r->action = 0;
    else return false;

    if (!parse_mac_item(cJSON_GetObjectItem(j, "target"), r->target)) return false;

    const cJSON *ty = cJSON_GetObjectItem(j, "type");
    if (!cJSON_IsString(ty) || !ty->valuestring) return false;

    if (strcmp(ty->valuestring, "time") == 0) {
        r->type   = RULE_TIME;
        r->at_min = (int16_t)parse_hm(cJSON_GetObjectItem(j, "time"));
        if (r->at_min < 0) return false;
        const cJSON *days = cJSON_GetObjectItem(j, "days");
        if (cJSON_IsArray(days)) {
            const cJSON *d;
            cJSON_ArrayForEach(d, days) {
                if (!cJSON_IsNumber(d) || d->valueint < 0 || d->valueint > 6) return false;
                r->days |= (uint8_t)(1u << d->valueint);
            }
        }
        if (!r->days) r->days = 0x7F;                       // không ghi "days" = mọi ngày
    } else if (strcmp(ty->valuestring, "sensor") == 0) {
        r->type = RULE_SENSOR;
        if (!parse_mac_item(cJSON_GetObjectItem(j, "src"), r->src)) return false;

        const cJSON *m = cJSON_GetObjectItem(j, "metric");
        if (!cJSON_IsString(m) || !m->valuestring) return false;
        if (strcmp(m->valuestring, "temp") == 0)       r->metric = METRIC_TEMP;
        else if (strcmp(m->valuestring, "light") == 0) r->metric = METRIC_LIGHT;
        else return false;

        const cJSON *op = cJSON_GetObjectItem(j, "op");
        if (!cJSON_IsString(op) || !op->valuestring) return false;
        if (strcmp(op->valuestring, ">") == 0)      r->op = OP_GT;
        else if (strcmp(op->valuestring, "<") == 0) r->op = OP_LT;
        else return false;

        const cJSON *v = cJSON_GetObjectItem(j, "value");
        if (!cJSON_IsNumber(v)) return false;
        r->value = (float)v->valuedouble;

        const cJSON *hy = cJSON_GetObjectItem(j, "hyst");
        if (hy) {
            if (!cJSON_IsNumber(hy) || hy->valuedouble < 0) return false;
            r->hyst = (float)hy->valuedouble;
        }
        r->revert = cJSON_IsTrue(cJSON_GetObjectItem(j, "revert")) ? 1 : 0;

        const cJSON *from = cJSON_GetObjectItem(j, "from");
        const cJSON *to   = cJSON_GetObjectItem(j, "to");
        if (from || to) {
            r->win_from = (int16_t)parse_hm(from);
            r->win_to   = (int16_t)parse_hm(to);
            if (r->win_from < 0 || r->win_to < 0 || r->win_from == r->win_to) return false;
        } else {
            r->win_from = -1;
            r->win_to   = -1;
        }
    } else {
        return false;
    }
    return true;
}

static cJSON *rule_to_json(int id) {
    const rule_t *r = &s_rules[id];
    char mac[13], hm[16];
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "id", id);
    cJSON_AddBoolToObject(o, "en", r->enabled);
    mac_to_str(r->target, mac);
    cJSON_AddStringToObject(o, "target", mac);
    cJSON_AddStringToObject(o, "action", r->action ? "on" : "off");

    if (r->type == RULE_TIME) {
        cJSON_AddStringToObject(o, "type", "time");
        snprintf(hm, sizeof(hm), "%02d:%02d", r->at_min / 60, r->at_min % 60);
        cJSON_AddStringToObject(o, "time", hm);
        cJSON *d = cJSON_AddArrayToObject(o, "days");
        for (int k = 0; k < 7; k++)
            if (r->days & (1 << k)) cJSON_AddItemToArray(d, cJSON_CreateNumber(k));
    } else {
        cJSON_AddStringToObject(o, "type", "sensor");
        mac_to_str(r->src, mac);
        cJSON_AddStringToObject(o, "src", mac);
        cJSON_AddStringToObject(o, "metric", r->metric == METRIC_TEMP ? "temp" : "light");
        cJSON_AddStringToObject(o, "op", r->op == OP_GT ? ">" : "<");
        cJSON_AddNumberToObject(o, "value", round(r->value * 100.0) / 100.0);
        cJSON_AddNumberToObject(o, "hyst",  round(r->hyst * 100.0) / 100.0);
        cJSON_AddBoolToObject(o, "revert", r->revert);
        if (r->win_from >= 0) {
            snprintf(hm, sizeof(hm), "%02d:%02d", r->win_from / 60, r->win_from % 60);
            cJSON_AddStringToObject(o, "from", hm);
            snprintf(hm, sizeof(hm), "%02d:%02d", r->win_to / 60, r->win_to % 60);
            cJSON_AddStringToObject(o, "to", hm);
        }
    }
    return o;
}

// Publish retained home/esp/rule/<id> (slot trống -> payload rỗng để xóa retained cũ). Gọi khi đang giữ s_rules_mux.
static void publish_rule(int id) {
    char topic[40];
    snprintf(topic, sizeof(topic), "home/esp/rule/%d", id);
    if (!s_rules[id].used) { mqtt_pub_r(topic, "", 1); return; }
    cJSON *o = rule_to_json(id);
    char *str = cJSON_PrintUnformatted(o);
    if (str) { mqtt_pub_r(topic, str, 1); cJSON_free(str); }
    cJSON_Delete(o);
}

static void publish_all_rules(void) {
    xSemaphoreTake(s_rules_mux, portMAX_DELAY);
    for (int i = 0; i < MAX_RULES; i++) publish_rule(i);
    xSemaphoreGive(s_rules_mux);
}

// home/esp/rule/<id>/set : JSON = tạo/sửa luật, payload rỗng = xóa luật
static void handle_rule_set(int id, const char *data, int dl) {
    if (id < 0 || id >= MAX_RULES) { ESP_LOGW(TAG, "Rule id ngoai 0..%d", MAX_RULES - 1); return; }

    rule_t r;
    bool del = (dl == 0);
    if (!del) {
        cJSON *j = cJSON_ParseWithLength(data, dl);
        bool ok = j && parse_rule(j, &r);
        cJSON_Delete(j);
        if (!ok) { ESP_LOGW(TAG, "Rule %d khong hop le", id); return; }
    }

    xSemaphoreTake(s_rules_mux, portMAX_DELAY);
    if (del) memset(&s_rules[id], 0, sizeof(s_rules[id]));
    else     s_rules[id] = r;
    s_rt[id].active   = false;
    s_rt[id].last_key = -1;
    rules_save();
    publish_rule(id);
    xSemaphoreGive(s_rules_mux);
    ESP_LOGI(TAG, "Rule %d %s", id, del ? "da xoa" : "da luu");
}

static bool in_window(const rule_t *r, int m) {
    if (r->win_from < 0) return true;
    if (r->win_from <= r->win_to) return m >= r->win_from && m < r->win_to;
    return m >= r->win_from || m < r->win_to;       // khung qua nửa đêm, ví dụ 18:00 -> 06:00
}

static void rule_fire(int id, const uint8_t *target, bool on) {
    char mac[13], payload[96];
    mac_to_str(target, mac);
    esp_err_t e = request_relay(target, on);
    ESP_LOGI(TAG, "Rule %d -> %s %s (%s)", id, mac, on ? "ON" : "OFF", esp_err_to_name(e));
    snprintf(payload, sizeof(payload), "{\"rule\": %d, \"target\": \"%s\", \"action\": \"%s\", \"ok\": %s}",
             id, mac, on ? "on" : "off", e == ESP_OK ? "true" : "false");
    mqtt_pub("home/esp/automation/event", payload);
}

static void automation_task(void *arg) {
    int memory_log_counter = 0;
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));

        if (++memory_log_counter >= 60) {
            memory_log_counter = 0;
            log_memory_usage();
        }

        bool tv = time_valid();
        struct tm tm = {0};
        int now_min = 0, key = -1;
        if (tv) {
            time_t t;
            time(&t);
            localtime_r(&t, &tm);
            now_min = tm.tm_hour * 60 + tm.tm_min;
            key     = tm.tm_yday * 1440 + now_min;
        }
        uint32_t now = now_ms();

        xSemaphoreTake(s_rules_mux, portMAX_DELAY);
        for (int i = 0; i < MAX_RULES; i++) {
            rule_t *r = &s_rules[i];
            rule_rt_t *rt = &s_rt[i];
            if (!r->used || !r->enabled) continue;

            if (r->type == RULE_TIME) {
                // chạy đúng 1 lần ở mỗi phút khớp
                if (!tv || key == rt->last_key) continue;
                if (now_min == r->at_min && (r->days & (1 << tm.tm_wday))) {
                    rt->last_key = key;
                    rule_fire(i, r->target, r->action);
                }
            } else {
                node_t *s = node_find(r->src, false);
                if (!s || (now - s->last_ms) > SENSOR_STALE_MS) continue;   // dữ liệu cũ -> không đánh giá
                if (r->win_from >= 0 && !tv) continue;

                float v    = (r->metric == METRIC_TEMP) ? s->temp : s->lux;
                bool  trig = (r->op == OP_GT) ? (v > r->value) : (v < r->value);
                bool  rel  = (r->op == OP_GT) ? (v < r->value - r->hyst) : (v > r->value + r->hyst);
                bool  win  = in_window(r, now_min);
                bool  next = rt->active ? !(rel || !win) : (trig && win);

                if (next != rt->active) {          // chỉ hành động khi CHUYỂN trạng thái
                    rt->active = next;
                    if (next)              rule_fire(i, r->target, r->action);
                    else if (r->revert)    rule_fire(i, r->target, !r->action);
                }
            }
        }
        xSemaphoreGive(s_rules_mux);

        reconcile_nodes();
    }
}

/* ======================================================================
 *  Nhận dữ liệu từ node: ESP-NOW + UDP -> cùng một queue
 * ====================================================================== */
typedef struct {
    bool     is_udp;
    uint8_t  from_mac[6];          // ESP-NOW: MAC người gửi trực tiếp
    struct sockaddr_in from;       // UDP: địa chỉ người gửi trực tiếp
    uint8_t  data[sizeof(pkt_t)];
} rx_item_t;

static QueueHandle_t s_rx_q;

static void espnow_recv_cb(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
    if (len != (int)sizeof(pkt_t)) return;
    rx_item_t it = {0};
    it.is_udp = false;
    memcpy(it.from_mac, info->src_addr, 6);
    memcpy(it.data, data, len);
    xQueueSend(s_rx_q, &it, 0);
}

static void udp_rx_task(void *arg) {
    s_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    struct sockaddr_in me = {0};
    me.sin_family      = AF_INET;
    me.sin_port        = htons(UDP_PORT);
    me.sin_addr.s_addr = htonl(INADDR_ANY);
    if (s_sock < 0 || bind(s_sock, (struct sockaddr *)&me, sizeof(me)) < 0) {
        ESP_LOGE(TAG, "UDP bind that bai");
        s_sock = -1;
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG, "UDP listen :%d", UDP_PORT);

    uint8_t buf[128];
    while (1) {
        rx_item_t it = {0};
        socklen_t sl = sizeof(it.from);
        int n = recvfrom(s_sock, buf, sizeof(buf), 0, (struct sockaddr *)&it.from, &sl);
        if (n != (int)sizeof(pkt_t)) continue;
        it.is_udp = true;
        memcpy(it.data, buf, n);
        xQueueSend(s_rx_q, &it, 0);
    }
}

static void publish_alert(const char *id, const char *name, const char *ev, const pkt_t *p) {
    char topic[64];
    snprintf(topic, sizeof(topic), "home/node/%s/alert", id);
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "event",  ev);
    cJSON_AddStringToObject(o, "node",   id);
    cJSON_AddStringToObject(o, "name",   name);
    cJSON_AddNumberToObject(o, "temp",   round(p->temp * 10.0) / 10.0);
    cJSON_AddNumberToObject(o, "warn_c", p->warn_c);
    cJSON_AddNumberToObject(o, "cut_c",  p->cut_c);
    char *str = cJSON_PrintUnformatted(o);
    if (str) {
        mqtt_pub(topic, str);
        ESP_LOGW(TAG, "[ALERT %s] %s", id, str);
        cJSON_free(str);
    }
    cJSON_Delete(o);
}

// Node báo trạng thái OTA -> đẩy lên MQTT (cũng là xác nhận node đã nhận lệnh)
static void handle_ota_status(const pkt_t *p) {
    node_t *n = node_find(p->h.src, false);
    if (n) { n->ota_pending = false; n->fw = p->fw_ver; }
    char id[13], topic[64];
    ota_node_topic(p->h.src, id, topic);
    publish_ota(topic, id, p->ota_state, p->ota_pct, p->ota_err, p->fw_ver, p->fw_new);
}

static void handle_telemetry(const rx_item_t *it, const pkt_t *p) {
    node_t *n = node_find(p->h.src, true);
    if (!n) { ESP_LOGW(TAG, "Bang node day"); return; }

    n->via_udp = it->is_udp;
    n->hops    = p->h.hops;
    n->temp    = p->temp;
    n->lux     = p->lux;
    n->relay   = p->relay;
    n->warn_c  = p->warn_c;
    n->cut_c   = p->cut_c;
    n->last_ms = now_ms();
    n->fw      = p->fw_ver;
    if (it->is_udp) {
        n->addr = it->from;
        n->addr.sin_port = htons(UDP_PORT);
        // ACK để node biết đường Wi-Fi tới master còn sống
        pkt_t ack = {0};
        ack.h.magic = PROTO_MAGIC;
        ack.h.type  = MSG_ACK;
        memcpy(ack.h.src, s_my_mac, 6);
        memcpy(ack.h.dst, p->h.src, 6);
        sendto(s_sock, &ack, sizeof(ack), 0, (const struct sockaddr *)&it->from, sizeof(it->from));
    } else {
        memcpy(n->next_mac, it->from_mac, 6);
    }

    char id[13], topic[64];
    mac_to_str(p->h.src, id);
    snprintf(topic, sizeof(topic), "home/node/%s/telemetry", id);

    // via : gói này đến master bằng đường nào | link/rssi : đường lên của chính node gốc
    const char *via  = (p->h.hops > 0) ? "relay" : (it->is_udp ? "wifi" : "espnow");
    const char *link = p->link == LINK_WIFI ? "wifi" : (p->link == LINK_ESPNOW ? "espnow" : "none");

    char nm[NAME_LEN];
    memcpy(nm, p->name, NAME_LEN);
    nm[NAME_LEN - 1] = 0;

    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "temp",   round(p->temp * 100.0) / 100.0);
    cJSON_AddNumberToObject(o, "light",  round(p->lux * 10.0) / 10.0);
    cJSON_AddNumberToObject(o, "relay",  p->relay);
    cJSON_AddNumberToObject(o, "hops",   p->h.hops);
    cJSON_AddStringToObject(o, "via",    via);
    cJSON_AddStringToObject(o, "link",   link);
    cJSON_AddNumberToObject(o, "rssi",   p->rssi);
    cJSON_AddBoolToObject  (o, "is_new", (p->flags & FLAG_NEW) != 0);
    cJSON_AddStringToObject(o, "name",   nm);
    cJSON_AddStringToObject(o, "area",   p->area  < N_AREAS ? AREAS[p->area]  : "unassigned");
    cJSON_AddStringToObject(o, "type",   p->dtype < N_TYPES ? TYPES[p->dtype] : "unassigned");
    cJSON_AddNumberToObject(o, "fw", p->fw_ver);
    cJSON *sf = cJSON_AddObjectToObject(o, "safety");
    cJSON_AddNumberToObject(sf, "warn_c",  p->warn_c);
    cJSON_AddNumberToObject(sf, "cut_c",   p->cut_c);
    cJSON_AddBoolToObject  (sf, "warn",    (p->flags & FLAG_OT_WARN) != 0);
    cJSON_AddBoolToObject  (sf, "tripped", (p->flags & FLAG_OT_TRIP) != 0);

    char *payload = cJSON_PrintUnformatted(o);
    if (payload) {
        mqtt_pub(topic, payload);
        ESP_LOGI(TAG, "[NODE %s] %s", id, payload);
        cJSON_free(payload);
    }
    cJSON_Delete(o);

    // Phát sự kiện cảnh báo khi trạng thái quá nhiệt của node thay đổi
    uint8_t prev = n->flags, cur = p->flags;
    n->flags = cur;
    const char *ev = NULL;
    if      ((cur & FLAG_OT_TRIP) && !(prev & FLAG_OT_TRIP)) ev = "overtemp_trip";   // đã ngắt relay
    else if (!(cur & FLAG_OT_TRIP) && (prev & FLAG_OT_TRIP)) ev = "trip_reset";      // đã mở khóa
    else if ((cur & FLAG_OT_WARN) && !(prev & FLAG_OT_WARN)) ev = "overtemp_warn";   // vượt ngưỡng cảnh báo
    else if (!(cur & FLAG_OT_WARN) && (prev & FLAG_OT_WARN)) ev = "overtemp_ok";     // hạ nhiệt
    if (ev) publish_alert(id, nm, ev, p);
}

static void master_rx_task(void *arg) {
    rx_item_t it;
    while (xQueueReceive(s_rx_q, &it, portMAX_DELAY)) {
        const pkt_t *p = (const pkt_t *)it.data;
        if (p->h.magic != PROTO_MAGIC) continue;
        if (p->h.type == MSG_TELEMETRY)        handle_telemetry(&it, p);
        else if (p->h.type == MSG_OTA_STATUS)  handle_ota_status(p);
    }
}

// Master phát beacon để các node biết đường về master (hops = 0)
static void beacon_task(void *arg) {
    uint16_t seq = 0;
    while (1) {
        pkt_t b = {0};
        b.h.magic = PROTO_MAGIC;
        b.h.type  = MSG_BEACON;
        b.h.ttl   = 1;
        b.h.hops  = 0;
        b.h.seq   = seq++;
        memcpy(b.h.src, s_my_mac, 6);
        esp_now_send(BCAST, (const uint8_t *)&b, sizeof(b));
        vTaskDelay(pdMS_TO_TICKS(BEACON_PERIOD_MS));
    }
}

static void espnow_start(void) {
    esp_read_mac(s_my_mac, ESP_MAC_WIFI_STA);
    esp_wifi_set_ps(WIFI_PS_NONE);

    s_rx_q = xQueueCreate(16, sizeof(rx_item_t));
    ESP_ERROR_CHECK(esp_now_init());
    ESP_ERROR_CHECK(esp_now_register_recv_cb(espnow_recv_cb));
    ensure_peer(BCAST);

    xTaskCreate(master_rx_task, "master_rx", 4096, NULL, 5, NULL);
    xTaskCreate(udp_rx_task,    "udp_rx",    4096, NULL, 5, NULL);
    xTaskCreate(beacon_task,    "beacon",    2048, NULL, 4, NULL);
}

/* ======================================================================
 *  BLE: quét node chưa cấu hình rồi nạp cấu hình Wi-Fi vào node
 * ====================================================================== */
static const ble_uuid128_t CHR_UUID = BLE_UUID128_INIT(
    0x01, 0xa0, 0x00, 0x1a, 0x5d, 0x7e, 0x53, 0x9a,
    0x6f, 0x4b, 0x0e, 0x4c, 0x02, 0x00, 0x1d, 0x5a);

#define MAX_FOUND 8
static ble_addr_t        s_found[MAX_FOUND];
static int               s_found_n;
static uint8_t           s_own_type;
static uint16_t          s_conn = BLE_HS_CONN_HANDLE_NONE;
static uint16_t          s_chr_handle;
static int               s_result;
static prov_blob_t       s_blob;
static volatile bool     s_scanning = false;
static SemaphoreHandle_t s_sync_sem, s_scan_done_sem, s_step_sem, s_disc_sem;

static void ble_on_sync(void) {
    ble_hs_util_ensure_addr(0);
    ble_hs_id_infer_auto(0, &s_own_type);
    xSemaphoreGive(s_sync_sem);
}

static void ble_host_task(void *param) {
    nimble_port_run();
    nimble_port_freertos_deinit();
}

static int gap_scan_cb(struct ble_gap_event *ev, void *arg) {
    switch (ev->type) {
    case BLE_GAP_EVENT_DISC: {
        struct ble_hs_adv_fields f;
        if (ble_hs_adv_parse_fields(&f, ev->disc.data, ev->disc.length_data) != 0) break;
        size_t pl = strlen(BLE_NAME_PREFIX);
        if (f.name && f.name_len >= pl && memcmp(f.name, BLE_NAME_PREFIX, pl) == 0) {
            for (int i = 0; i < s_found_n; i++)
                if (memcmp(s_found[i].val, ev->disc.addr.val, 6) == 0) return 0;
            if (s_found_n < MAX_FOUND) {
                s_found[s_found_n++] = ev->disc.addr;
                ESP_LOGI(TAG, "BLE tim thay node %.*s", f.name_len, f.name);
            }
        }
        break;
    }
    case BLE_GAP_EVENT_DISC_COMPLETE:
        xSemaphoreGive(s_scan_done_sem);
        break;
    default: break;
    }
    return 0;
}

static int gap_conn_cb(struct ble_gap_event *ev, void *arg) {
    switch (ev->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (ev->connect.status == 0) { s_conn = ev->connect.conn_handle; s_result = 0; }
        else                         { s_conn = BLE_HS_CONN_HANDLE_NONE;  s_result = -1; }
        xSemaphoreGive(s_step_sem);
        break;
    case BLE_GAP_EVENT_DISCONNECT:
        s_conn = BLE_HS_CONN_HANDLE_NONE;
        xSemaphoreGive(s_disc_sem);
        break;
    default: break;
    }
    return 0;
}

static int disc_chr_cb(uint16_t conn, const struct ble_gatt_error *err,
                       const struct ble_gatt_chr *chr, void *arg) {
    if (err->status == 0) { s_chr_handle = chr->val_handle; return 0; }
    xSemaphoreGive(s_step_sem);
    return 0;
}

static int write_cb(uint16_t conn, const struct ble_gatt_error *err,
                    struct ble_gatt_attr *attr, void *arg) {
    s_result = err->status;
    xSemaphoreGive(s_step_sem);
    return 0;
}

static bool wait_step(int ms) { return xSemaphoreTake(s_step_sem, pdMS_TO_TICKS(ms)) == pdTRUE; }

static int provision_one(const ble_addr_t *addr) {
    int ret = -1;
    xSemaphoreTake(s_step_sem, 0);
    xSemaphoreTake(s_disc_sem, 0);

    s_result = -1;
    if (ble_gap_connect(s_own_type, addr, 5000, NULL, gap_conn_cb, NULL) != 0) return -1;
    if (!wait_step(6000) || s_result != 0) { ble_gap_conn_cancel(); return -1; }

    s_chr_handle = 0;
    if (ble_gattc_disc_chrs_by_uuid(s_conn, 1, 0xFFFF, &CHR_UUID.u, disc_chr_cb, NULL) == 0) {
        wait_step(5000);
    }

    if (s_chr_handle) {
        struct os_mbuf *om = ble_hs_mbuf_from_flat(&s_blob, sizeof(s_blob));
        s_result = -1;
        if (om && ble_gattc_write_long(s_conn, s_chr_handle, 0, om, write_cb, NULL) == 0) {
            if (wait_step(8000) && s_result == 0) ret = 0;
        }
    }

    if (s_conn != BLE_HS_CONN_HANDLE_NONE) {
        ble_gap_terminate(s_conn, BLE_ERR_REM_USER_CONN_TERM);
        xSemaphoreTake(s_disc_sem, pdMS_TO_TICKS(3000));
    }
    ESP_LOGI(TAG, "Provision node: %s", ret == 0 ? "OK" : "FAIL");
    return ret;
}

static void build_blob(prov_blob_t *b) {
    memset(b, 0, sizeof(*b));
    b->magic = PROV_MAGIC;
    strlcpy(b->ssid, WIFI_SSID, sizeof(b->ssid));
    strlcpy(b->pass, WIFI_PASS, sizeof(b->pass));
    wifi_ap_record_t ap;
    if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) b->channel = ap.primary;
    esp_read_mac(b->master_mac, ESP_MAC_WIFI_STA);
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t ip;
    if (netif && esp_netif_get_ip_info(netif, &ip) == ESP_OK) b->master_ip = ip.ip.addr;
}

static void publish_scan_status(const char *status, int found, int ok) {
    char payload[96];
    snprintf(payload, sizeof(payload),
             "{\"status\": \"%s\", \"found\": %d, \"provisioned\": %d}", status, found, ok);
    mqtt_pub(TOPIC_SCAN_RESULT, payload);
}

static void scan_task(void *arg) {
    int ok = 0;
    s_found_n = 0;
    build_blob(&s_blob);
    publish_scan_status("scanning", 0, 0);
    xSemaphoreTake(s_sync_sem, 0);
    xSemaphoreTake(s_scan_done_sem, 0);

    if (nimble_port_init() == ESP_OK) {
        ble_hs_cfg.sync_cb = ble_on_sync;
        nimble_port_freertos_init(ble_host_task);

        if (xSemaphoreTake(s_sync_sem, pdMS_TO_TICKS(5000)) == pdTRUE) {
            struct ble_gap_disc_params dp = {0};
            dp.passive = 1;
            dp.filter_duplicates = 1;
            if (ble_gap_disc(s_own_type, BLE_SCAN_MS, &dp, gap_scan_cb, NULL) == 0) {
                xSemaphoreTake(s_scan_done_sem, pdMS_TO_TICKS(BLE_SCAN_MS + 2000));
                ESP_LOGI(TAG, "BLE quet xong: %d node", s_found_n);
                for (int i = 0; i < s_found_n; i++)
                    if (provision_one(&s_found[i]) == 0) ok++;
            }
        }
        nimble_port_stop();
        nimble_port_deinit();
    } else {
        ESP_LOGE(TAG, "Khong bat duoc BLE");
    }

    publish_scan_status("done", s_found_n, ok);
    s_scanning = false;
    vTaskDelete(NULL);
}

static void start_scan(void) {
    if (s_scanning) { ESP_LOGW(TAG, "Dang quet roi"); return; }
    s_scanning = true;
    if (xTaskCreate(scan_task, "ble_scan", 8192, NULL, 5, NULL) != pdPASS) s_scanning = false;
}

/* ======================================================================
 *  MQTT
 * ====================================================================== */
static void handle_mqtt_message(const char *topic, int tl, const char *data, int dl) {
    // --- home/esp/command ---
    if (bytes_is(topic, tl, TOPIC_COMMAND)) {
        if (bytes_is(data, dl, "scan") || bytes_is(data, dl, "SCAN")) {
            ESP_LOGI(TAG, "Lenh SCAN -> bat BLE");
            start_scan();
        }
        return;
    }
    // --- home/esp/ota/cmd ---
    if (bytes_is(topic, tl, TOPIC_OTA_CMD)) {
        handle_ota_cmd(data, dl);
        return;
    }
    // --- home/esp/rule/<id>/set ---
    if (tl > 14 + 4 && memcmp(topic, "home/esp/rule/", 14) == 0 && memcmp(topic + tl - 4, "/set", 4) == 0) {
        int idl = tl - 14 - 4;
        if (idl >= 1 && idl <= 2) {
            char num[3] = {0};
            memcpy(num, topic + 14, idl);
            char *end;
            long id = strtol(num, &end, 10);
            if (*end == 0) handle_rule_set((int)id, data, dl);
        }
        return;
    }
    // --- home/node/<MAC12>/<set|config|safety> ---
    if (tl > 23 && memcmp(topic, "home/node/", 10) == 0 && topic[22] == '/') {
        char hex[13];
        memcpy(hex, topic + 10, 12);
        hex[12] = 0;
        uint8_t mac[6];
        if (!parse_mac_hex(hex, mac)) return;
        const char *verb = topic + 23;
        int vl = tl - 23;

        if (bytes_is(verb, vl, "set")) {
            bool on;
            if (bytes_is(data, dl, "ON"))       on = true;
            else if (bytes_is(data, dl, "OFF")) on = false;
            else return;
            esp_err_t e = send_relay_cmd(mac, on);
            ESP_LOGI(TAG, "Relay %s -> %s (%s)", hex, on ? "ON" : "OFF", esp_err_to_name(e));
        } else if (bytes_is(verb, vl, "config")) {
            handle_config(mac, data, dl);
        } else if (bytes_is(verb, vl, "safety")) {
            handle_safety(mac, data, dl);
        }
    }
}

static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data) {
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;

    switch ((esp_mqtt_event_id_t)event_id) {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "MQTT Connected to Broker via WSS!");
        s_mqtt_connected = true;
        esp_mqtt_client_subscribe(s_mqtt_client, TOPIC_COMMAND, 0);
        esp_mqtt_client_subscribe(s_mqtt_client, TOPIC_NODE_SET, 0);
        esp_mqtt_client_subscribe(s_mqtt_client, TOPIC_NODE_CFG, 0);
        esp_mqtt_client_subscribe(s_mqtt_client, TOPIC_NODE_SAFETY, 0);
        esp_mqtt_client_subscribe(s_mqtt_client, TOPIC_RULE_SET, 0);
        publish_all_rules();                       // đồng bộ lại danh sách luật (retained) cho app
        esp_mqtt_client_subscribe(s_mqtt_client, TOPIC_OTA_CMD, 0);
        {
            char info[32];
            snprintf(info, sizeof(info), "{\"fw\": %d}", FW_VERSION);
            mqtt_pub_r("home/esp/info", info, 1);
        }
#ifdef CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE
        esp_ota_mark_app_valid_cancel_rollback();  // firmware mới đã lên Wi-Fi + MQTT -> xác nhận hợp lệ
#endif
        break;

    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGW(TAG, "MQTT Disconnected!");
        s_mqtt_connected = false;
        break;

    case MQTT_EVENT_DATA:
        if (event->current_data_offset != 0 || event->data_len != event->total_data_len) {
            ESP_LOGW(TAG, "MQTT payload bi chia manh (>buffer), bo qua");
            break;
        }
        ESP_LOGI(TAG, "[MQTT RX] %.*s = %.*s", event->topic_len, event->topic, event->data_len, event->data);
        handle_mqtt_message(event->topic, event->topic_len, event->data, event->data_len);
        break;

    case MQTT_EVENT_ERROR:
        ESP_LOGE(TAG, "MQTT_EVENT_ERROR, error_type=%d", event->error_handle->error_type);
        break;

    default:
        break;
    }
}

static void mqtt_app_start(void) {
    const esp_mqtt_client_config_t mqtt_cfg = {
        .broker = {
            .address = { .uri = MQTT_BROKER_URI },
            .verification = { .crt_bundle_attach = esp_crt_bundle_attach },
        },
        .credentials = {
            .username = MQTT_USERNAME,
            .authentication = { .password = MQTT_PASSWORD },
        },
    };

    s_mqtt_client = esp_mqtt_client_init(&mqtt_cfg);
    esp_mqtt_client_register_event(s_mqtt_client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    esp_mqtt_client_start(s_mqtt_client);
}

/* ======================================================================
 *  Wi-Fi
 * ====================================================================== */
static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGW(TAG, "WiFi disconnect, dang thu lai...");
        esp_wifi_connect();
        xEventGroupClearBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init_sta(void) {
    s_wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdFALSE, portMAX_DELAY);
}

void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    s_rules_mux     = xSemaphoreCreateMutex();
    rules_load();
    s_sync_sem      = xSemaphoreCreateBinary();
    s_scan_done_sem = xSemaphoreCreateBinary();
    s_step_sem      = xSemaphoreCreateBinary();
    s_disc_sem      = xSemaphoreCreateBinary();

    ESP_LOGI(TAG, "Khoi dong WiFi...");
    wifi_init_sta();

    ESP_LOGI(TAG, "Khoi dong ESP-NOW + UDP...");
    espnow_start();

    ESP_LOGI(TAG, "Khoi dong NTP + tu dong hoa...");
    time_start();
    xTaskCreate(automation_task, "automation", 4096, NULL, 4, NULL);

    ESP_LOGI(TAG, "Khoi dong MQTT Client WSS...");
    mqtt_app_start();
    log_memory_usage();
}