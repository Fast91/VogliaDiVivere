/**
 * Copyright (c) 2017, Łukasz Marcin Podkalicki <lpodkalicki@gmail.com>
 * ESP32/016
 * WiFi Sniffer.
 */

#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_spi_flash.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "driver/gpio.h"


#define DATA_LENGTH 112

#define TYPE_MANAGEMENT       0x00
#define TYPE_CONTROL          0x01
#define TYPE_DATA             0x02
#define SUBTYPE_PROBE_REQUEST 0x04

#define	LED_GPIO_PIN			GPIO_NUM_4
#define	WIFI_CHANNEL_MAX		(13)
#define	WIFI_CHANNEL_SWITCH_INTERVAL	(500)

void loop_task(void *pvParameter);

static wifi_country_t wifi_country = {.cc="CN", .schan=1, .nchan=13, .policy=WIFI_COUNTRY_POLICY_AUTO};

typedef struct {
	unsigned frame_ctrl:16;
	unsigned duration_id:16;
	uint8_t addr1[6]; // receiver address
	uint8_t addr2[6]; // sender address
	uint8_t addr3[6]; // filtering address
	unsigned sequence_ctrl:16;
	uint8_t addr4[6]; // optional
} wifi_ieee80211_mac_hdr_t;

typedef struct {
	wifi_ieee80211_mac_hdr_t hdr;
	uint8_t payload[0]; // network data ended with 4 bytes csum (CRC32)
} wifi_ieee80211_packet_t;

struct RxControl {
 signed rssi:8; // signal intensity of packet
 unsigned rate:4;
 unsigned is_group:1;
 unsigned:1;
 unsigned sig_mode:2; // 0:is 11n packet; 1:is not 11n packet;
 unsigned legacy_length:12; // if not 11n packet, shows length of packet.
 unsigned damatch0:1;
 unsigned damatch1:1;
 unsigned bssidmatch0:1;
 unsigned bssidmatch1:1;
 unsigned MCS:7; // if is 11n packet, shows the modulation and code used (range from 0 to 76)
 unsigned CWB:1; // if is 11n packet, shows if is HT40 packet or not
 unsigned HT_length:16;// if is 11n packet, shows length of packet.
 unsigned Smoothing:1;
 unsigned Not_Sounding:1;
 unsigned:1;
 unsigned Aggregation:1;
 unsigned STBC:2;
 unsigned FEC_CODING:1; // if is 11n packet, shows if is LDPC packet or not.
 unsigned SGI:1;
 unsigned rxend_state:8;
 unsigned ampdu_cnt:8;
 unsigned channel:4; //which channel this packet in.
 unsigned:12;
};

struct SnifferPacket{
    struct RxControl rx_ctrl;
    uint8_t data[DATA_LENGTH];
    uint16_t cnt;
    uint16_t len;
};

static esp_err_t event_handler(void *ctx, system_event_t *event);
static void wifi_sniffer_init(void);
static void wifi_sniffer_set_channel(uint8_t channel);
static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);
static int showMetadata(struct SnifferPacket *snifferPacket);
static void getMAC(char *addr, uint8_t* data, uint16_t offset);
static void showOtherData(void * buff, wifi_promiscuous_pkt_type_t type);
//static void printDataSpan(uint16_t start, uint16_t size, uint8_t* data);

static void getMAC(char *addr, uint8_t* data, uint16_t offset) {
  sprintf(addr, "%02x:%02x:%02x:%02x:%02x:%02x", data[offset+0], data[offset+1], data[offset+2], data[offset+3], data[offset+4], data[offset+5]);
}

/*static void printDataSpan(uint16_t start, uint16_t size, uint8_t* data) {
  for(uint16_t i = start; i < DATA_LENGTH && i < start+size; i++) {
    printf("%u", data[i]);
  }
}*/

void
app_main(void)
{
	uint8_t level = 0, channel = 1;

	// setup
	wifi_sniffer_init();
	gpio_set_direction(LED_GPIO_PIN, GPIO_MODE_OUTPUT);

	// loop
	while (true) {
		gpio_set_level(LED_GPIO_PIN, level ^= 1);
		vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL / portTICK_PERIOD_MS);
		wifi_sniffer_set_channel(channel);
		channel = (channel % WIFI_CHANNEL_MAX) + 1;
    	}
	/*printf("Start of main.\n");
	static uint8_t ucParameterToPass;
	//TaskHandle_t xHandle = NULL;
	xTaskCreate(&loop_task, "loop_task", 512, &ucParameterToPass, 0, NULL);//&xHandle);
	//configASSERT( xHandle );
	// Use the handle to delete the task.
	//if( xHandle != NULL )
	//{
	//   vTaskDelete( xHandle );
	//   printf("vTaskDelete( xHandle )\n");
	//}
	printf("End of main.\n");*/
}

/*void loop_task(void *pvParameter){
	while(1){
		printf("Hello World.\n");
		fflush(stdout);
		vTaskDelay(1000 / portTICK_PERIOD_MS);
	}
}*/

esp_err_t
event_handler(void *ctx, system_event_t *event)
{
	return ESP_OK;
}

void
wifi_sniffer_init(void)
{
	wifi_promiscuous_filter_t filter;
	filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;// & WIFI_EVENT_MASK_AP_PROBEREQRECVED;
	nvs_flash_init();
    	tcpip_adapter_init();
    	ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );
    	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
	ESP_ERROR_CHECK( esp_wifi_set_country(&wifi_country) ); // set country for channel range [1, 13]
	ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
    	ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_APSTA) ); // WIFI_MODE_NULL
    	ESP_ERROR_CHECK( esp_wifi_start() );
	esp_wifi_set_promiscuous(true);
	esp_wifi_set_promiscuous_filter(&filter);
	esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
}

void
wifi_sniffer_set_channel(uint8_t channel)
{
	esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

const char *
wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type)
{
	switch(type) {
	case WIFI_PKT_MGMT: return "MGMT";
	case WIFI_PKT_DATA: return "DATA";
	case WIFI_PKT_CTRL: return "CTRL"; // aggiunta mia
	default:	
	case WIFI_PKT_MISC: return "MISC";
	}
}

void
wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type)
{
	/*if (type != WIFI_PKT_MGMT){
		//printf("Not MGMT -> %u\n", type);
		return;
	}*/

	struct SnifferPacket *snifferPacket = (struct SnifferPacket*) buff;
	if(showMetadata(snifferPacket)){
		showOtherData(buff, type);
	}
}

static void showOtherData(void *buff, wifi_promiscuous_pkt_type_t type){
	const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
		const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
		const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;
		printf("PACKET TYPE=%s, CHAN=%02d, RSSI=%02d,"
			" ADDR1=%02x:%02x:%02x:%02x:%02x:%02x,"
			" ADDR2=%02x:%02x:%02x:%02x:%02x:%02x,"
			" ADDR3=%02x:%02x:%02x:%02x:%02x:%02x\n",
			wifi_sniffer_packet_type2str(type),
			ppkt->rx_ctrl.channel,
			ppkt->rx_ctrl.rssi,
			// ADDR1
			hdr->addr1[0],hdr->addr1[1],hdr->addr1[2],
			hdr->addr1[3],hdr->addr1[4],hdr->addr1[5],
			// ADDR2
			hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],
			hdr->addr2[3],hdr->addr2[4],hdr->addr2[5],
			// ADDR3
			hdr->addr3[0],hdr->addr3[1],hdr->addr3[2],
			hdr->addr3[3],hdr->addr3[4],hdr->addr3[5]
		);
}

static int showMetadata(struct SnifferPacket *snifferPacket) {

  unsigned int frameControl = ((unsigned int)snifferPacket->data[1] << 8) + snifferPacket->data[0];

  uint8_t version      = (frameControl & 0b0000000000000011) >> 0;
  uint8_t frameType    = (frameControl & 0b0000000000001100) >> 2;
  uint8_t frameSubType = (frameControl & 0b0000000011110000) >> 4;
  uint8_t toDS         = (frameControl & 0b0000000100000000) >> 8;
  uint8_t fromDS       = (frameControl & 0b0000001000000000) >> 9;

  // Only look for probe request packets
  if (frameType != TYPE_MANAGEMENT ||
      frameSubType != SUBTYPE_PROBE_REQUEST)
        return 0;

  printf("RSSI: ");
  printf("%d", snifferPacket->rx_ctrl.rssi);

  //printf(" Ch: ");
  //printf(wifi_get_channel());

  char addr[] = "00:00:00:00:00:00";
  getMAC(addr, snifferPacket->data, 10);
  printf(" Peer MAC: ");
  printf(addr);

  uint8_t SSID_length = snifferPacket->data[25];
  //printf(" SSID: ");
  //printDataSpan(26, SSID_length, snifferPacket->data);

  printf("\n");
  return 1;
}
