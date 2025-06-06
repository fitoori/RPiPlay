/**
 * RPiPlay - An open-source AirPlay mirroring server for Raspberry Pi
 * Copyright (C) 2019 Florian Draschbacher
 * Modified with the help of AI by github.com/fitoori
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#include <stddef.h>
#include <cstring>
#include <csignal>
#include <unistd.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <array>

#include <sys/socket.h>
#include <ifaddrs.h>
#ifdef __linux__
#include <netpacket/packet.h>
#else
#include <net/if_dl.h>   /* macOS and *BSD */
#endif

#include "log.h"
#include "lib/raop.h"
#include "lib/stream.h"
#include "lib/logger.h"
#include "lib/dnssd.h"
#include "renderers/video_renderer.h"
#include "renderers/audio_renderer.h"

#define VERSION "1.2"

#define DEFAULT_NAME "RPiPlay"
#define DEFAULT_BACKGROUND_MODE BACKGROUND_MODE_ON
#define DEFAULT_AUDIO_DEVICE AUDIO_DEVICE_HDMI
#define DEFAULT_LOW_LATENCY false
#define DEFAULT_DEBUG_LOG false
#define DEFAULT_ROTATE 0
#define DEFAULT_FLIP FLIP_NONE
#define DEFAULT_HW_ADDRESS { (char) 0x48, (char) 0x5d, (char) 0x60, (char) 0x7c, (char) 0xee, (char) 0x22 }

int start_server(std::vector<char> hw_addr, std::string name, bool debug_log,
                 video_renderer_config_t const *video_config, audio_renderer_config_t const *audio_config);

int stop_server();

typedef video_renderer_t *(*video_init_func_t)(logger_t *logger, video_renderer_config_t const *config);
typedef audio_renderer_t *(*audio_init_func_t)(logger_t *logger, video_renderer_t *video_renderer, audio_renderer_config_t const *config);

typedef struct video_renderer_list_entry_s {
    const char *name;
    const char *description;
    video_init_func_t init_func;
} video_renderer_list_entry_t;

typedef struct audio_renderer_list_entry_s {
    const char *name;
    const char *description;
    audio_init_func_t init_func;
} audio_renderer_list_entry_t;

// Using sig_atomic_t to comply with async‑signal‑safe requirements
static volatile sig_atomic_t running = 0;
static dnssd_t *dnssd = NULL;
static raop_t *raop = NULL;
static video_init_func_t video_init_func = NULL;
static audio_init_func_t audio_init_func = NULL;
static video_renderer_t *video_renderer = NULL;
static audio_renderer_t *audio_renderer = NULL;
static logger_t *render_logger = NULL;

static const video_renderer_list_entry_t video_renderers[] = {
#if defined(HAS_RPI_RENDERER)
    {"rpi", "Raspberry Pi OpenMAX accelerated H.264 renderer", video_renderer_rpi_init},
#endif
#if defined(HAS_GSTREAMER_RENDERER)
    {"gstreamer", "GStreamer H.264 renderer", video_renderer_gstreamer_init},
#endif
#if defined(HAS_DUMMY_RENDERER)
    {"dummy", "Dummy renderer; does not actually display video", video_renderer_dummy_init},
#endif
};

static const audio_renderer_list_entry_t audio_renderers[] = {
#if defined(HAS_RPI_RENDERER)
    {"rpi", "AAC renderer using fdk-aac for decoding and OpenMAX for rendering", audio_renderer_rpi_init},
#endif
#if defined(HAS_GSTREAMER_RENDERER)
    {"gstreamer", "GStreamer audio renderer", audio_renderer_gstreamer_init},
#endif
#if defined(HAS_DUMMY_RENDERER)
    {"dummy", "Dummy renderer; does not actually play audio", audio_renderer_dummy_init},
#endif
};

// Ensure at least one renderer is compiled in; gives clear build‑time error otherwise
static_assert(sizeof(video_renderers) / sizeof(video_renderers[0]) > 0, "At least one video renderer must be enabled");
static_assert(sizeof(audio_renderers) / sizeof(audio_renderers[0]) > 0, "At least one audio renderer must be enabled");

static void signal_handler(int sig) {
    switch (sig) {
        case SIGINT:
        case SIGTERM:
            running = 0;
            break;
    }
}

static void init_signals(void) {
    struct sigaction sigact{};

    sigact.sa_handler = signal_handler;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = 0;
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
}

// Accepts both colon‑delimited and raw 12‑hex‑digit MAC strings
static int parse_hw_addr(const std::string &str, std::vector<char> &hw_addr) {
    hw_addr.clear();
    size_t i = 0;
    while (i < str.length()) {
        if (str[i] == ':' || str[i] == '-' || str[i] == ' ') { // skip delimiters
            ++i;
            continue;
        }
        if (i + 1 >= str.length()) {
            return -1; // malformed
        }
        char byte_str[3] = {str[i], str[i + 1], '\0'};
        hw_addr.push_back(static_cast<char>(strtol(byte_str, NULL, 16)));
        i += 2;
    }
    return hw_addr.size() == 6 ? 0 : -1;
}

static std::string find_mac () {
/*  finds the MAC address of the first active network interface *
 *  in a Linux, *BSD or macOS system.                           */
    std::string mac_address;
    struct ifaddrs *ifap = nullptr, *ifaptr = nullptr;
    if (getifaddrs(&ifap) != 0) {
        return mac_address; // empty
    }

    for(ifaptr = ifap; ifaptr != NULL; ifaptr = ifaptr->ifa_next) {
        if(ifaptr->ifa_addr == NULL) continue;
        int non_null_octets = 0; // reset for every interface
        unsigned char octet[6] = {0};
#ifdef __linux__
        if (ifaptr->ifa_addr->sa_family != AF_PACKET) continue;
        struct sockaddr_ll *s = (struct sockaddr_ll*) ifaptr->ifa_addr;
        for (int i = 0; i < 6; i++) {
            if ((octet[i] = s->sll_addr[i]) != 0) non_null_octets++;
        }
#else    /* macOS and *BSD */
        if (ifaptr->ifa_addr->sa_family != AF_LINK) continue;
        unsigned char *ptr = (unsigned char *) LLADDR((struct sockaddr_dl *) ifaptr->ifa_addr);
        for (int i = 0; i < 6 ; i++) {
            if ((octet[i] = ptr[i]) != 0) non_null_octets++;
        }
#endif
        if (non_null_octets) {
            std::ostringstream oss;
            for (int i = 0; i < 6 ; i++) {
                oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(octet[i]);
                if (i < 5) oss << ":";
            }
            mac_address = oss.str();
            break;
        }
    }

    freeifaddrs(ifap);
    return mac_address;
}

static video_init_func_t find_video_init_func(const char *name) {
    for (size_t i = 0; i < sizeof(video_renderers)/sizeof(video_renderers[0]); i++) {
        if (!strcmp(name, video_renderers[i].name)) {
            return video_renderers[i].init_func;
        }
    }
    return NULL;
}

static audio_init_func_t find_audio_init_func(const char *name) {
    for (size_t i = 0; i < sizeof(audio_renderers)/sizeof(audio_renderers[0]); i++) {
        if (!strcmp(name, audio_renderers[i].name)) {
            return audio_renderers[i].init_func;
        }
    }
    return NULL;
}

void print_info(char *name) {
    printf("RPiPlay %s: An open-source AirPlay mirroring server for Raspberry Pi\n", VERSION);
    printf("Usage: %s [-n name] [-b (on|auto|off)] [-r (90|180|270)] [-l] [-a (hdmi|analog|off)] [-vr renderer] [-ar renderer]\n", name);
    printf("Options:\n");
    printf("-n name               Specify the network name of the AirPlay server\n");
    printf("-b (on|auto|off)      Show black background always, only during active connection, or never\n");
    printf("-r (90|180|270)       Specify image rotation in multiples of 90 degrees\n");
    printf("-f (horiz|vert|both)  Specify image flipping (horiz = horizontal, vert = vertical, both = both)\n");
    printf("-l                    Enable low-latency mode (disables render clock)\n");
    printf("-a (hdmi|analog|off)  Set audio output device\n");
    printf("-vr renderer          Set video renderer to use. Available renderers:\n");
    for (size_t i = 0; i < sizeof(video_renderers)/sizeof(video_renderers[0]); i++) {
        printf("    %s: %s%s\n", video_renderers[i].name, video_renderers[i].description, i == 0 ? " [Default]" : "");
    }
    printf("-ar renderer          Set audio renderer to use. Available renderers:\n");
    for (size_t i = 0; i < sizeof(audio_renderers)/sizeof(audio_renderers[0]); i++) {
        printf("    %s: %s%s\n", audio_renderers[i].name, audio_renderers[i].description, i == 0 ? " [Default]" : "");
    }
    printf("-d                    Enable debug logging\n");
    printf("-v/-h                 Displays this help and version information\n");
}

int main(int argc, char *argv[]) {
    init_signals();

    std::string server_name = DEFAULT_NAME;
    std::vector<char> server_hw_addr = DEFAULT_HW_ADDRESS;
    bool debug_log = DEFAULT_DEBUG_LOG;

    video_renderer_config_t video_config{};
    video_config.background_mode = DEFAULT_BACKGROUND_MODE;
    video_config.low_latency = DEFAULT_LOW_LATENCY;
    video_config.rotation = DEFAULT_ROTATE;
    video_config.flip = DEFAULT_FLIP;

    audio_renderer_config_t audio_config{};
    audio_config.device = DEFAULT_AUDIO_DEVICE;
    audio_config.low_latency = DEFAULT_LOW_LATENCY;

    // Default to the first listed renderer (compile-time asserts guarantee at least one)
    video_init_func = video_renderers[0].init_func;
    audio_init_func = audio_renderers[0].init_func;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        std::string arg(argv[i]);
        if (arg == "-n") {
            if (i == argc - 1) continue;
            server_name = std::string(argv[++i]);
        } else if (arg == "-b") {
            // For backwards-compatibility, make just -b disable the background
            if (i == argc - 1 || argv[i + 1][0] == '-') {
                video_config.background_mode = BACKGROUND_MODE_OFF;
                continue;
            }

            std::string background_mode(argv[++i]);
            video_config.background_mode = background_mode == "off" ? BACKGROUND_MODE_OFF :
                                           background_mode == "auto" ? BACKGROUND_MODE_AUTO :
                                           BACKGROUND_MODE_ON;
        } else if (arg == "-a") {
            if (i == argc - 1) continue;
            std::string audio_device_name(argv[++i]);
            audio_config.device = audio_device_name == "hdmi" ? AUDIO_DEVICE_HDMI :
                                  audio_device_name == "analog" ? AUDIO_DEVICE_ANALOG :
                                  AUDIO_DEVICE_NONE;
        } else if (arg == "-l") {
            video_config.low_latency = !video_config.low_latency;
            audio_config.low_latency = !audio_config.low_latency;
        } else if (arg == "-r") {
            if (i == argc - 1) continue; // guard against missing value
            video_config.rotation = atoi(argv[++i]);
        } else if (arg == "-f") {
            if (i == argc - 1) continue;
            std::string flip_type(argv[++i]);
            video_config.flip = flip_type == "horiz" ? FLIP_HORIZONTAL :
                                flip_type == "vert" ? FLIP_VERTICAL :
                                flip_type == "both" ? FLIP_BOTH :
                                FLIP_NONE;
        } else if (arg == "-d") {
            debug_log = !debug_log;
        } else if (arg == "-vr") {
            if (i == argc - 1) {
                fprintf(stderr, "Error: You must supply the name of a video renderer after the -vr argument.\n");
                exit(1);
            }
            video_init_func = find_video_init_func(argv[++i]);
            if (!video_init_func) {
                fprintf(stderr, "Error: Unable to locate video renderer \"%s\".\n", argv[i]);
                exit(1);
            }
        } else if (arg == "-ar") {
            if (
