/**
 * RPiPlay - An open-source AirPlay mirroring server for Raspberry Pi
 * Copyright (C) 2019 Florian Draschbacher
 *
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
#include <array>
#include <cassert>
#include <csignal>
#include <cstddef>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>

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

// ──────────────────────────────────────────────────────────────
// Build‑time defaults (unchanged)
// ──────────────────────────────────────────────────────────────
#define DEFAULT_NAME "RPiPlay"
#define DEFAULT_BACKGROUND_MODE BACKGROUND_MODE_ON
#define DEFAULT_AUDIO_DEVICE  AUDIO_DEVICE_HDMI
#define DEFAULT_LOW_LATENCY   false
#define DEFAULT_DEBUG_LOG     false
#define DEFAULT_ROTATE        0
#define DEFAULT_FLIP          FLIP_NONE
#define DEFAULT_HW_ADDRESS    { (char)0x48, (char)0x5d, (char)0x60, (char)0x7c, (char)0xee, (char)0x22 }

// ──────────────────────────────────────────────────────────────
// Forward declarations
// ──────────────────────────────────────────────────────────────
int start_server(const std::vector<char>& hw_addr,
                 const std::string&       name,
                 bool                     debug_log,
                 const video_renderer_config_t* video_config,
                 const audio_renderer_config_t* audio_config);
int stop_server();

using video_init_func_t = video_renderer_t* (*)(logger_t*, const video_renderer_config_t*);
using audio_init_func_t = audio_renderer_t* (*)(logger_t*, video_renderer_t*, const audio_renderer_config_t*);

struct video_renderer_list_entry_t {
    const char*        name;
    const char*        description;
    video_init_func_t  init_func;
};
struct audio_renderer_list_entry_t {
    const char*        name;
    const char*        description;
    audio_init_func_t  init_func;
};

// ──────────────────────────────────────────────────────────────
// Globals (kept for C callback compatibility)
// ──────────────────────────────────────────────────────────────
static volatile sig_atomic_t running = 0;               // set asynchronously from signal handler
static dnssd_t*              dnssd          = nullptr;
static raop_t*               raop           = nullptr;
static video_init_func_t     video_init     = nullptr;
static audio_init_func_t     audio_init     = nullptr;
static video_renderer_t*     video_renderer = nullptr;
static audio_renderer_t*     audio_renderer = nullptr;
static logger_t*             render_logger  = nullptr;

// ──────────────────────────────────────────────────────────────
// Renderer tables – first entry is the preferred default
// ──────────────────────────────────────────────────────────────
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

static_assert(std::size(video_renderers) > 0, "At least one video renderer must be enabled at compile time");
static_assert(std::size(audio_renderers) > 0, "At least one audio renderer must be enabled at compile time");

// ──────────────────────────────────────────────────────────────
// Signal handling – keep handlers async‑safe
// ──────────────────────────────────────────────────────────────
static void signal_handler(int sig) {
    switch (sig) {
        case SIGINT:
        case SIGTERM:
            running = 0;
            break;
    }
}
static void init_signals() {
    struct sigaction sa{};
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
}

// ──────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────
static int parse_hw_addr(const std::string& str, std::vector<char>& hw_addr) {
    hw_addr.clear();
    std::stringstream ss(str);
    std::string byte;
    while (std::getline(ss, byte, ':')) {
        if (byte.empty()) continue;
        hw_addr.push_back(static_cast<char>(std::stol(byte, nullptr, 16)));
    }
    return hw_addr.size() == 6 ? 0 : -1;
}

static std::string find_mac() {
    /* Finds the MAC address of the first active network interface */
    std::string mac_address;
    struct ifaddrs* ifap = nullptr;
    if (getifaddrs(&ifap) != 0) return mac_address; // empty

    for (auto* ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
#ifdef __linux__
        if (ifa->ifa_addr->sa_family != AF_PACKET) continue;
        auto* s = reinterpret_cast<struct sockaddr_ll*>(ifa->ifa_addr);
        if (s->sll_halen != 6) continue;
        bool any_non_zero = false;
        for (int i = 0; i < 6; ++i) if (s->sll_addr[i]) { any_non_zero = true; break; }
        if (!any_non_zero) continue;
        std::ostringstream oss;
        for (int i = 0; i < 6; ++i) {
            if (i) oss << ':';
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(s->sll_addr[i]);
        }
        mac_address = oss.str();
        break;
#else // macOS / *BSD
        if (ifa->ifa_addr->sa_family != AF_LINK) continue;
        auto* sdl = reinterpret_cast<struct sockaddr_dl*>(ifa->ifa_addr);
        if (sdl->sdl_alen != 6) continue;
        auto* ptr = reinterpret_cast<unsigned char*>(LLADDR(sdl));
        bool any_non_zero = false;
        for (int i = 0; i < 6; ++i) if (ptr[i]) { any_non_zero = true; break; }
        if (!any_non_zero) continue;
        std::ostringstream oss;
        for (int i = 0; i < 6; ++i) {
            if (i) oss << ':';
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ptr[i]);
        }
        mac_address = oss.str();
        break;
#endif
    }
    freeifaddrs(ifap);
    return mac_address;
}

static video_init_func_t find_video_init_func(const char* name) {
    for (const auto& vr : video_renderers) {
        if (!strcmp(name, vr.name)) return vr.init_func;
    }
    return nullptr;
}
static audio_init_func_t find_audio_init_func(const char* name) {
    for (const auto& ar : audio_renderers) {
        if (!strcmp(name, ar.name)) return ar.init_func;
    }
    return nullptr;
}

static void print_info(const char* exe) {
    printf("RPiPlay %s: An open‑source AirPlay mirroring server for Raspberry Pi\n", VERSION);
    printf("Usage: %s [-n name] [-b (on|auto|off)] [-r (90|180|270)] [-l] [-a (hdmi|analog|off)] [-vr renderer] [-ar renderer]\n", exe);
    printf("Options:\n");
    printf("-n name               Specify the network name of the AirPlay server\n");
    printf("-b (on|auto|off)      Show black background always, only during active connection, or never\n");
    printf("-r (90|180|270)       Specify image rotation in multiples of 90 degrees\n");
    printf("-f (horiz|vert|both)  Specify image flipping (horiz = horizontal, vert = vertical, both = both)\n");
    printf("-l                    Enable low‑latency mode (disables render clock)\n");
    printf("-a (hdmi|analog|off)  Set audio output device\n");
    printf("-vr renderer          Set video renderer to use. Available renderers:\n");
    for (size_t i = 0; i < std::size(video_renderers); ++i) {
        printf("    %s: %s%s\n", video_renderers[i].name, video_renderers[i].description, i == 0 ? " [Default]" : "");
    }
    printf("-ar renderer          Set audio renderer to use. Available renderers:\n");
    for (size_t i = 0; i < std::size(audio_renderers); ++i) {
        printf("    %s: %s%s\n", audio_renderers[i].name, audio_renderers[i].description, i == 0 ? " [Default]" : "");
    }
    printf("-d                    Enable debug logging\n");
    printf("-v/-h                 Displays this help and version information\n");
}

// ──────────────────────────────────────────────────────────────
// C callbacks bridging to renderers – unchanged
// ──────────────────────────────────────────────────────────────
extern "C" void conn_init(void*)                { if (video_renderer) video_renderer->funcs->update_background(video_renderer, 1); }
extern "C" void conn_destroy(void*)             { if (video_renderer) video_renderer->funcs->update_background(video_renderer, -1); }
extern "C" void audio_process(void*, raop_ntp_t* ntp, aac_decode_struct* d) {
    if (audio_renderer) audio_renderer->funcs->render_buffer(audio_renderer, ntp, d->data, d->data_len, d->pts);
}
extern "C" void video_process(void*, raop_ntp_t* ntp, h264_decode_struct* d) {
    if (video_renderer) video_renderer->funcs->render_buffer(video_renderer, ntp, d->data, d->data_len, d->pts, d->frame_type);
}
extern "C" void audio_flush(void*)             { if (audio_renderer) audio_renderer->funcs->flush(audio_renderer); }
extern "C" void video_flush(void*)             { if (video_renderer) video_renderer->funcs->flush(video_renderer); }
extern "C" void audio_set_volume(void*, float v) { if (audio_renderer) audio_renderer->funcs->set_volume(audio_renderer, v); }
extern "C" void log_callback(void*, int level, const char* msg) {
    switch (level) {
        case LOGGER_DEBUG:   LOGD("%s", msg); break;
        case LOGGER_WARNING: LOGW("%s", msg); break;
        case LOGGER_INFO:    LOGI("%s", msg); break;
        case LOGGER_ERR:     LOGE("%s", msg); break;
    }
}

// ──────────────────────────────────────────────────────────────
// Server start / stop
// ──────────────────────────────────────────────────────────────
int start_server(const std::vector<char>& hw_addr,
                 const std::string&       name,
                 bool                     debug_log,
                 const video_renderer_config_t* video_config,
                 const audio_renderer_config_t* audio_config) {
    raop_callbacks_t cbs{};
    cbs.conn_init       = conn_init;
    cbs.conn_destroy    = conn_destroy;
    cbs.audio_process   = audio_process;
    cbs.video_process   = video_process;
    cbs.audio_flush     = audio_flush;
    cbs.video_flush     = video_flush;
    cbs.audio_set_volume= audio_set_volume;

    raop = raop_init(10, &cbs);
    if (!raop) { LOGE("Error initializing raop!"); return -1; }
    raop_set_log_callback(raop, log_callback, nullptr);
    raop_set_log_level(raop, debug_log ? RAOP_LOG_DEBUG : LOGGER_INFO);

    render_logger = logger_init();
    logger_set_callback(render_logger, log_callback, nullptr);
    logger_set
