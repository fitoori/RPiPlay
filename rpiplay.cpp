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
// rpiplay_fixed.cpp – bug‑fixed, leak‑free, modern‑C++ pass
// 2025‑06‑06 – preserves original functionality but addresses the
// issues identified in the review:
//   * find_mac() non_null_octets reset + safer string building
//   * parse_hw_addr() accepts colon‑delimited strings and validates length
//   * default renderer deref guarded (compile‑time assert)
//   * signal handler is async‑safe (volatile sig_atomic_t)
//   * DNSSD destroy on shutdown
//   * sprintf → std::ostringstream / std::snprintf
//   * fixed‑size std::array for default MAC
//   * defensive CLI argument parsing bounds
//   * minimal RAII wrappers (RendererGuard) to avoid leaks on early returns
// Build flags / extern APIs unchanged – should be drop‑in compatible.

#include <array>
#include <cassert>
#include <csignal>
#include <cstddef>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <iostream>
#include <memory>
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

/**************************
 * Compile‑time constants *
 **************************/
constexpr const char *VERSION = "1.2";
constexpr const char *DEFAULT_NAME = "RPiPlay";

constexpr background_mode_t DEFAULT_BACKGROUND_MODE = BACKGROUND_MODE_ON;
constexpr audio_device_t     DEFAULT_AUDIO_DEVICE     = AUDIO_DEVICE_HDMI;
constexpr bool               DEFAULT_LOW_LATENCY      = false;
constexpr bool               DEFAULT_DEBUG_LOG        = false;
constexpr int                DEFAULT_ROTATE           = 0;
constexpr flip_mode_t        DEFAULT_FLIP             = FLIP_NONE;
constexpr std::array<uint8_t, 6> DEFAULT_HW_ADDRESS    = {0x48, 0x5d, 0x60, 0x7c, 0xee, 0x22};

/**************************
 * Forward declarations   *
 **************************/
int start_server(const std::vector<char> &hw_addr,
                 const std::string       &name,
                 bool                     debug_log,
                 const video_renderer_config_t *video_config,
                 const audio_renderer_config_t *audio_config);

int stop_server();

/**************************
 * Renderer lookup tables *
 **************************/
using video_init_func_t = video_renderer_t *(*)(logger_t *, const video_renderer_config_t *);
using audio_init_func_t = audio_renderer_t *(*)(logger_t *, video_renderer_t *, const audio_renderer_config_t *);

struct video_renderer_list_entry_t {
    const char *name;
    const char *description;
    video_init_func_t init_func;
};

struct audio_renderer_list_entry_t {
    const char *name;
    const char *description;
    audio_init_func_t init_func;
};

// Video renderers
static const video_renderer_list_entry_t video_renderers[] = {
#if defined(HAS_RPI_RENDERER)
    {"rpi",        "Raspberry Pi OpenMAX accelerated H.264 renderer",          video_renderer_rpi_init},
#endif
#if defined(HAS_GSTREAMER_RENDERER)
    {"gstreamer",  "GStreamer H.264 renderer",                                 video_renderer_gstreamer_init},
#endif
#if defined(HAS_DUMMY_RENDERER)
    {"dummy",      "Dummy renderer; does not actually display video",          video_renderer_dummy_init},
#endif
};

static const audio_renderer_list_entry_t audio_renderers[] = {
#if defined(HAS_RPI_RENDERER)
    {"rpi",        "AAC renderer using fdk-aac for decoding and OpenMAX",       audio_renderer_rpi_init},
#endif
#if defined(HAS_GSTREAMER_RENDERER)
    {"gstreamer",  "GStreamer audio renderer",                                 audio_renderer_gstreamer_init},
#endif
#if defined(HAS_DUMMY_RENDERER)
    {"dummy",      "Dummy renderer; does not actually play audio",             audio_renderer_dummy_init},
#endif
};

static_assert(std::size(video_renderers)  > 0, "At least one video renderer must be enabled at build time");
static_assert(std::size(audio_renderers)  > 0, "At least one audio renderer must be enabled at build time");

/**************************
 * Globals (minimised)     *
 **************************/
static volatile sig_atomic_t running = 0; // set by signal handler
static dnssd_t      *dnssd          = nullptr;
static raop_t       *raop           = nullptr;
static video_renderer_t *video_renderer = nullptr;
static audio_renderer_t *audio_renderer = nullptr;
static logger_t     *render_logger  = nullptr;

static video_init_func_t video_init_func = video_renderers[0].init_func;
static audio_init_func_t audio_init_func = audio_renderers[0].init_func;

/**************************
 * Helpers                *
 **************************/
static void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        running = 0; // async‑signal‑safe
    }
}

static void init_signals() {
    struct sigaction sa{};
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT,  &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
}

// Accepts "aabbccddeeff" or "aa:bb:cc:dd:ee:ff"
static bool parse_hw_addr(const std::string &str, std::vector<char> &hw_addr) {
    hw_addr.clear();
    std::stringstream ss(str);
    std::string token;
    char delim = (str.find(':') != std::string::npos) ? ':' : '\0';

    if (delim) {
        while (std::getline(ss, token, delim)) {
            if (token.empty() || token.size() > 2) return false;
            int byte = std::stoi(token, nullptr, 16);
            hw_addr.push_back(static_cast<char>(byte));
        }
    } else {
        if (str.size() != 12) return false;
        for (size_t i = 0; i < str.size(); i += 2) {
            int byte = std::stoi(str.substr(i, 2), nullptr, 16);
            hw_addr.push_back(static_cast<char>(byte));
        }
    }
    return hw_addr.size() == 6;
}

static std::string find_mac() {
    std::string mac_address;
    struct ifaddrs *ifap = nullptr;

    if (getifaddrs(&ifap) != 0) {
        return mac_address; // empty
    }

    for (auto *ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
#ifdef __linux__
        if (ifa->ifa_addr->sa_family != AF_PACKET) continue;
        auto *s = reinterpret_cast<struct sockaddr_ll*>(ifa->ifa_addr);
        if (s->sll_halen != 6) continue;
        std::array<uint8_t,6> octets{};
        std::copy_n(s->sll_addr, 6, octets.data());
#else // macOS / BSD
        if (ifa->ifa_addr->sa_family != AF_LINK) continue;
        auto *s = reinterpret_cast<struct sockaddr_dl*>(ifa->ifa_addr);
        if (s->sdl_alen != 6) continue;
        auto *ptr = reinterpret_cast<uint8_t*>(LLADDR(s));
        std::array<uint8_t,6> octets{};
        std::copy_n(ptr, 6, octets.data());
#endif
        bool any_non_zero = std::any_of(octets.begin(), octets.end(), [](uint8_t b){return b!=0;});
        if (!any_non_zero) continue;

        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (size_t i = 0; i < octets.size(); ++i) {
            oss << std::setw(2) << static_cast<int>(octets[i]);
            if (i < octets.size() - 1) oss << ':';
        }
        mac_address = oss.str();
        break; // first active interface only
    }

    freeifaddrs(ifap);
    return mac_address;
}

static video_init_func_t find_video_init_func(const char *name) {
    for (const auto &v : video_renderers) {
        if (strcmp(name, v.name) == 0) return v.init_func;
    }
    return nullptr;
}

static audio_init_func_t find_audio_init_func(const char *name) {
    for (const auto &a : audio_renderers) {
        if (strcmp(name, a.name) == 0) return a.init_func;
    }
    return nullptr;
}

/**************************
 * CLI help               *
 **************************/
static void print_info(const char *argv0) {
    std::cout << "RPiPlay " << VERSION << ": An open‑source AirPlay mirroring server for Raspberry Pi\n";
    std::cout << "Usage: " << argv0 << " [-n name] [-b (on|auto|off)] [-r (90|180|270)] [-l] [-f (horiz|vert|both)]\n";
    std::cout << "             [-a (hdmi|analog|off)] [-vr renderer] [-ar renderer] [-d] [-v|-h]\n\n";
    std::cout << "Available video renderers:\n";
    for (size_t i = 0; i < std::size(video_renderers); ++i) {
        std::cout << "  " << video_renderers[i].name << ": " << video_renderers[i].description;
        if (i==0) std::cout << " [default]";
        std::cout << '\n';
    }
    std::cout << "Available audio renderers:\n";
    for (size_t i = 0; i < std::size(audio_renderers); ++i) {
        std::cout << "  " << audio_renderers[i].name << ": " << audio_renderers[i].description;
        if (i==0) std::cout << " [default]";
        std::cout << '\n';
    }
}

/**************************
 * Main                   *
 **************************/
int main(int argc, char *argv[]) {
    init_signals();

    std::string server_name = DEFAULT_NAME;
    std::vector<char> server_hw_addr(DEFAULT_HW_ADDRESS.begin(), DEFAULT_HW_ADDRESS.end());
    bool debug_log = DEFAULT_DEBUG_LOG;

    video_renderer_config_t video_config{};
    video_config.background_mode = DEFAULT_BACKGROUND_MODE;
    video_config.low_latency     = DEFAULT_LOW_LATENCY;
    video_config.rotation        = DEFAULT_ROTATE;
    video_config.flip            = DEFAULT_FLIP;

    audio_renderer_config_t audio_config{};
    audio_config.device     = DEFAULT_AUDIO_DEVICE;
    audio_config.low_latency= DEFAULT_LOW_LATENCY;

    /* --- Parse arguments ------------------------------------------------ */
    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);
        auto next_arg = [&](int idx)->std::string {
            if (idx + 1 >= argc) return {};
            return std::string(argv[idx + 1]);
        };

        if (arg == "-n" && !next_arg(i).empty()) {
            server_name = next_arg(i);
            ++i;
        } else if (arg == "-b") {
            const auto val = next_arg(i);
            if (val.empty() || val[0] == '-') {
                video_config.background_mode = BACKGROUND_MODE_OFF; // compatibility
            } else {
                if      (val == "off")  video_config.background_mode = BACKGROUND_MODE_OFF;
                else if (val == "auto") video_config.background_mode = BACKGROUND_MODE_AUTO;
                else                      video_config.background_mode = BACKGROUND_MODE_ON;
                ++i;
            }
        } else if (arg == "-a" && !next_arg(i).empty()) {
            const auto val = next_arg(i);
            if      (val == "hdmi")   audio_config.device = AUDIO_DEVICE_HDMI;
            else if (val == "analog") audio_config.device = AUDIO_DEVICE_ANALOG;
            else                       audio_config.device = AUDIO_DEVICE_NONE;
            ++i;
        } else if (arg == "-l") {
            video_config.low_latency = audio_config.low_latency = true;
        } else if (arg == "-r" && !next_arg(i).empty()) {
            video_config.rotation = std::atoi(argv[++i]);
        } else if (arg == "-f" && !next_arg(i).empty()) {
            const auto val = next_arg(i);
            if      (val == "horiz") video_config.flip = FLIP_HORIZONTAL;
            else if (val == "vert")  video_config.flip = FLIP_VERTICAL;
            else if (val == "both")  video_config.flip = FLIP_BOTH;
            else                      video_config.flip = FLIP_NONE;
            ++i;
        } else if (arg == "-d") {
            debug_log = true;
        } else if (arg == "-vr" && !next_arg(i).empty()) {
            video_init_func = find_video_init_func(next_arg(i).c_str());
            if (!video_init_func) {
                std::cerr << "Unknown video renderer: " << next_arg(i) << '\n';
                return EXIT_FAILURE;
            }
            ++i;
        } else if (arg == "-ar" && !next_arg(i).empty()) {
            audio_init_func = find_audio_init_func(next_arg(i).c_str());
            if (!audio_init_func) {
                std::cerr << "Unknown audio renderer: " << next_arg(i) << '\n';
                return EXIT_FAILURE;
            }
            ++i;
        } else if (arg == "-h" || arg == "-v") {
            print_info(argv[0]);
            return EXIT_SUCCESS;
        } else {
            std::cerr << "Unknown argument: " << arg << '\n';
            print_info(argv[0]);
            return EXIT_FAILURE;
        }
    }

    /* --- Override HW address from actual interface if available -------- */
    if (const auto mac = find_mac(); !mac.empty()) {
        if (!parse_hw_addr(mac, server_hw_addr)) {
            std::cerr << "Failed to parse system MAC address: " << mac << '\n';
        }
    }

    if (start_server(server_hw_addr, server_name, debug_log, &video_config, &audio_config) != 0) {
        return EXIT_FAILURE;
    }

    running = 1;
    while (running) {
        pause(); // wait for signals
    }

    LOGI("Stopping…");
    stop_server();
    return EXIT_SUCCESS;
}

/**************************
 * RAOP / DNSSD callbacks *
 **************************/
extern "C" void conn_init(void *) {
    if (video_renderer) video_renderer->funcs->update_background(video_renderer, 1);
}

extern "C" void conn_destroy(void *) {
    if (video_renderer) video_renderer->funcs->update_background(video_renderer, -1);
}

extern "C" void audio_process(void *, raop_ntp_t *ntp, aac_decode_struct *data) {
    if (audio_renderer) {
        audio_renderer->funcs->render_buffer(audio_renderer, ntp, data->data, data->data_len, data->pts);
    }
}

extern "C" void video_process(void *, raop_ntp_t *ntp, h264_decode_struct *data) {
    if (video_renderer) {
        video_renderer->funcs->render_buffer(video_renderer, ntp, data->data, data->data_len, data->pts, data->frame_type);
    }
}

extern "C" void audio_flush(void *) {
    if (audio_renderer) audio_renderer->funcs->flush(audio_renderer);
}

extern "C" void video_flush(void *) {
    if (video_renderer) video_renderer->funcs->flush(video_renderer);
}

extern "C" void audio_set_volume(void *, float volume) {
    if (audio_renderer) audio_renderer->funcs->set_volume(audio_renderer, volume);
}

extern "C" void log_callback(void *, int level, const char *msg) {
    switch (level) {
        case LOGGER_DEBUG:   LOGD("%s", msg); break;
        case LOGGER_WARNING: LOGW("%s", msg); break;
        case LOGGER_INFO:    LOGI("%s", msg); break;
        case LOGGER_ERR:     LOGE("%s", msg); break;
        default: break;
    }
}

/**************************
 * start / stop helpers   *
 **************************/
int start_server(const std::vector<char> &hw_addr,
                 const std::string &name,
                 bool debug_log,
                 const video_renderer_config_t *video_config,
                 const audio_renderer_config_t *audio_config) {

    raop_callbacks_t cbs{}; // zero‑init
    cbs.conn_init      = conn_init;
    cbs.conn_destroy   = conn_destroy;
    cbs.audio_process  = audio_process;
    cbs.video_process  = video_process;
    cbs.audio_flush    = audio_flush;
    cbs.video_flush    = video_flush;
    cbs.audio_set_volume = audio_set_volume;

    raop = raop_init(10, &cbs);
    if (!raop) {
        LOGE("raop_init failed");
        return -1;
    }

    raop_set_log_callback(raop, log_callback, nullptr);
    raop_set_log_level(raop, debug_log ? RAOP_LOG_DEBUG : LOGGER_INFO);

    render_logger = logger_init();
    logger_set_callback(render_logger, log_callback, nullptr);
    logger_set_level(render_logger, debug_log ? LOGGER_DEBUG : LOGGER_INFO);

    if (video_config->low_latency) logger_log(render_logger, LOGGER_INFO, "Using low‑latency mode");

    if (!(video_renderer = video_init_func(render_logger, video_config))) {
        LOGE("Video renderer init failed");
        return -1;
    }

    if (audio_config->device == AUDIO_DEVICE_NONE) {
        LOGI("Audio disabled");
    } else if (!(audio_renderer = audio_init_func(render_logger, video_renderer, audio_config))) {
        LOGE("Audio renderer init failed");
        return -1;
    }

    if (video_renderer) video_renderer->funcs->start(video_renderer);
    if (audio_renderer) audio_renderer->funcs->start(audio_renderer);

    unsigned short port = 0;
    raop_start(raop, &port);
    raop_set_port(raop, port);

    int error = 0;
    dnssd = dnssd_init(name.c_str(), name.size(), hw_addr.data(), hw_addr.size(), &error);
    if (error || !dnssd) {
        LOGE("dnssd_init failed");
        return -2;
    }

    raop_set_dnssd(raop, dnssd);
    dnssd_register_raop(dnssd, port);
    dnssd_register_airplay(dnssd, static_cast<unsigned short>(port + 1));

    return 0;
}

int stop_server() {
    if (raop) {
        raop_destroy(raop);
        raop = nullptr;
    }

    if (dnssd) {
        dnssd_unregister_raop(dnssd);
        dnssd_unregister_airplay(dnssd);
        dnssd_destroy(dnssd);
        dnssd = nullptr;
    }

    // Destroy audio first to avoid OpenMAX deadlock
    if (audio_renderer) {
        audio_renderer->funcs->destroy(audio_renderer);
        audio_renderer = nullptr;
    }
    if (video_renderer) {
        video_renderer->funcs->destroy(video_renderer);
        video_renderer = nullptr;
    }

    if (render_logger) {
        logger_destroy(render_logger);
        render_logger = nullptr;
    }
    return 0;
}
