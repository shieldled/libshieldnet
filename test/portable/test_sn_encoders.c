/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * Portable (POSIX and Win32) checks of the client-side protocol helpers: the
 * PIXEL_FRAME header encoder and the DEVICE_INFO geometry decoder. Links only
 * the client sources, no OS port, so the Windows CI job can run it.
 *
 * The pixel_header vector comes from goshieldnet, so it is an independent
 * encoding. Generator (a throwaway Go module with
 * `replace github.com/shieldled/goshieldnet => <goshieldnet checkout>`,
 * goshieldnet at c71d3a1):
 *
 *     px := bytes 0x00..0x0f
 *     b, _ := sled.PixelFrame(7, 1000, 2000, px)
 *     fmt.Println(hex.EncodeToString(b))
 *
 * printed
 *     0000000000000007 00000000000003e8 00000000000007d0 00000010
 *     000102030405060708090a0b0c0d0e0f
 * (spaces added). The first 28 bytes are the header checked below.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "command_encode.h"
#include "response_decode.h"
#include "sn_pts.h"

static int failures;

#define CHECK(c)                                                              \
    do {                                                                      \
        if (!(c)) {                                                           \
            printf("FAIL %s %s:%d: %s\n", __func__, __FILE__, __LINE__, #c);            \
            failures++;                                                       \
        }                                                                     \
    } while (0)

static void pixel_header(void)
{
    static const uint8_t want[28] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xd0,
        0x00, 0x00, 0x00, 0x10,
    };
    uint8_t got[28];
    memset(got, 0xAA, sizeof got);
    shieldnet_encode_pixel_frame_header(7, 1000, 2000, 16, got);
    CHECK(memcmp(got, want, sizeof want) == 0);

    /* The timestamps are signed on the wire: -1 is all ones. */
    shieldnet_encode_pixel_frame_header(UINT64_MAX, -1, INT64_MIN, 0, got);
    for (int i = 0; i < 16; i++) CHECK(got[i] == 0xFF);
    CHECK(got[16] == 0x80);
    for (int i = 17; i < 28; i++) CHECK(got[i] == 0x00);
}

/* Appends [namelen][name][vallen][value]; a NULL value is a capability. */
static size_t put_field(uint8_t *b, size_t o, const char *name, const char *val)
{
    size_t nl = strlen(name), vl = val ? strlen(val) : 0;
    b[o++] = (uint8_t)nl;
    memcpy(&b[o], name, nl);
    o += nl;
    b[o++] = (uint8_t)vl;
    if (vl) memcpy(&b[o], val, vl);
    return o + vl;
}

static bool geo(const char *env, const char *strips, const char *leds, const char *bpp,
                const char *dup_leds, sled_geometry_t *g)
{
    uint8_t b[256];
    size_t o = 0;
    if (env) o = put_field(b, o, "envelope", env);
    if (strips) o = put_field(b, o, "strips", strips);
    if (leds) o = put_field(b, o, "leds", leds);
    o = put_field(b, o, "x-private", "9");
    if (bpp) o = put_field(b, o, "bpp", bpp);
    o = put_field(b, o, "rgbw", NULL); /* a capability is ignored */
    if (dup_leds) o = put_field(b, o, "leds", dup_leds);
    return sled_decode_geometry(b, o, g);
}

/* A valid geometry plus, if `pins` is non-NULL, a field named `pins` with that
 * value, and a private capability. */
static bool geo_unknown_field(const char *pins, sled_geometry_t *g)
{
    uint8_t b[256];
    size_t o = 0;
    o = put_field(b, o, "envelope", "1400");
    o = put_field(b, o, "strips", "4");
    o = put_field(b, o, "leds", "300");
    o = put_field(b, o, "bpp", "3");
    if (pins) o = put_field(b, o, "pins", pins);
    o = put_field(b, o, "x-cap", NULL);
    return sled_decode_geometry(b, o, g);
}

static void geometry(void)
{
    sled_geometry_t g;

    memset(&g, 0, sizeof g);
    CHECK(geo("1400", "4", "300", "3", NULL, &g));
    CHECK(g.envelope == 1400 && g.strips == 4 && g.leds == 300 && g.bpp == 3);

    CHECK(!geo("1400", "4", NULL, "3", NULL, &g));      /* missing leds */
    CHECK(!geo("1400", "4", "300", "5", NULL, &g));     /* bpp 5 */
    CHECK(!geo("1400", "4", "0", "3", NULL, &g));       /* leds 0 */
    CHECK(!geo("1400", "65535", "65535", "4", NULL, &g)); /* over the capacity cap */
    CHECK(!geo("1400", "4", "010", "3", NULL, &g));     /* non-canonical decimal */

    /* Rule 4: a repeated field takes its LAST value, and that is the one checked. */
    memset(&g, 0, sizeof g);
    CHECK(geo("1400", "4", "300", "3", "7", &g));
    CHECK(g.leds == 7);
    CHECK(!geo("1400", "4", "300", "3", "0", &g));      /* last is invalid, first valid */
    CHECK(geo("1400", "4", "0", "3", "300", &g));       /* first invalid, last valid */
    CHECK(g.leds == 300);

    /* Exactly at the cap is accepted: 4096 x 1024 x 4 = 16777216. */
    CHECK(geo("1400", "4096", "1024", "4", NULL, &g));
    CHECK(!geo("1400", "4096", "1025", "4", NULL, &g));

    /* envelope ranges from 80 (sled 5.3.1). */
    CHECK(!geo("79", "4", "300", "3", NULL, &g));
    CHECK(geo("80", "4", "300", "3", NULL, &g));
    CHECK(g.envelope == 80);

    /* A name the decoder does not know is skipped, whatever its value (sled
     * 5.3.3 rule 2): `pins` is one. */
    memset(&g, 0, sizeof g);
    CHECK(geo_unknown_field(NULL, &g));
    CHECK(g.envelope == 1400 && g.leds == 300);
    CHECK(geo_unknown_field("8", &g));
    CHECK(g.envelope == 1400 && g.leds == 300);
    CHECK(geo_unknown_field("256", &g));
    CHECK(geo_unknown_field("032", &g));
}

static void pts_lead(void)
{
    CHECK(SN_PTS_MAX_LEAD_NS == INT64_C(1000000000));
}

int main(void)
{
    pixel_header();
    geometry();
    pts_lead();
    if (failures) {
        printf("%d check(s) failed\n", failures);
        return 1;
    }
    puts("sn_encoders: all checks passed");
    return 0;
}
