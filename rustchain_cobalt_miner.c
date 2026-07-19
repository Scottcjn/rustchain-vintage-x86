/*
 * rustchain_cobalt_miner.c - RustChain attestation miner for Sun Cobalt Qube 3
 *                            (AMD K6-2, i586, Cobalt Linux 2.2 / glibc 2.1.3)
 *
 * Single file, no external deps beyond libc. Detects the CPU from
 * /proc/cpuinfo, times a busy loop with RDTSC when the CPU advertises it
 * or a calibrated libc wall-clock loop otherwise, reads MACs via ioctl
 * (kernel 2.2 has no sysfs), then POSTs an attestation JSON to the
 * RustChain node over plain HTTP.
 *
 * Flags:
 *   --test-only        print hardware detection, no network
 *   --dry-run          print the exact JSON payload, no network
 *   --self-test        run SHA-1 / math self-tests and exit
 *   --force-loop-timing use the non-RDTSC timing path even when available
 *   --once             attest one time and exit
 *   --node host:port   node address (default 50.28.86.131:8088)
 *   --wallet id        wallet / miner id (default cobalt-qube3-scott)
 *
 * Build on the Qube (native, correct for kernel 2.2 / glibc 2.1.3):
 *   gcc -O2 -o rustchain_cobalt rustchain_cobalt_miner.c
 * Build/test on a modern Linux x86 host (also has RDTSC):
 *   gcc -O2 -m32 -o rustchain_cobalt rustchain_cobalt_miner.c   (or -m64)
 *   ./rustchain_cobalt --self-test
 *
 * Protocol matches rustchain_amiga_miner.c (legacy plain-HTTP path):
 * POST /attest/challenge {} -> nonce, then POST /attest/submit with
 * miner/miner_id/nonce/report/device/signals/fingerprint. No Ed25519.
 * The fingerprint is honest: clock_drift carries raw RDTSC-derived samples,
 * anti_emulation lists real VM indicators found in /proc/cpuinfo. A genuine
 * K6-2 has no hypervisor flag, so it passes; that is the whole point.
 *
 * C89 / gcc 2.95 rules: all declarations at the top of a block, no // comments.
 */

/* Expose the historic BSD socket/ioctl interfaces under modern -ansi. */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _BSD_SOURCE
#define _BSD_SOURCE 1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/time.h>
#include <sys/utsname.h>

#define MINER_VERSION "1.1"
#define DEFAULT_NODE_HOST "50.28.86.131"
#define DEFAULT_NODE_PORT 8088
#define DEFAULT_WALLET "cobalt-qube3-scott"
#define POLL_SECONDS (30 * 60)

#define PAYLOAD_MAX 4096
#define HTTP_MAX 5120
#define RESP_MAX 8192

/* ------------------------------------------------------------------ */
/* SHA-1  (verbatim from rustchain_amiga_miner.c, portable C89)        */
/* ------------------------------------------------------------------ */

typedef struct {
    unsigned long h[5];
    unsigned long len_lo;
    unsigned long len_hi;
    unsigned char buf[64];
    int buf_used;
} sha1_ctx;

static unsigned long sha1_rol(unsigned long v, int n)
{
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFFUL;
}

static void sha1_init(sha1_ctx *c)
{
    c->h[0] = 0x67452301UL;
    c->h[1] = 0xEFCDAB89UL;
    c->h[2] = 0x98BADCFEUL;
    c->h[3] = 0x10325476UL;
    c->h[4] = 0xC3D2E1F0UL;
    c->len_lo = 0;
    c->len_hi = 0;
    c->buf_used = 0;
}

static void sha1_block(sha1_ctx *c, const unsigned char *p)
{
    unsigned long w[80];
    unsigned long a, b, d, e, f, k, t;
    unsigned long cc;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((unsigned long)p[i * 4] << 24) |
               ((unsigned long)p[i * 4 + 1] << 16) |
               ((unsigned long)p[i * 4 + 2] << 8) |
               ((unsigned long)p[i * 4 + 3]);
    }
    for (i = 16; i < 80; i++)
        w[i] = sha1_rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3]; e = c->h[4];

    for (i = 0; i < 80; i++) {
        if (i < 20)      { f = (b & cc) | ((~b) & d);          k = 0x5A827999UL; }
        else if (i < 40) { f = b ^ cc ^ d;                     k = 0x6ED9EBA1UL; }
        else if (i < 60) { f = (b & cc) | (b & d) | (cc & d);  k = 0x8F1BBCDCUL; }
        else             { f = b ^ cc ^ d;                     k = 0xCA62C1D6UL; }
        t = (sha1_rol(a, 5) + f + e + k + w[i]) & 0xFFFFFFFFUL;
        e = d; d = cc; cc = sha1_rol(b, 30); b = a; a = t;
    }

    c->h[0] = (c->h[0] + a) & 0xFFFFFFFFUL;
    c->h[1] = (c->h[1] + b) & 0xFFFFFFFFUL;
    c->h[2] = (c->h[2] + cc) & 0xFFFFFFFFUL;
    c->h[3] = (c->h[3] + d) & 0xFFFFFFFFUL;
    c->h[4] = (c->h[4] + e) & 0xFFFFFFFFUL;
}

static void sha1_update(sha1_ctx *c, const unsigned char *p, unsigned long n)
{
    unsigned long old = c->len_lo;
    c->len_lo = (c->len_lo + (n << 3)) & 0xFFFFFFFFUL;
    if (c->len_lo < old)
        c->len_hi++;
    c->len_hi += (n >> 29);

    while (n > 0) {
        unsigned long take = 64 - c->buf_used;
        if (take > n) take = n;
        memcpy(c->buf + c->buf_used, p, take);
        c->buf_used += (int)take;
        p += take;
        n -= take;
        if (c->buf_used == 64) {
            sha1_block(c, c->buf);
            c->buf_used = 0;
        }
    }
}

static void sha1_final(sha1_ctx *c, unsigned char out[20])
{
    unsigned char pad = 0x80;
    unsigned char zero = 0;
    unsigned char lenb[8];
    unsigned long lo = c->len_lo, hi = c->len_hi;
    int i;

    sha1_update(c, &pad, 1);
    while (c->buf_used != 56)
        sha1_update(c, &zero, 1);

    lenb[0] = (unsigned char)(hi >> 24); lenb[1] = (unsigned char)(hi >> 16);
    lenb[2] = (unsigned char)(hi >> 8);  lenb[3] = (unsigned char)(hi);
    lenb[4] = (unsigned char)(lo >> 24); lenb[5] = (unsigned char)(lo >> 16);
    lenb[6] = (unsigned char)(lo >> 8);  lenb[7] = (unsigned char)(lo);
    memcpy(c->buf + 56, lenb, 8);
    sha1_block(c, c->buf);

    for (i = 0; i < 5; i++) {
        out[i * 4]     = (unsigned char)(c->h[i] >> 24);
        out[i * 4 + 1] = (unsigned char)(c->h[i] >> 16);
        out[i * 4 + 2] = (unsigned char)(c->h[i] >> 8);
        out[i * 4 + 3] = (unsigned char)(c->h[i]);
    }
}

static void sha1_hex(const unsigned char *data, unsigned long n, char out[41])
{
    sha1_ctx c;
    unsigned char dig[20];
    int i;
    static const char hexd[] = "0123456789abcdef";

    sha1_init(&c);
    sha1_update(&c, data, n);
    sha1_final(&c, dig);
    for (i = 0; i < 20; i++) {
        out[i * 2] = hexd[dig[i] >> 4];
        out[i * 2 + 1] = hexd[dig[i] & 0x0F];
    }
    out[40] = '\0';
}

/* ------------------------------------------------------------------ */
/* 64-bit helpers + entropy stats (verbatim from the Amiga miner)      */
/* ------------------------------------------------------------------ */

#define ENT_SAMPLES 16

struct entropy_info {
    unsigned long samples_ns[ENT_SAMPLES];
    int sample_count;
    int timer_ok;
    char timing_source[8];
    unsigned long long mean_ns;
    unsigned long long variance_ns;
    unsigned long long stdev_ns;
    unsigned long long drift_stdev_ns;
    unsigned long min_ns;
    unsigned long max_ns;
    unsigned long long cv_ppm;
};

static char *u64s(unsigned long long v, char *buf)
{
    char tmp[24];
    int i = 0, o = 0;
    if (v == 0) { buf[0] = '0'; buf[1] = '\0'; return buf; }
    while (v > 0) { tmp[i++] = (char)('0' + (int)(v % 10)); v /= 10; }
    while (i > 0) buf[o++] = tmp[--i];
    buf[o] = '\0';
    return buf;
}

static unsigned long long isqrt64(unsigned long long x)
{
    unsigned long long lo = 1, hi = 4294967295ULL, mid;

    if (x == 0) return 0;
    if (x < hi) hi = x;
    while (lo < hi) {
        mid = lo + (hi - lo + 1) / 2;
        if (mid <= x / mid) lo = mid;
        else hi = mid - 1;
    }
    return lo;
}

static void entropy_compute_stats(struct entropy_info *e)
{
    int n = e->sample_count, i;
    unsigned long long sum = 0, var = 0;
    long long dsum = 0, dvar = 0, dmean;

    e->min_ns = e->samples_ns[0];
    e->max_ns = e->samples_ns[0];
    for (i = 0; i < n; i++) {
        sum += e->samples_ns[i];
        if (e->samples_ns[i] < e->min_ns) e->min_ns = e->samples_ns[i];
        if (e->samples_ns[i] > e->max_ns) e->max_ns = e->samples_ns[i];
    }
    e->mean_ns = sum / (unsigned long long)n;

    for (i = 0; i < n; i++) {
        long long d = (long long)e->samples_ns[i] - (long long)e->mean_ns;
        var += (unsigned long long)(d * d);
    }
    e->variance_ns = var / (unsigned long long)n;
    e->stdev_ns = isqrt64(e->variance_ns);
    e->cv_ppm = e->mean_ns ? (e->stdev_ns * 1000000ULL) / e->mean_ns : 0;

    if (n > 1) {
        for (i = 1; i < n; i++)
            dsum += (long long)e->samples_ns[i] - (long long)e->samples_ns[i - 1];
        dmean = dsum / (n - 1);
        for (i = 1; i < n; i++) {
            long long d = ((long long)e->samples_ns[i] -
                           (long long)e->samples_ns[i - 1]) - dmean;
            dvar += d * d;
        }
        e->drift_stdev_ns = isqrt64((unsigned long long)(dvar / (n - 1)));
    } else {
        e->drift_stdev_ns = 0;
    }
}

/* server thresholds: cv >= 0.0001 and nonzero drift, timer worked */
static int clock_drift_passed(const struct entropy_info *e)
{
    return e->timer_ok && e->cv_ppm >= 100 && e->drift_stdev_ns > 0;
}

/* ------------------------------------------------------------------ */
/* x86 timing: RDTSC when advertised, calibrated libc loop otherwise  */
/* ------------------------------------------------------------------ */

/*
 * Detect CPUID without executing it first.  x86-64 guarantees CPUID.  On
 * 32-bit x86 we toggle EFLAGS.ID; 386 and early 486 chips leave it fixed.
 * This avoids a SIGILL handler and works with the gcc 2.x inline assembler.
 */
static int cpu_has_cpuid(void)
{
#if defined(__x86_64__)
    return 1;
#else
    unsigned long before, after;

    __asm__ __volatile__(
        "pushfl\n\t"
        "popl %0\n\t"
        "movl %0,%1\n\t"
        "xorl $0x200000,%1\n\t"
        "pushl %1\n\t"
        "popfl\n\t"
        "pushfl\n\t"
        "popl %1\n\t"
        "pushl %0\n\t"
        "popfl"
        : "=&r"(before), "=&r"(after)
        :
        : "cc");
    return ((before ^ after) & 0x200000UL) != 0;
#endif
}

/* RDTSC is used only when CPUID leaf 1 explicitly advertises it. */
static int cpu_supports_tsc(int cpu_family)
{
    unsigned int eax, ebx, ecx, edx;

    /* No family-4 CPU implements RDTSC, including CPUID-capable 486s. */
    if (cpu_family > 0 && cpu_family <= 4)
        return 0;
    if (!cpu_has_cpuid())
        return 0;

    eax = 0;
    ecx = 0;
    __asm__ __volatile__("cpuid"
                         : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                         : "0"(eax), "2"(ecx));
    if (eax < 1U)
        return 0;

    eax = 1;
    ecx = 0;
    __asm__ __volatile__("cpuid"
                         : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                         : "0"(eax), "2"(ecx));
    return (edx & 0x00000010U) ? 1 : 0;
}

/* Read the cycle counter, after cpu_supports_tsc() has approved it. */
static unsigned long long read_tsc(void)
{
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long)hi << 32) | (unsigned long long)lo;
}

/*
 * Estimate the TSC rate (cycles per second) by spinning for a wall-clock
 * interval measured with clock(). Falls back to a nominal 450MHz (the
 * K6-2/450 in the original box) if calibration is degenerate; the exact
 * rate only scales the reported ns, and variance is the useful signal.
 */
static unsigned long long calibrate_tsc_hz(void)
{
    clock_t c0, c1;
    unsigned long long t0, t1, dc;
    double secs;

    t0 = read_tsc();
    c0 = clock();
    /* busy-wait about 150ms of CPU time */
    while (((c1 = clock()) - c0) < (clock_t)(CLOCKS_PER_SEC / 7))
        ;
    t1 = read_tsc();
    dc = t1 - t0;
    secs = (double)(c1 - c0) / (double)CLOCKS_PER_SEC;
    if (secs <= 0.0 || dc == 0)
        return 450000000ULL;
    return (unsigned long long)((double)dc / secs);
}

static void collect_entropy_rdtsc(struct entropy_info *e)
{
    unsigned long long hz;
    int i, j;
    volatile unsigned long acc = 0;

    memset(e, 0, sizeof(*e));
    e->sample_count = ENT_SAMPLES;
    e->timer_ok = 1;
    strcpy(e->timing_source, "rdtsc");

    hz = calibrate_tsc_hz();
    if (hz == 0) hz = 450000000ULL;

    for (i = 0; i < ENT_SAMPLES; i++) {
        unsigned long long a0, a1, cycles;
        a0 = read_tsc();
        for (j = 0; j < 200000; j++)
            acc ^= (unsigned long)(j * 19 + i);
        a1 = read_tsc();
        cycles = a1 - a0;
        /* cycles -> ns: ns = cycles * 1e9 / hz */
        e->samples_ns[i] = (unsigned long)((cycles * 1000000000ULL) / hz);
    }

    entropy_compute_stats(e);
}

/* Keep the loop observable even under -O2 on old and new compilers. */
static volatile unsigned long loop_timing_sink = 0;

static void run_timing_loop(unsigned long iterations, unsigned long salt)
{
    volatile unsigned long acc;
    unsigned long i;

    acc = salt ^ 0x9E3779B9UL;
    for (i = 0; i < iterations; i++)
        acc = (acc * 1664525UL + 1013904223UL) ^ (i + salt);
    loop_timing_sink ^= acc;
}

static unsigned long timeval_diff_us(const struct timeval *start,
                                     const struct timeval *end)
{
    long sec, usec;

    sec = (long)(end->tv_sec - start->tv_sec);
    usec = (long)(end->tv_usec - start->tv_usec);
    if (usec < 0) {
        usec += 1000000L;
        sec--;
    }
    if (sec < 0 || sec > 3600L)
        return 0;
    return (unsigned long)sec * 1000000UL + (unsigned long)usec;
}

/*
 * Measure a loop with gettimeofday().  clock() is sampled at the same time
 * and is used only when wall-clock resolution is too coarse or unavailable.
 */
static int measure_timing_loop(unsigned long iterations, unsigned long salt,
                               unsigned long long *elapsed_ns)
{
    struct timeval tv0, tv1;
    clock_t c0, c1;
    unsigned long elapsed_us;
    int have_tv;

    c0 = clock();
    have_tv = (gettimeofday(&tv0, (struct timezone *)0) == 0);
    run_timing_loop(iterations, salt);
    if (have_tv)
        have_tv = (gettimeofday(&tv1, (struct timezone *)0) == 0);
    c1 = clock();

    if (have_tv) {
        elapsed_us = timeval_diff_us(&tv0, &tv1);
        if (elapsed_us > 0) {
            *elapsed_ns = (unsigned long long)elapsed_us * 1000ULL;
            return 1;
        }
    }

    if (c0 != (clock_t)-1 && c1 != (clock_t)-1 && c1 > c0 &&
        CLOCKS_PER_SEC > 0) {
        *elapsed_ns = ((unsigned long long)(c1 - c0) * 1000000000ULL) /
                      (unsigned long long)CLOCKS_PER_SEC;
        return *elapsed_ns > 0;
    }

    *elapsed_ns = 0;
    return 0;
}

/* Calibrate one sample to roughly 20ms so old, coarse clocks still tick. */
static unsigned long calibrate_loop_iterations(void)
{
    unsigned long iterations;
    unsigned long long elapsed_ns, scaled;
    int attempt;

    iterations = 50000UL;
    for (attempt = 0; attempt < 10; attempt++) {
        if (!measure_timing_loop(iterations, (unsigned long)attempt,
                                 &elapsed_ns) || elapsed_ns == 0) {
            if (iterations <= 25000000UL)
                iterations *= 4UL;
            else
                iterations = 100000000UL;
            continue;
        }

        if (elapsed_ns >= 10000000ULL && elapsed_ns <= 40000000ULL)
            return iterations;

        scaled = ((unsigned long long)iterations * 20000000ULL) / elapsed_ns;
        if (scaled < 1000ULL)
            scaled = 1000ULL;
        if (scaled > 100000000ULL)
            scaled = 100000000ULL;
        if ((unsigned long)scaled == iterations)
            return iterations;
        iterations = (unsigned long)scaled;
    }
    return iterations;
}

static void collect_entropy_loop(struct entropy_info *e)
{
    unsigned long iterations;
    unsigned long long elapsed_ns;
    int i;

    memset(e, 0, sizeof(*e));
    e->sample_count = ENT_SAMPLES;
    e->timer_ok = 1;
    strcpy(e->timing_source, "loop");
    iterations = calibrate_loop_iterations();

    for (i = 0; i < ENT_SAMPLES; i++) {
        if (!measure_timing_loop(iterations, (unsigned long)i, &elapsed_ns)) {
            e->timer_ok = 0;
            elapsed_ns = 0;
        }
        if (elapsed_ns > (unsigned long long)~0UL)
            elapsed_ns = (unsigned long long)~0UL;
        e->samples_ns[i] = (unsigned long)elapsed_ns;
    }

    entropy_compute_stats(e);
}

static void collect_entropy(struct entropy_info *e, int use_tsc)
{
    if (use_tsc)
        collect_entropy_rdtsc(e);
    else
        collect_entropy_loop(e);
}

/* ------------------------------------------------------------------ */
/* Hardware detection: /proc/cpuinfo + uname + ioctl MACs              */
/* ------------------------------------------------------------------ */

struct hwinfo {
    char family[16];        /* "x86" */
    char arch[24];          /* "retro" (K6-2 is 1998 silicon) */
    char machine[16];       /* uname -m, e.g. "i586" */
    char cpu[96];           /* /proc/cpuinfo model name */
    char vendor[16];        /* AuthenticAMD */
    int  cpu_family;        /* 5 for K6 */
    int  has_tsc;
    int  has_hypervisor;    /* VM indicator */
    int  cores;
    unsigned long mem_kb;
    char cpu_sig[41];       /* sha1 of identifying cpuinfo fields */
    char macs[8][18];       /* up to 8 MAC strings "aa:bb:.." */
    int  mac_count;
    char hostname[64];
};

/* read a whole small file into buf, return length or -1 */
static int read_file(const char *path, char *buf, int buflen)
{
    FILE *f = fopen(path, "r");
    int n;
    if (!f) return -1;
    n = (int)fread(buf, 1, buflen - 1, f);
    fclose(f);
    if (n < 0) n = 0;
    buf[n] = '\0';
    return n;
}

/* find "key<sep>value" line in cpuinfo text, copy value (trimmed) */
static int cpuinfo_field(const char *text, const char *key, char *out, int outlen)
{
    const char *p = text;
    int klen = (int)strlen(key);

    while (p && *p) {
        if (strncmp(p, key, klen) == 0) {
            const char *c = strchr(p, ':');
            const char *nl;
            int o = 0;
            if (c) {
                c++;
                while (*c == ' ' || *c == '\t') c++;
                nl = strchr(c, '\n');
                while (*c && c != nl && o < outlen - 1)
                    out[o++] = *c++;
                /* trim trailing spaces */
                while (o > 0 && (out[o - 1] == ' ' || out[o - 1] == '\t'))
                    o--;
                out[o] = '\0';
                return 1;
            }
        }
        p = strchr(p, '\n');
        if (p) p++;
    }
    out[0] = '\0';
    return 0;
}

static void detect_cpu(struct hwinfo *hw)
{
    static char cpuinfo[8192];
    char flags[2048];
    char famstr[16];
    char sigsrc[512];

    read_file("/proc/cpuinfo", cpuinfo, sizeof(cpuinfo));

    if (!cpuinfo_field(cpuinfo, "model name", hw->cpu, sizeof(hw->cpu)))
        strcpy(hw->cpu, "Unknown x86");
    if (!cpuinfo_field(cpuinfo, "vendor_id", hw->vendor, sizeof(hw->vendor)))
        strcpy(hw->vendor, "unknown");
    if (cpuinfo_field(cpuinfo, "cpu family", famstr, sizeof(famstr)))
        hw->cpu_family = atoi(famstr);
    else
        hw->cpu_family = 0;

    flags[0] = '\0';
    cpuinfo_field(cpuinfo, "flags", flags, sizeof(flags));
    /*
     * Do not trust a missing or synthetic /proc flag enough to execute
     * RDTSC.  CPUID must exist and explicitly advertise feature bit 4.
     * Family 4 is forced to the loop path even on late CPUID-capable 486s.
     */
    hw->has_tsc = cpu_supports_tsc(hw->cpu_family);
    /* honest VM check: kernel exposes "hypervisor" in flags under a VM */
    hw->has_hypervisor = strstr(flags, "hypervisor") ? 1 : 0;

    /* stable cpu signature from identifying fields (analog of the ROM hash) */
    sprintf(sigsrc, "%s|%s|fam%d|%.400s", hw->vendor, hw->cpu, hw->cpu_family, flags);
    sha1_hex((const unsigned char *)sigsrc, (unsigned long)strlen(sigsrc), hw->cpu_sig);
}

static void detect_uname(struct hwinfo *hw)
{
    struct utsname u;
    if (uname(&u) == 0) {
        strncpy(hw->machine, u.machine, sizeof(hw->machine) - 1);
        hw->machine[sizeof(hw->machine) - 1] = '\0';
        strncpy(hw->hostname, u.nodename, sizeof(hw->hostname) - 1);
        hw->hostname[sizeof(hw->hostname) - 1] = '\0';
    } else {
        strcpy(hw->machine, "i586");
        strcpy(hw->hostname, "qube3");
    }
}

static void detect_mem(struct hwinfo *hw)
{
    static char meminfo[4096];
    char val[32];
    hw->mem_kb = 0;
    if (read_file("/proc/meminfo", meminfo, sizeof(meminfo)) > 0) {
        /* 2.2 kernel MemTotal is in kB */
        if (cpuinfo_field(meminfo, "MemTotal", val, sizeof(val)))
            hw->mem_kb = strtoul(val, NULL, 10);
    }
}

/* MAC addresses via SIOCGIFCONF + SIOCGIFHWADDR (works on kernel 2.2) */
static void detect_macs(struct hwinfo *hw)
{
    struct ifconf ifc;
    struct ifreq ifrbuf[16];
    int sock, i, count;

    hw->mac_count = 0;
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    memset(&ifc, 0, sizeof(ifc));
    ifc.ifc_len = sizeof(ifrbuf);
    ifc.ifc_req = ifrbuf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) < 0) {
        close(sock);
        return;
    }

    count = ifc.ifc_len / sizeof(struct ifreq);
    for (i = 0; i < count && hw->mac_count < 8; i++) {
        struct ifreq ir;
        unsigned char *m;
        memset(&ir, 0, sizeof(ir));
        memcpy(ir.ifr_name, ifrbuf[i].ifr_name, IFNAMSIZ);
        ir.ifr_name[IFNAMSIZ - 1] = '\0';
        if (strcmp(ir.ifr_name, "lo") == 0)
            continue;
        if (ioctl(sock, SIOCGIFHWADDR, &ir) < 0)
            continue;
        m = (unsigned char *)ir.ifr_hwaddr.sa_data;
        if ((m[0] | m[1] | m[2] | m[3] | m[4] | m[5]) == 0)
            continue;
        sprintf(hw->macs[hw->mac_count], "%02x:%02x:%02x:%02x:%02x:%02x",
                m[0], m[1], m[2], m[3], m[4], m[5]);
        hw->mac_count++;
    }
    close(sock);
}

/* lowercase copy for case-insensitive brand matching */
static void str_lower(char *dst, const char *src, int dstlen)
{
    int i = 0;
    while (src[i] && i < dstlen - 1) {
        char c = src[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        dst[i] = c;
        i++;
    }
    dst[i] = '\0';
}

/*
 * Honest arch classification. We report what the chip truthfully says it is
 * (CPU family from /proc/cpuinfo + brand string), never a self-assigned
 * vintage label. The server still validates via the timing fingerprint that
 * it is real silicon; this only names the generation.
 *
 * The hard case is family 6: Pentium Pro/II/III are family 6, but so are
 * modern Core i-series. We only tag family 6 as vintage when the brand string
 * literally says so ("Pentium II/III/Pro"), otherwise it is "modern". This
 * refuses to hand a vintage bonus to a modern chip.
 *
 *   family 4                       -> "486"
 *   family 5 (Pentium/MMX/K5/K6)   -> "retro"
 *   family 6 + "Pentium III"       -> "pentium3"
 *   family 6 + "Pentium II"        -> "pentium2"
 *   family 6 + "Pentium Pro"       -> "pentium_pro"
 *   anything else                  -> "modern"
 */
static void classify_arch(struct hwinfo *hw)
{
    char b[96];
    str_lower(b, hw->cpu, sizeof(b));

    if (hw->cpu_family == 4 || strstr(b, "486")) {
        strcpy(hw->arch, "486");
    } else if (hw->cpu_family == 6 && (strstr(b, "pentium iii") || strstr(b, "pentium 3"))) {
        strcpy(hw->arch, "pentium3");
    } else if (hw->cpu_family == 6 && (strstr(b, "pentium ii") || strstr(b, "pentium 2"))) {
        strcpy(hw->arch, "pentium2");
    } else if (hw->cpu_family == 6 && strstr(b, "pentium pro")) {
        strcpy(hw->arch, "pentium_pro");
    } else if (hw->cpu_family == 5) {
        /* classic Pentium, Pentium MMX, AMD K5/K6 -- 1993-1999 */
        strcpy(hw->arch, "retro");
    } else {
        strcpy(hw->arch, "modern");
    }
}

static void detect_hardware(struct hwinfo *hw)
{
    memset(hw, 0, sizeof(*hw));
    strcpy(hw->family, "x86");
    hw->cores = 1;
    detect_cpu(hw);
    classify_arch(hw);
    detect_uname(hw);
    detect_mem(hw);
    detect_macs(hw);
}

/* ------------------------------------------------------------------ */
/* JSON payload (structure from the Amiga miner, x86 device fields)    */
/* ------------------------------------------------------------------ */

static void json_escape(char *dst, int dstlen, const char *src)
{
    int o = 0;
    while (*src && o < dstlen - 8) {
        unsigned char ch = (unsigned char)*src++;
        if (ch == '"' || ch == '\\') {
            dst[o++] = '\\';
            dst[o++] = (char)ch;
        } else if (ch < 0x20) {
            sprintf(dst + o, "\\u%04x", ch);
            o += 6;
        } else {
            dst[o++] = (char)ch;
        }
    }
    dst[o] = '\0';
}

static int build_macs_json(char *out, int outlen, const struct hwinfo *hw)
{
    int i, o = 0;
    o += sprintf(out + o, "[");
    for (i = 0; i < hw->mac_count && o < outlen - 24; i++)
        o += sprintf(out + o, "%s\"%s\"", i ? "," : "", hw->macs[i]);
    o += sprintf(out + o, "]");
    return o;
}

static int build_fingerprint(char *out, int outlen,
                             const struct hwinfo *hw,
                             const struct entropy_info *e)
{
    char mean_s[24], stdev_s[24], drift_s[24], cvw_s[24];
    char samples_s[ENT_SAMPLES * 12];
    char indicators_s[80];
    int clock_ok = clock_drift_passed(e);
    int emu_ok = !hw->has_hypervisor;
    int all_ok = clock_ok && emu_ok;
    int i, o = 0, len;
    const char *timing_source;

    timing_source = strcmp(e->timing_source, "rdtsc") == 0 ? "rdtsc" : "loop";

    for (i = 0; i < e->sample_count; i++)
        o += sprintf(samples_s + o, "%s%lu", i ? "," : "", e->samples_ns[i]);

    indicators_s[0] = '\0';
    if (hw->has_hypervisor)
        sprintf(indicators_s, "\"cpuinfo:hypervisor\"");

    len = sprintf(out,
        "{"
        "\"all_passed\":%s,"
        "\"checks\":{"
            "\"clock_drift\":{"
                "\"passed\":%s,"
                "\"data\":{"
                    "\"mean_ns\":%s,"
                    "\"stdev_ns\":%s,"
                    "\"cv\":%s.%06lu,"
                    "\"drift_stdev\":%s,"
                    "\"timer_source\":\"%s\","
                    "\"timing_source\":\"%s\","
                    "\"samples_ns\":[%s]"
                "}"
            "},"
            "\"anti_emulation\":{"
                "\"passed\":%s,"
                "\"data\":{"
                    "\"platform\":\"linux-x86\","
                    "\"vm_indicators\":[%s]"
                "}"
            "}"
        "}"
        "}",
        all_ok ? "true" : "false",
        clock_ok ? "true" : "false",
        u64s(e->mean_ns, mean_s),
        u64s(e->stdev_ns, stdev_s),
        u64s(e->cv_ppm / 1000000ULL, cvw_s),
        (unsigned long)(e->cv_ppm % 1000000ULL),
        u64s(e->drift_stdev_ns, drift_s),
        timing_source,
        timing_source,
        samples_s,
        emu_ok ? "true" : "false",
        indicators_s);

    if (len >= outlen) return -1;
    return len;
}

static int build_payload(char *out, int outlen,
                         const struct hwinfo *hw,
                         const char *wallet, const char *miner_id,
                         const char *nonce,
                         const struct entropy_info *e)
{
    char w[128], m[128], n[160];
    char macs_json[192];
    char commit_src[512];
    char commitment[41];
    char mean_s[24], var_s[24], score_s[24];
    static char fingerprint[1200];
    int len;

    json_escape(w, sizeof(w), wallet);
    json_escape(m, sizeof(m), miner_id);
    json_escape(n, sizeof(n), nonce);

    if (build_fingerprint(fingerprint, sizeof(fingerprint), hw, e) < 0)
        return -1;
    build_macs_json(macs_json, sizeof(macs_json), hw);

    sprintf(commit_src, "%s%s%s%s", n, w, hw->arch, hw->cpu_sig);
    sha1_hex((const unsigned char *)commit_src, (unsigned long)strlen(commit_src),
             commitment);

    len = sprintf(out,
        "{"
        "\"miner\":\"%s\","
        "\"miner_id\":\"%s\","
        "\"nonce\":\"%s\","
        "\"report\":{"
            "\"nonce\":\"%s\","
            "\"commitment\":\"%s\","
            "\"derived\":{"
                "\"mean_ns\":%s,"
                "\"variance_ns\":%s,"
                "\"min_ns\":%lu,"
                "\"max_ns\":%lu,"
                "\"sample_count\":%d"
            "},"
            "\"entropy_score\":%s"
        "},"
        "\"device\":{"
            "\"family\":\"%s\","
            "\"arch\":\"%s\","
            "\"model\":\"%s\","
            "\"cpu\":\"%s\","
            "\"vendor\":\"%s\","
            "\"cpu_family\":%d,"
            "\"cores\":%d,"
            "\"memory_gb\":0,"
            "\"memory_kb\":%lu,"
            "\"machine\":\"%s\","
            "\"cpu_sig\":\"%s\","
            "\"has_tsc\":%s,"
            "\"miner_version\":\"" MINER_VERSION "\""
        "},"
        "\"signals\":{"
            "\"macs\":%s,"
            "\"hostname\":\"%s\""
        "},"
        "\"fingerprint\":%s"
        "}",
        w, m, n, n, commitment,
        u64s(e->mean_ns, mean_s), u64s(e->variance_ns, var_s),
        e->min_ns, e->max_ns, e->sample_count,
        u64s(e->variance_ns, score_s),
        hw->family, hw->arch, hw->cpu, hw->cpu, hw->vendor,
        hw->cpu_family, hw->cores, hw->mem_kb, hw->machine, hw->cpu_sig,
        hw->has_tsc ? "true" : "false",
        macs_json, hw->hostname,
        fingerprint);

    if (len >= outlen) return -1;
    return len;
}

/* ------------------------------------------------------------------ */
/* HTTP                                                                */
/* ------------------------------------------------------------------ */

static int format_http_post(char *out, int outlen,
                            const char *host, int port,
                            const char *path, const char *body)
{
    int len = (int)strlen(body);
    int n;

    n = sprintf(out,
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "User-Agent: rustchain-cobalt/" MINER_VERSION "\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        path, host, port, len, body);

    if (n >= outlen) return -1;
    return n;
}

static int http_status(const char *resp)
{
    if (strncmp(resp, "HTTP/1.", 7) != 0) return -1;
    return atoi(resp + 9);
}

static int json_find_string(const char *json, const char *key,
                            char *out, int outlen)
{
    char pat[64];
    const char *p;
    int o = 0;

    sprintf(pat, "\"%s\"", key);
    p = strstr(json, pat);
    if (!p) return 0;
    p += strlen(pat);
    while (*p == ' ' || *p == ':') p++;
    if (*p != '"') return 0;
    p++;
    while (*p && *p != '"' && o < outlen - 1)
        out[o++] = *p++;
    out[o] = '\0';
    return o > 0;
}

static int http_request(const char *host, int port,
                        const char *path, const char *body,
                        char *resp, int resplen)
{
    static char req[HTTP_MAX];
    struct sockaddr_in sa;
    int reqlen, got, total = 0;
    int s;

    reqlen = format_http_post(req, sizeof(req), host, port, path, body);
    if (reqlen < 0) {
        printf("[FAIL] request too large\n");
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);

    sa.sin_addr.s_addr = inet_addr(host);
    if (sa.sin_addr.s_addr == INADDR_NONE) {
        struct hostent *he = gethostbyname(host);
        if (!he) {
            printf("[FAIL] cannot resolve %s\n", host);
            return -1;
        }
        memcpy(&sa.sin_addr, he->h_addr_list[0], 4);
    }

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        printf("[FAIL] socket() failed\n");
        return -1;
    }

    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        printf("[FAIL] connect to %s:%d failed\n", host, port);
        close(s);
        return -1;
    }

    if (send(s, req, reqlen, 0) != reqlen) {
        printf("[FAIL] send failed\n");
        close(s);
        return -1;
    }

    while (total < resplen - 1) {
        got = recv(s, resp + total, resplen - 1 - total, 0);
        if (got <= 0) break;
        total += got;
    }
    resp[total] = '\0';
    close(s);

    return total;
}

/* ------------------------------------------------------------------ */
/* Attestation flow                                                    */
/* ------------------------------------------------------------------ */

static void print_detection(const struct hwinfo *hw)
{
    int i;
    printf("RustChain Cobalt Qube 3 Miner v" MINER_VERSION "\n");
    printf("  CPU:       %s\n", hw->cpu);
    printf("  Vendor:    %s (family %d)\n", hw->vendor, hw->cpu_family);
    printf("  Family:    %s  arch: %s  machine: %s\n",
           hw->family, hw->arch, hw->machine);
    printf("  TSC:       %s   hypervisor flag: %s\n",
           hw->has_tsc ? "yes" : "no", hw->has_hypervisor ? "YES (VM!)" : "no");
    printf("  CPU sig:   %s\n", hw->cpu_sig);
    printf("  Memory:    %lu KB\n", hw->mem_kb);
    printf("  Hostname:  %s\n", hw->hostname);
    printf("  MACs:      ");
    if (hw->mac_count == 0) printf("(none found)");
    for (i = 0; i < hw->mac_count; i++)
        printf("%s%s", i ? ", " : "", hw->macs[i]);
    printf("\n");
}

static void print_timing(const struct entropy_info *e)
{
    char mean_s[24], stdev_s[24], drift_s[24];

    printf("  Timing:    %s (%s)\n", e->timing_source,
           e->timer_ok ? "timer ok" : "timer failed");
    printf("  Mean ns:   %s  stdev: %s  drift stdev: %s\n",
           u64s(e->mean_ns, mean_s), u64s(e->stdev_ns, stdev_s),
           u64s(e->drift_stdev_ns, drift_s));
}

static int attest_once(const char *host, int port,
                       const char *wallet, const char *miner_id,
                       const struct hwinfo *hw, int force_loop_timing)
{
    static char resp[RESP_MAX];
    static char payload[PAYLOAD_MAX];
    char nonce[160];
    struct entropy_info ent;
    int n, status;

    printf("[ATTEST] requesting challenge from %s:%d\n", host, port);
    n = http_request(host, port, "/attest/challenge", "{}", resp, sizeof(resp));
    if (n <= 0) return 0;

    status = http_status(resp);
    if (status != 200) {
        printf("[FAIL] challenge HTTP %d\n", status);
        return 0;
    }
    if (!json_find_string(resp, "nonce", nonce, sizeof(nonce))) {
        printf("[FAIL] no nonce in challenge response\n");
        return 0;
    }
    printf("[OK] got nonce\n");

    collect_entropy(&ent, hw->has_tsc && !force_loop_timing);
    if (build_payload(payload, sizeof(payload), hw, wallet, miner_id,
                      nonce, &ent) < 0) {
        printf("[FAIL] payload too large\n");
        return 0;
    }

    printf("[ATTEST] submitting (%d bytes)\n", (int)strlen(payload));
    n = http_request(host, port, "/attest/submit", payload, resp, sizeof(resp));
    if (n <= 0) return 0;

    status = http_status(resp);
    if (status == 200 && strstr(resp, "\"ok\"")) {
        char ticket[64];
        printf("[PASS] attestation accepted\n");
        if (json_find_string(resp, "ticket_id", ticket, sizeof(ticket)))
            printf("       ticket: %s\n", ticket);
        if (strstr(resp, "\"fingerprint_passed\":false") ||
            strstr(resp, "\"fingerprint_passed\": false"))
            printf("       flagged: fingerprint failed, minimal reward\n");
        return 1;
    }

    printf("[FAIL] submit HTTP %d\n", status);
    {
        const char *body = strstr(resp, "\r\n\r\n");
        if (body) {
            char snip[201];
            strncpy(snip, body + 4, 200);
            snip[200] = '\0';
            printf("       %s\n", snip);
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* self-test (math + payload, runs on any host)                        */
/* ------------------------------------------------------------------ */

static int selftest(void)
{
    char hex[41];
    int fails = 0;

    printf("SHA-1 vectors:\n");
    sha1_hex((const unsigned char *)"", 0, hex);
    if (strcmp(hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709")) { printf("  FAIL empty\n"); fails++; }
    sha1_hex((const unsigned char *)"abc", 3, hex);
    if (strcmp(hex, "a9993e364706816aba3e25717850c26c9cd0d89d")) { printf("  FAIL abc\n"); fails++; }
    sha1_hex((const unsigned char *)"The quick brown fox jumps over the lazy dog", 43, hex);
    if (strcmp(hex, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12")) { printf("  FAIL fox\n"); fails++; }

    printf("isqrt64:\n");
    if (isqrt64(1000000ULL) != 1000) { printf("  FAIL sqrt(1e6)\n"); fails++; }
    if (isqrt64(17179869184ULL) != 131072ULL) { printf("  FAIL sqrt(2^34)\n"); fails++; }

    printf("entropy stats (fixed samples):\n");
    {
        struct entropy_info e;
        int k;
        memset(&e, 0, sizeof(e));
        e.sample_count = ENT_SAMPLES;
        e.timer_ok = 1;
        strcpy(e.timing_source, "rdtsc");
        for (k = 0; k < ENT_SAMPLES; k++)
            e.samples_ns[k] = (k % 2) ? 1200000UL : 700000UL;
        entropy_compute_stats(&e);
        if (e.mean_ns != 950000ULL) { printf("  FAIL mean\n"); fails++; }
        if (e.stdev_ns != 250000ULL) { printf("  FAIL stdev\n"); fails++; }
        if (e.cv_ppm != 263157ULL) { printf("  FAIL cv\n"); fails++; }
        if (!clock_drift_passed(&e)) { printf("  FAIL drift-pass\n"); fails++; }
    }

    printf("payload build + forced loop timing:\n");
    {
        struct hwinfo hw;
        struct entropy_info e;
        static char payload[PAYLOAD_MAX];
        int plen, depth = 0, instr = 0, i, bad = 0;

        memset(&hw, 0, sizeof(hw));
        strcpy(hw.family, "x86"); strcpy(hw.arch, "retro");
        strcpy(hw.machine, "i586"); strcpy(hw.cpu, "AMD-K6(tm) 3D processor");
        strcpy(hw.vendor, "AuthenticAMD"); hw.cpu_family = 5; hw.has_tsc = 1;
        hw.cores = 1; hw.mem_kb = 262144; strcpy(hw.hostname, "qube3");
        strcpy(hw.cpu_sig, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        strcpy(hw.macs[0], "00:10:e0:12:34:56"); hw.mac_count = 1;

        memset(&e, 0, sizeof(e));
        e.sample_count = ENT_SAMPLES; e.timer_ok = 1;
        strcpy(e.timing_source, "rdtsc");
        for (i = 0; i < ENT_SAMPLES; i++) e.samples_ns[i] = (i % 2) ? 445000UL : 440000UL;
        entropy_compute_stats(&e);

        plen = build_payload(payload, sizeof(payload), &hw,
                             "cobalt-qube3-scott", "cobalt-qube3-scott",
                             "cafebabe1234", &e);
        if (plen <= 0) { printf("  FAIL payload build\n"); fails++; }
        if (!strstr(payload, "\"family\":\"x86\"")) { printf("  FAIL family\n"); fails++; }
        if (!strstr(payload, "\"arch\":\"retro\"")) { printf("  FAIL arch\n"); fails++; }
        if (!strstr(payload, "\"macs\":[\"00:10:e0:12:34:56\"]")) { printf("  FAIL macs\n"); fails++; }
        if (!strstr(payload, "\"timer_source\":\"rdtsc\"")) { printf("  FAIL timer\n"); fails++; }
        if (!strstr(payload, "\"timing_source\":\"rdtsc\"")) { printf("  FAIL RDTSC source\n"); fails++; }
        if (strstr(payload, ":-")) { printf("  FAIL negative number\n"); fails++; }

        collect_entropy(&e, 0);
        if (strcmp(e.timing_source, "loop") != 0) { printf("  FAIL loop select\n"); fails++; }
        if (!e.timer_ok || e.mean_ns == 0) { printf("  FAIL loop timer\n"); fails++; }
        plen = build_payload(payload, sizeof(payload), &hw,
                             "cobalt-qube3-scott", "cobalt-qube3-scott",
                             "cafebabe1234", &e);
        if (plen <= 0) { printf("  FAIL loop payload build\n"); fails++; }
        if (!strstr(payload, "\"timer_source\":\"loop\"")) { printf("  FAIL legacy loop source\n"); fails++; }
        if (!strstr(payload, "\"timing_source\":\"loop\"")) { printf("  FAIL loop source\n"); fails++; }
        if (strstr(payload, "\"timing_source\":\"rdtsc\"")) { printf("  FAIL loop masquerade\n"); fails++; }

        for (i = 0; i < plen; i++) {
            char ch = payload[i];
            if (instr) { if (ch == '\\') i++; else if (ch == '"') instr = 0; }
            else {
                if (ch == '"') instr = 1;
                else if (ch == '{') depth++;
                else if (ch == '}') depth--;
                if (depth < 0) bad = 1;
            }
        }
        if (depth != 0 || bad || instr) { printf("  FAIL brace balance\n"); fails++; }

        if (!fails) { printf("\nsample payload:\n%s\n\n", payload); }
    }

    printf("%s (%d failures)\n", fails ? "SELF-TEST FAILED" : "ALL CHECKS PASSED", fails);
    return fails ? 20 : 0;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    struct hwinfo hw;
    char host[128];
    int port = DEFAULT_NODE_PORT;
    char wallet[96];
    int test_only = 0, dry_run = 0, once = 0, self_test = 0;
    int force_loop_timing = 0;
    int i;

    strcpy(host, DEFAULT_NODE_HOST);
    strcpy(wallet, DEFAULT_WALLET);

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--test-only") == 0) test_only = 1;
        else if (strcmp(argv[i], "--dry-run") == 0) dry_run = 1;
        else if (strcmp(argv[i], "--self-test") == 0) self_test = 1;
        else if (strcmp(argv[i], "--force-loop-timing") == 0) force_loop_timing = 1;
        else if (strcmp(argv[i], "--once") == 0) once = 1;
        else if (strcmp(argv[i], "--node") == 0 && i + 1 < argc) {
            char *colon;
            strncpy(host, argv[++i], sizeof(host) - 1);
            host[sizeof(host) - 1] = '\0';
            colon = strchr(host, ':');
            if (colon) { *colon = '\0'; port = atoi(colon + 1); }
        }
        else if (strcmp(argv[i], "--wallet") == 0 && i + 1 < argc) {
            strncpy(wallet, argv[++i], sizeof(wallet) - 1);
            wallet[sizeof(wallet) - 1] = '\0';
        }
        else {
            printf("usage: rustchain_cobalt [--test-only] [--dry-run] [--self-test]\n");
            printf("                        [--force-loop-timing] [--once]\n");
            printf("                        [--node host:port] [--wallet id]\n");
            return 5;
        }
    }

    if (self_test)
        return selftest();

    detect_hardware(&hw);
    print_detection(&hw);

    if (test_only) {
        struct entropy_info ent;
        collect_entropy(&ent, hw.has_tsc && !force_loop_timing);
        print_timing(&ent);
        return ent.timer_ok ? 0 : 10;
    }

    if (dry_run) {
        static char payload[PAYLOAD_MAX];
        struct entropy_info ent;
        collect_entropy(&ent, hw.has_tsc && !force_loop_timing);
        if (build_payload(payload, sizeof(payload), &hw, wallet, wallet,
                          "dry-run-nonce", &ent) < 0) {
            printf("[FAIL] payload too large\n");
            return 10;
        }
        printf("--- payload for POST http://%s:%d/attest/submit ---\n", host, port);
        printf("%s\n", payload);
        return 0;
    }

    for (;;) {
        attest_once(host, port, wallet, wallet, &hw, force_loop_timing);
        if (once)
            break;
        printf("[SLEEP] next attestation in %d minutes\n", POLL_SECONDS / 60);
        sleep(POLL_SECONDS);
    }

    return 0;
}
