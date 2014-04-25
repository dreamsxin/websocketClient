#include "util.h"

static const char b64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char reverse_table[128] = {
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64
};

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
/* FIXME: can we do this in an endian-proof way? */
#ifdef WORDS_BIGENDIAN
#define blk0(i) block->l[i]
#else
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) \
    |(rol(block->l[i],8)&0x00FF00FF))
#endif
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
    ^block->l[(i+2)&15]^block->l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);

uint8_t *base64_encode(uint8_t *bindata, int32_t inlen, uint8_t *out, int32_t *outlen)
{
    int32_t _outlen = *outlen;
    uint8_t *_out = NULL;
    int32_t out_pos = 0;
    uint32_t bits_collected = 0;
    uint32_t accumulator = 0;
    int i = 0;

    _outlen = (inlen / 3 + (inlen % 3 != 0)) * 4 + 1;
    _out = out;

    memset(_out, '=', _outlen);
    _out[_outlen - 1] = 0;

    for (i = 0; i < inlen; i++)
    {
        accumulator = (accumulator << 8) | (bindata[i] & 0xffu);
        bits_collected += 8;
        while (bits_collected >= 6)
        {
            bits_collected -= 6;
            _out[out_pos++] = b64_table[(accumulator >> bits_collected) & 0x3fu];
        }
    }

    if (bits_collected >= 6)
    {
        if (NULL == *out)
        {
            free(_out);
        }
        return NULL;
    }

    if (bits_collected > 0)
    {
        // Any trailing bits that are missing.
        accumulator <<= 6 - bits_collected;
        _out[out_pos++] = b64_table[accumulator & 0x3fu];
    }

    *outlen = _outlen;
    return _out;
}

uint8_t *base64_decode(uint8_t *bindata, int32_t inlen, uint8_t **out, int32_t *outlen)
{
    int32_t _outlen = *outlen;
    uint8_t *_out = NULL;
    int32_t bits_collected = 0;
    uint32_t accumulator = 0;
    int32_t out_pos = 0;
    int32_t c = 0;
    int32_t i = 0;

    if (NULL == *out)
    {
        _outlen = inlen;
        _out = (unsigned char *) malloc(_outlen);
    }
    else
    {
        _outlen = *outlen;
        _out = *out;
    }

    memset(_out, 0, _outlen);

    for (i = 0; i < inlen; i++)
    {
        c = bindata[i];
        if (isspace(c) || c == '=')
        {
            // Skip whitespace and padding. Be liberal in what you accept.
            continue;
        }
        if ((c > 127) || (c < 0) || (reverse_table[c] > 63))
        {
            return NULL;
        }
        accumulator = (accumulator << 6) | reverse_table[c];
        bits_collected += 6;
        if (bits_collected >= 8)
        {
            bits_collected -= 8;
            _out[out_pos++] = (char) ((accumulator >> bits_collected) & 0xffu);
        }
    }

    *outlen = out_pos;
    *out = _out;
    return _out;
}

/* Hash a single 512-bit block. This is the core of the algorithm. */
static void _SHA1_Transform(uint32_t state[5], const uint8_t buffer[64])
{
    uint32_t a, b, c, d, e;

    typedef union
    {
        uint8_t c[64];
        uint32_t l[16];
    } CHAR64LONG16;
    CHAR64LONG16* block;

    block = (CHAR64LONG16*) buffer;

    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a, b, c, d, e, 0);
    R0(e, a, b, c, d, 1);
    R0(d, e, a, b, c, 2);
    R0(c, d, e, a, b, 3);
    R0(b, c, d, e, a, 4);
    R0(a, b, c, d, e, 5);
    R0(e, a, b, c, d, 6);
    R0(d, e, a, b, c, 7);
    R0(c, d, e, a, b, 8);
    R0(b, c, d, e, a, 9);
    R0(a, b, c, d, e, 10);
    R0(e, a, b, c, d, 11);
    R0(d, e, a, b, c, 12);
    R0(c, d, e, a, b, 13);
    R0(b, c, d, e, a, 14);
    R0(a, b, c, d, e, 15);
    R1(e, a, b, c, d, 16);
    R1(d, e, a, b, c, 17);
    R1(c, d, e, a, b, 18);
    R1(b, c, d, e, a, 19);
    R2(a, b, c, d, e, 20);
    R2(e, a, b, c, d, 21);
    R2(d, e, a, b, c, 22);
    R2(c, d, e, a, b, 23);
    R2(b, c, d, e, a, 24);
    R2(a, b, c, d, e, 25);
    R2(e, a, b, c, d, 26);
    R2(d, e, a, b, c, 27);
    R2(c, d, e, a, b, 28);
    R2(b, c, d, e, a, 29);
    R2(a, b, c, d, e, 30);
    R2(e, a, b, c, d, 31);
    R2(d, e, a, b, c, 32);
    R2(c, d, e, a, b, 33);
    R2(b, c, d, e, a, 34);
    R2(a, b, c, d, e, 35);
    R2(e, a, b, c, d, 36);
    R2(d, e, a, b, c, 37);
    R2(c, d, e, a, b, 38);
    R2(b, c, d, e, a, 39);
    R3(a, b, c, d, e, 40);
    R3(e, a, b, c, d, 41);
    R3(d, e, a, b, c, 42);
    R3(c, d, e, a, b, 43);
    R3(b, c, d, e, a, 44);
    R3(a, b, c, d, e, 45);
    R3(e, a, b, c, d, 46);
    R3(d, e, a, b, c, 47);
    R3(c, d, e, a, b, 48);
    R3(b, c, d, e, a, 49);
    R3(a, b, c, d, e, 50);
    R3(e, a, b, c, d, 51);
    R3(d, e, a, b, c, 52);
    R3(c, d, e, a, b, 53);
    R3(b, c, d, e, a, 54);
    R3(a, b, c, d, e, 55);
    R3(e, a, b, c, d, 56);
    R3(d, e, a, b, c, 57);
    R3(c, d, e, a, b, 58);
    R3(b, c, d, e, a, 59);
    R4(a, b, c, d, e, 60);
    R4(e, a, b, c, d, 61);
    R4(d, e, a, b, c, 62);
    R4(c, d, e, a, b, 63);
    R4(b, c, d, e, a, 64);
    R4(a, b, c, d, e, 65);
    R4(e, a, b, c, d, 66);
    R4(d, e, a, b, c, 67);
    R4(c, d, e, a, b, 68);
    R4(b, c, d, e, a, 69);
    R4(a, b, c, d, e, 70);
    R4(e, a, b, c, d, 71);
    R4(d, e, a, b, c, 72);
    R4(c, d, e, a, b, 73);
    R4(b, c, d, e, a, 74);
    R4(a, b, c, d, e, 75);
    R4(e, a, b, c, d, 76);
    R4(d, e, a, b, c, 77);
    R4(c, d, e, a, b, 78);
    R4(b, c, d, e, a, 79);

    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;

    /* Wipe variables */
    a = b = c = d = e = 0;
}

/* SHA1Init - Initialize new context */
void sha1Init(SHA1_CTX* context)
{
    /* SHA1 initialization constants */
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}

/* Run your data through this. */
void sha1Update(SHA1_CTX* context, const uint8_t* data, const size_t len)
{
    size_t i, j;

    j = (context->count[0] >> 3) & 63;
    if ((context->count[0] += len << 3) < (len << 3)) context->count[1]++;
    context->count[1] += (len >> 29);
    if ((j + len) > 63)
    {
        memcpy(&context->buffer[j], data, (i = 64 - j));
        _SHA1_Transform(context->state, context->buffer);
        for (; i + 63 < len; i += 64)
        {
            _SHA1_Transform(context->state, data + i);
        }
        j = 0;
    }
    else i = 0;
    memcpy(&context->buffer[j], &data[i], len - i);
}

/* Add padding and return the message digest. */
void sha1Final(SHA1_CTX* context, uint8_t digest[SHA1_DIGEST_SIZE])
{
    uint32_t i;
    uint8_t finalcount[8];

    for (i = 0; i < 8; i++)
    {
        finalcount[i] = (unsigned char) ((context->count[(i >= 4 ? 0 : 1)]
                                          >> ((3 - (i & 3)) * 8)) & 255); /* Endian independent */
    }
    sha1Update(context, (uint8_t *) "\200", 1);
    while ((context->count[0] & 504) != 448)
    {
        sha1Update(context, (uint8_t *) "\0", 1);
    }
    sha1Update(context, finalcount, 8); /* Should cause a SHA1_Transform() */
    for (i = 0; i < SHA1_DIGEST_SIZE; i++)
    {
        digest[i] = (uint8_t)
                ((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }

    /* Wipe variables */
    i = 0;
    memset(context->buffer, 0, 64);
    memset(context->state, 0, 20);
    memset(context->count, 0, 8);
    memset(finalcount, 0, 8); /* SWR */
}

uint8_t *digest_to_hex(const uint8_t digest[SHA1_DIGEST_SIZE], uint8_t *output)
{
    int i = 0;
    int len = 0;
    char *c = (char *) output;

    for (i = 0; i < SHA1_DIGEST_SIZE; i++)
    {
        len += sprintf(c + len, "%02x", digest[i]);
    }

    return output;
}

uint8_t *sha1BuffHex(const void *buff, size_t lenth, uint8_t *out)
{
    uint8_t digest[SHA1_DIGEST_SIZE] = {0};
    SHA1_CTX context;
    sha1Init(&context);
    sha1Update(&context, (uint8_t*) buff, lenth);
    sha1Final(&context, digest);
    return digest_to_hex(digest, out);
}

uint8_t *sha1Buff(const void *buff, size_t lenth, uint8_t *out)
{
    uint8_t digest[SHA1_DIGEST_SIZE] = {0};
    SHA1_CTX context;
    sha1Init(&context);
    sha1Update(&context, (uint8_t*) buff, lenth);
    sha1Final(&context, digest);
    memcpy(out, digest, SHA1_DIGEST_SIZE);
    return out;
}

uint8_t *sha1File(char *filename, uint8_t* out)
{
    uint8_t digest[20] = {0};
    FILE *inFile = fopen(filename, "rb");
    SHA1_CTX mdContext;
    int bytes;
    unsigned char data[1024];

    if (inFile == NULL)
    {
        return NULL;
    }

    sha1Init(&mdContext);
    while ((bytes = fread(data, 1, 1024, inFile)) != 0)
    {
        sha1Update(&mdContext, data, bytes);
    }
    sha1Final(&mdContext, digest);
    fclose(inFile);
    return digest_to_hex(digest, out);
}

static int _get_addr_by_hostname(int32_t domain, int32_t socktype, const char *hostname, uint16_t port, struct sockaddr_storage *out, int32_t *size)
{
    int iret = -1;
    char sport[16] = {0};
    struct addrinfo hints = {0};
    struct addrinfo *result = NULL;
    hints.ai_family = domain; /* Allow IPv4 or IPv6 */
    hints.ai_socktype = socktype; /* Datagram/Stream socket */
    hints.ai_flags = AI_ALL | AI_CANONNAME | AI_PASSIVE;
    hints.ai_protocol = 0;

    snprintf(sport, 16, "%d", (int) port);
    iret = getaddrinfo(hostname, sport, &hints, &result);
    if (iret != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(iret));
        return -1;
    }
    else
    {
        memcpy(out, result->ai_addr, result->ai_addrlen);
        *size = result->ai_addrlen;
    }
    freeaddrinfo(result);
    return iret;
}

int32_t ut_connect(const char *hostname, uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_storage addr_remote = {0};
    int32_t addr_len = 0;
    int iret = _get_addr_by_hostname(AF_INET, SOCK_STREAM, hostname, port, &addr_remote, &addr_len);
    if (iret >= 0)
    {
        if (connect(fd, (struct sockaddr *) &addr_remote, addr_len) < 0)
        {
            perror("connect:");
            return -1;
        }
        else
        {
            return fd;
        }
    }
    else
    {
        return -1;
    }
}

#ifndef _WIN32

uint64_t ntohll(uint64_t val)
{
    if (__BYTE_ORDER == __LITTLE_ENDIAN)
    {
        return (((uint64_t) htonl((int) ((val << 32) >> 32))) << 32) | (uint32_t) htonl((int) (val >> 32));
    }
    else if (__BYTE_ORDER == __BIG_ENDIAN)
    {
        return val;
    }
}

uint64_t htonll(uint64_t val)
{
    if (__BYTE_ORDER == __LITTLE_ENDIAN)
    {
        return (((uint64_t) htonl((int) ((val << 32) >> 32))) << 32) | (uint32_t) htonl((int) (val >> 32));
    }
    else if (__BYTE_ORDER == __BIG_ENDIAN)
    {
        return val;
    }
}
#endif

char *str2lower(char *str)
{
    char *p = str;
    while (*p)
    {
        if (*p >= 65 && *p <= 90)
        {
            *p += 32;
        }
        p++;
    }

    return str;
}