#include "websocket.h"
#include "util.h"

static wsContext_t ctx;

url_t *_parse_url(const char *url, url_t *ret)
{
    int iret = sscanf(url, "%[^://]%*c%*c%*c%[^:]%*c%d/%[^?]%*c%s", ret->scheme, ret->hostname, &ret->port, ret->path, ret->query);
    if (2 == iret)
    {
        iret = sscanf(url, "%[^://]%*c%*c%*c%[^/]/%[^?]%*c%s", ret->scheme, ret->hostname, ret->path, ret->query);
        ret->port = 80;
    }

    char buff[256] = {0};
    sprintf(buff, "/%s", ret->path);
    sprintf(ret->path, "%s", buff);
    return ret;
}

static const char *_recv_line(char *buff)
{
    int i = 0;
    char c = 0;
    while ('\n' != c)
    {
        recv(ctx.fd, &c, 1, 0);
        buff[i++] = c;
    }

    return buff;
}

static int _validate_headers()
{
    char buff[256] = {0};
    while (strcmp(buff, "\r\n") != 0)
    {
        puts(buff);
        memset(buff, 0, 256);
        _recv_line(buff);
    }

    return 0;
}

static int _handshake(const char *host, unsigned short port, const char *resource)
{
    int offset = 0;
    char *header_str = calloc(1, 512);
    offset += sprintf(header_str + offset, "GET %s HTTP/1.1\r\n", resource);
    offset += sprintf(header_str + offset, "Upgrade: websocket\r\n");
    offset += sprintf(header_str + offset, "Connection: Upgrade\r\n");
    offset += sprintf(header_str + offset, "Host: %s:%u\r\n", host, port);
    offset += sprintf(header_str + offset, "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n");
    offset += sprintf(header_str + offset, "Sec-WebSocket-Version: 13\r\n\r\n");

    send(ctx.fd, header_str, offset, 0);
    return _validate_headers();
}

static ANBF_t *_create_frame(int fin, int rsv1, int rsv2, int rsv3, int opcode, int has_mask, void *data, int len)
{
    ANBF_t *frame = malloc(sizeof (ANBF_t));

    frame->fin = fin;
    frame->rsv1 = rsv1;
    frame->rsv2 = rsv2;
    frame->rsv3 = rsv3;
    frame->mask = has_mask;
    frame->opcode = opcode;
    frame->data = data;
    frame->length = len;

    return frame;
}

static void *_format_frame(ANBF_t *frame, int *size)
{
    uint16_t header =
            (frame->fin << 15) |
            (frame->rsv1 << 14) |
            (frame->rsv2 << 13) |
            (frame->rsv3 << 12) |
            (frame->opcode << 8);

    char byteLen = 0;
    if (frame->length < LENGTH_7)
    {
        header |= frame->mask << 7 | (uint8_t) frame->length;
    }
    else if (frame->length < LENGTH_16)
    {
        header |= frame->mask << 7 | 0x7e;
        byteLen = 2;
    }
    else
    {
        header |= frame->mask << 7 | 0x7f;
        byteLen = 8;
    }

    int offset = 0;
    char *frame_header = malloc(sizeof (header) + byteLen + frame->length);
    header = htons(header);
    memcpy(frame_header + offset, &header, sizeof (header));
    offset += sizeof (header);
    if (byteLen == 2)
    {
        uint16_t len = htons(frame->length);
        memcpy(frame_header + offset, &len, sizeof (len));
        offset += sizeof (len);
    }
    else if (byteLen == 8)
    {
        uint64_t len = htonll(frame->length);
        memcpy(frame_header + offset, &len, sizeof (len));
        offset += sizeof (len);
    }
    memcpy(frame_header + offset, frame->data, frame->length);
    *size = offset + frame->length;
    return frame_header;
}

static void *_ANBFmask(uint32_t mask_key, void *data, uint32_t len)
{
    int i = 0;
    char *_m = (char *) &mask_key;
    char *_d = (char *) data;
    for (; i < len; i++)
    {
        _d[i] ^= _m[i % 4];
    }
    return _d;
}

static ANBF_t *_recv_frame()
{
    uint8_t frame_header[2] = {0};
    recv(ctx.fd, &frame_header, 2, 0);
    uint8_t b1 = frame_header[0];
    uint8_t b2 = frame_header[1];
    uint8_t fin = b1 >> 7 & 1;
    uint8_t rsv1 = b1 >> 6 & 1;
    uint8_t rsv2 = b1 >> 5 & 1;
    uint8_t rsv3 = b1 >> 4 & 1;
    uint8_t opcode = b1 & 0xf;
    uint8_t has_mask = b2 >> 7 & 1;

    uint64_t frame_length = 0;
    uint16_t length_data = 0;
    uint8_t length_bits = b2 & 0x7f;
    if (length_bits == 0x7e)
    {
        recv(ctx.fd, &length_data, 2, 0);
        frame_length = ntohs(length_data);
    }
    else if (length_bits == 0x7f)
    {
        recv(ctx.fd, &length_data, 8, 0);
        frame_length = ntohll(length_data);
    }
    else
    {
        frame_length = length_bits;
    }

    uint32_t frame_mask = 0;
    if (has_mask)
    {
        recv(ctx.fd, &frame_mask, 4, 0);
    }

    uint8_t *payload = malloc(frame_length);
    recv(ctx.fd, payload, frame_length, 0);
    if (has_mask)
    {
        _ANBFmask(frame_mask, payload, frame_length);
    }

    return _create_frame(fin, rsv1, rsv2, rsv3, opcode, has_mask, payload, frame_length);
}

static int _send(void *payload, int len, int opcode)
{
    int length = 0;
    ANBF_t *frame = _create_frame(1, 0, 0, 0, opcode, 0, payload, len);
    char *data = _format_frame(frame, &length);
    int iret = send(ctx.fd, data, length, 0);
    free(frame);
    free(data);

    return iret;
}

int sendPing(void *payload, int len)
{
    return _send(payload, len, OPCODE_PING);
}

int sendPong(void *payload, int len)
{
    return _send(payload, len, OPCODE_PONG);
}

int sendCloseing(uint16_t status, char *reason)
{
    status = htons(status);
    uint8_t *p = (uint8_t *) & status;
    char payload[64] = {0};
    int len = snprintf(payload, 64, "\\x%02x\\x%02x%s", p[0], p[1], reason);
    return _send(payload, len, OPCODE_CLOSE);
}

int recvData(void *buff, int len)
{
    ANBF_t *frame = _recv_frame();
    if (!frame)
    {
        return 0;
    }

    if (frame->opcode == OPCODE_TEXT || frame->opcode == OPCODE_BINARY || frame->opcode == OPCODE_CONT)
    {
        if (frame->opcode == OPCODE_CONT && NULL == ctx._cont_data)
        {
            return 0;
        }
        else if (ctx._cont_data)
        {
            ctx._cont_data = realloc(ctx._cont_data, ctx._cont_data_size + frame->length);
            ctx._cont_data_size += frame->length;
            memcpy(ctx._cont_data + frame->length, frame->data, frame->length);
        }
        else
        {
            ctx._cont_data = frame->data;
            ctx._cont_data_size = frame->length;
        }

        if (frame->fin)
        {
            int data_len = ctx._cont_data_size > len ? len : ctx._cont_data_size;
            memcpy(buff, ctx._cont_data, data_len);
            ctx._cont_data = NULL;
            ctx._cont_data_size = 0;
            return data_len;
        }
    }
    else if (frame->opcode == OPCODE_CLOSE)
    {
        sendCloseing(STATUS_NORMAL, "");
        return 0;
    }
    else if (frame->opcode == OPCODE_PING)
    {
        sendPong("", 0);
        return 0;
    }

}

int sendUtf8Data(void *data, int len)
{
    return _send(data, len, OPCODE_TEXT);
}

int sendBinary(void *data, int len)
{
    return _send(data, len, OPCODE_BINARY);
}

int wsCreateConnection(const char *url)
{
    url_t purl = {0};
    _parse_url(url, &purl);
    puts(purl.hostname);
    ctx.fd = ut_connect(purl.hostname, purl.port);
    _handshake(purl.hostname, purl.port, purl.path);

    char *str = "{hell:world}";
    char *str1 = "{hell:afdsfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff}";
    sendUtf8Data(str, strlen(str));

    char buff[128] = {0};
    recvData(buff, 128);
    printf("%s\n", buff);

    recvData(buff, 128);
    //    printf("%s\n", buff);
}

//int createWsContext()