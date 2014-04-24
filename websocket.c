#include "websocket.h"

static wsContext_t ctx;

static url_t *_parse_url(const char *url, url_t *ret)
{
    char buff[256] = {0};
    int iret = sscanf(url, "%[^://]%*c%*c%*c%[^:]%*c%d/%[^?]%*c%s", ret->scheme, ret->hostname, &ret->port, ret->path, ret->query);
    if (2 == iret)
    {
        iret = sscanf(url, "%[^://]%*c%*c%*c%[^/]/%[^?]%*c%s", ret->scheme, ret->hostname, ret->path, ret->query);
        ret->port = 80;
    }
    sprintf(buff, "/%s", ret->path);
    sprintf(ret->path, "%s", buff);
    return ret;
}

static int32_t _recv_line(int32_t fd, char *buff)
{
    int32_t i = 0;
    int32_t iret = 0;
    char c = 0;
    while ('\n' != c)
    {
        iret = recv(fd, &c, 1, 0);
        if (iret < 0)
        {
            return iret;
        }
        buff[i++] = c;
    }

    return i - 1;
}

static int32_t _validate_headers(int32_t fd)
{
    char buff[256] = {0};
    while (strcmp(buff, "\r\n") != 0)
    {
        memset(buff, 0, 256);
        if (_recv_line(fd, buff) < 0)
        {
            return -1;
        }
    }

    return 0;
}

static int32_t _handshake(int32_t fd, const char *host, unsigned short port, const char *resource)
{
    int offset = 0;
    char *header_str = malloc(512);
    memset(header_str, 0, 512);
    offset += sprintf(header_str + offset, "GET %s HTTP/1.1\r\n", resource);
    offset += sprintf(header_str + offset, "Upgrade: websocket\r\n");
    offset += sprintf(header_str + offset, "Connection: Upgrade\r\n");
    offset += sprintf(header_str + offset, "Host: %s:%u\r\n", host, port);
    offset += sprintf(header_str + offset, "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n");
    offset += sprintf(header_str + offset, "Sec-WebSocket-Version: 13\r\n\r\n");

    send(fd, header_str, offset, 0);
    return _validate_headers(fd);
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

static void *_format_frame(ANBF_t *frame, int32_t *size)
{
    int offset = 0;
    char *frame_header = NULL;
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

    frame_header = (char *) malloc(sizeof (header) + byteLen + (uint32_t) frame->length);
    header = htons(header);
    memcpy(frame_header + offset, &header, sizeof (header));
    offset += sizeof (header);
    if (byteLen == 2)
    {
        uint16_t len = htons((uint16_t) frame->length);
        memcpy(frame_header + offset, &len, sizeof (len));
        offset += sizeof (len);
    }
    else if (byteLen == 8)
    {
        uint64_t len = htonll(frame->length);
        memcpy(frame_header + offset, &len, sizeof (len));
        offset += sizeof (len);
    }
    memcpy(frame_header + offset, frame->data, (uint32_t) frame->length);
    *size = offset + (uint32_t) frame->length;
    return frame_header;
}

static void *_ANBFmask(uint32_t mask_key, void *data, int32_t len)
{
    int32_t i = 0;
    uint8_t *_m = (uint8_t *) & mask_key;
    uint8_t *_d = (uint8_t *) data;
    for (; i < len; i++)
    {
        _d[i] ^= _m[i % 4];
    }
    return _d;
}

static int32_t _recv_restrict(int32_t fd, void *buff, int32_t size)
{
    int32_t offset = 0;
    int iret = 0;
    while (offset < size)
    {
        iret = recv(fd, ((char *) buff) + offset, (int32_t) (size - offset), 0);
        if (iret > 0)
        {
            offset += iret;
        }
        else
        {
            offset = -1;
            break;
        }
    }

    return offset;
}

static ANBF_t *_recv_frame(int32_t fd)
{
    uint8_t b1, b2, fin, rsv1, rsv2, rsv3, opcode, has_mask;
    uint64_t frame_length = 0;
    uint16_t length_data_16 = 0;
    uint64_t length_data_64 = 0;
    uint32_t frame_mask = 0;
    uint8_t length_bits = 0;
    uint8_t frame_header[2] = {0};
    int32_t iret = 0;
    char *payload = NULL;

    iret = _recv_restrict(fd, &frame_header, 2);
    if (iret < 0)
    {
        goto failed;
    }

    b1 = frame_header[0];
    b2 = frame_header[1];
    length_bits = b2 & 0x7f;
    fin = b1 >> 7 & 1;
    rsv1 = b1 >> 6 & 1;
    rsv2 = b1 >> 5 & 1;
    rsv3 = b1 >> 4 & 1;
    opcode = b1 & 0xf;
    has_mask = b2 >> 7 & 1;

    if (length_bits == 0x7e)
    {
        iret = _recv_restrict(fd, &length_data_16, 2);
        if (iret < 0)
        {
            goto failed;
        }

        frame_length = ntohs(length_data_16);
    }
    else if (length_bits == 0x7f)
    {
        iret = _recv_restrict(fd, &length_data_64, 8);
        if (iret < 0)
        {
            goto failed;
        }

        frame_length = ntohll(length_data_64);
    }
    else
    {
        frame_length = length_bits;
    }

    if (has_mask)
    {
        iret = _recv_restrict(fd, &frame_mask, 4);
        if (iret < 0)
        {
            goto failed;
        }
    }

    if (frame_length > 0)
    {
        payload = (char *) malloc((int32_t) frame_length);
        iret = _recv_restrict(fd, payload, (int32_t) frame_length);
        if (iret < 0)
        {
            goto failed;
        }
    }

    if (has_mask)
    {
        _ANBFmask(frame_mask, payload, (uint32_t) frame_length);
    }

    return _create_frame(fin, rsv1, rsv2, rsv3, opcode, has_mask, payload, (uint32_t) frame_length);

failed:
    return NULL;
}

static int32_t _send(int32_t fd, void *payload, int32_t len, int32_t opcode)
{
    int32_t length = 0;
    ANBF_t *frame = _create_frame(1, 0, 0, 0, opcode, 0, payload, len);
    char *data = (char *) _format_frame(frame, &length);
    int32_t iret = send(fd, data, length, 0);
    free(frame);
    free(data);

    return iret;
}

int32_t sendPing(wsContext_t *ctx, void *payload, int32_t len)
{
    return _send(ctx->fd, payload, len, OPCODE_PING);
}

int32_t sendPong(wsContext_t *ctx, void *payload, int32_t len)
{
    return _send(ctx->fd, payload, len, OPCODE_PONG);
}

int32_t sendCloseing(wsContext_t *ctx, uint16_t status, const char *reason)
{
    char *p = NULL;
    int len = 0;
    char payload[64] = {0};
    status = htons(status);
    p = (char *) &status;
    len = snprintf(payload, 64, "\\x%02x\\x%02x%s", p[0], p[1], reason);
    return _send(ctx->fd, payload, len, OPCODE_CLOSE);
}

int32_t recvData(wsContext_t *ctx, void *buff, int32_t len)
{
    int data_len = 0;
    ANBF_t *frame = NULL;

    while (1)
    {
        frame = _recv_frame(ctx->fd);
        if (!frame)
        {
            goto failed;
        }

        if (frame->opcode == OPCODE_TEXT || frame->opcode == OPCODE_BINARY || frame->opcode == OPCODE_CONT)
        {
            if (frame->opcode == OPCODE_CONT && NULL == ctx->cont_data)
            {
                goto failed;
            }
            else if (ctx->cont_data)
            {
                ctx->cont_data = (char *) realloc(ctx->cont_data, ctx->cont_data_size + (uint32_t) frame->length);
                memcpy(ctx->cont_data + ctx->cont_data_size, frame->data, (uint32_t) frame->length);
                ctx->cont_data_size += (uint32_t) frame->length;
                free(frame->data);
            }
            else
            {
                ctx->cont_data = frame->data;
                ctx->cont_data_size = (uint32_t) frame->length;
            }

            if (frame->fin)
            {
                data_len = ctx->cont_data_size > len ? len : ctx->cont_data_size;
                memcpy(buff, ctx->cont_data, data_len);
                free(ctx->cont_data);
                ctx->cont_data = NULL;
                ctx->cont_data_size = 0;
                free(frame);
                return data_len;
            }
            free(frame);
        }
        else if (frame->opcode == OPCODE_CLOSE)
        {
            free(frame);
            sendCloseing(ctx, STATUS_NORMAL, "");
            close(ctx->fd);
            goto failed;
        }
        else if (frame->opcode == OPCODE_PING)
        {
            free(frame);
            sendPong(ctx, "", 0);
        }
        else
        {
            free(frame);
            goto failed;
        }
    }

failed:
    return -1;
}

int32_t sendUtf8Data(wsContext_t *ctx, void *data, int32_t len)
{
    return _send(ctx->fd, data, len, OPCODE_TEXT);
}

int32_t sendBinary(wsContext_t *ctx, void *data, int32_t len)
{
    return _send(ctx->fd, data, len, OPCODE_BINARY);
}

int32_t wsCreateConnection(wsContext_t *ctx, const char *url)
{
    url_t purl = {0};
    _parse_url(url, &purl);
    ctx->fd = ut_connect(purl.hostname, purl.port);
    _handshake(ctx->fd, purl.hostname, purl.port, purl.path);

    return ctx->fd;
}

wsContext_t *wsContextNew(wsContext_t *ctx)
{
    if (!ctx)
    {
        ctx = (wsContext_t *) malloc(sizeof (wsContext_t));
    }
    memset(ctx, 0, sizeof (wsContext_t));

    return ctx;
}

int32_t wsContextFree(wsContext_t *ctx)
{
    close(ctx->fd);
    free(ctx);
    return 0;
}
