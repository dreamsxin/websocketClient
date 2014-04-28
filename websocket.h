/* 
 * File:   websocket.h
 * Author: sundq
 *
 * Created on 2014-4-1, 10:26
 */

#ifndef WEBSOCKET_H
#define	WEBSOCKET_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "util.h"
    
#define _free(p) do{free(p);p=NULL;}while(0)
    
typedef struct
{
    char scheme[8];
    char path[1024];
    char query[1024];
    char hostname[128];
    unsigned int port;
} url_t;

typedef enum
{
    OPCODE_CONT = 0x0,
    OPCODE_TEXT = 0x1,
    OPCODE_BINARY = 0x2,
    OPCODE_CLOSE = 0x8,
    OPCODE_PING = 0x9,
    OPCODE_PONG = 0xa
} opcode_t;

typedef enum
{
    STATUS_NORMAL = 1000,
    STATUS_GOING_AWAY = 1001,
    STATUS_PROTOCOL_ERROR = 1002,
    STATUS_UNSUPPORTED_DATA_TYPE = 1003,
    STATUS_STATUS_NOT_AVAILABLE = 1005,
    STATUS_ABNORMAL_CLOSED = 1006,
    STATUS_INVALID_PAYLOAD = 1007,
    STATUS_POLICY_VIOLATION = 1008,
    STATUS_MESSAGE_TOO_BIG = 1009,
    STATUS_INVALID_EXTENSION = 1010,
    STATUS_UNEXPECTED_CONDITION = 1011,
    STATUS_TLS_HANDSHAKE_ERROR = 1015
} close_code_t;

typedef enum
{
    //data length threashold.
    LENGTH_7 = 0x7d,
    LENGTH_16 = (1 << 16)
} threshold_t;

typedef struct
{
    int fin;
    int rsv1;
    int rsv2;
    int rsv3;
    int mask;
    int opcode;
    char *data;
    uint64_t length;
} ANBF_t;

typedef struct
{
    uint32_t fd;
    char *recv_buff;
    char *cont_data;
    int32_t cont_data_size;

} wsContext_t;

int32_t recvData(wsContext_t *ctx,void *buff, int32_t len);
int32_t sendBinary(wsContext_t *ctx,void *payload, int32_t len);
int32_t sendUtf8Data(wsContext_t *ctx,void *payload, int32_t len);
int32_t sendCloseing(wsContext_t *ctx,uint16_t status, const char *reason);
int32_t sendPing(wsContext_t *ctx,void *payload, int32_t len);
int32_t sendPong(wsContext_t *ctx,void *payload, int32_t len);
int32_t wsCreateConnection(wsContext_t  *ctx, const char *url);
wsContext_t *wsContextNew();
int32_t wsContextFree(wsContext_t *ctx);

#ifdef	__cplusplus
}
#endif

#endif	/* WEBSOCKET_H */

