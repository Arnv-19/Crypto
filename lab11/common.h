#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

#define MSG_REQ_TGT 1
#define MSG_RES_TGT 2
#define MSG_REQ_SRV 3
#define MSG_RES_SRV 4

typedef struct {
    int type;
    char client_id[16];
} MsgReqTgt;

typedef struct {
    int type;
    uint8_t enc_session_key[2];
    uint8_t enc_token[32];
    int token_len;
} MsgResTgt;

typedef struct {
    int type;
    uint8_t enc_token[32];
    int token_len;
    uint8_t enc_authenticator[32];
    int auth_len;
} MsgReqSrv;

typedef struct {
    int type;
    int status; // 1 = ALLOWED, 0 = DENIED
} MsgResSrv;

#endif
