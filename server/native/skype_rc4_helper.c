#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

int debuglog(const char *format, ...)
{
    return 0;
}

#include "../../skypeopensource2/goodsendrelay4_dll/goodsendrelay4_dll/skype/skype_rc4.c"

static uint32_t read_u32_be(const unsigned char *data)
{
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           (uint32_t)data[3];
}

static void write_u32_be(unsigned char *data, uint32_t value)
{
    data[0] = (unsigned char)(value >> 24);
    data[1] = (unsigned char)(value >> 16);
    data[2] = (unsigned char)(value >> 8);
    data[3] = (unsigned char)value;
}

static void write_u16_be(unsigned char *data, uint16_t value)
{
    data[0] = (unsigned char)(value >> 8);
    data[1] = (unsigned char)value;
}

typedef struct skype_rc4_session
{
    RC4_context send;
    RC4_context recv;
    int send_ready;
    int recv_ready;
} skype_rc4_session;

static int make_server_handshake_with_context(
    RC4_context *rc4,
    const unsigned char *shared_secret,
    int shared_secret_len,
    uint32_t iv,
    uint16_t sequence,
    int garbage_len,
    unsigned char *output,
    int output_capacity)
{
    int packet_len;

    if (!shared_secret || shared_secret_len < 48 || !output || !rc4)
    {
        return -1;
    }

    if (garbage_len < 4)
    {
        garbage_len = 4;
    }
    else if (garbage_len > 48)
    {
        garbage_len = 48;
    }

    packet_len = garbage_len + 16;
    if (output_capacity < packet_len)
    {
        return -2;
    }

    memset(output, 0, packet_len);
    write_u32_be(output, iv);
    write_u16_be(output + 4, sequence);

    output[6] = 0x00;
    output[7] = 0x00;
    output[8] = 0x00;
    output[9] = 0x01;
    output[10] = 0x00;
    output[11] = 0x00;
    output[12] = 0x00;
    output[13] = 0x03;

    output[14] = (unsigned char)((garbage_len + 1) * 2 + 1);
    output[15] = 0x03;

    memset(rc4, 0, sizeof(*rc4));
    Skype_RC4_Expand_IV(iv, shared_secret, rc4, 1, 48);
    RC4_crypt(output + 4, 10, rc4, 1);
    RC4_crypt(output + 14, (uint32_t)(garbage_len + 2), rc4, 0);

    return packet_len;
}

static int decrypt_client_handshake_with_context(
    RC4_context *rc4,
    const unsigned char *shared_secret,
    int shared_secret_len,
    const unsigned char *packet,
    int packet_len,
    unsigned char *output,
    int output_capacity)
{
    uint32_t iv;
    int remaining;

    if (!shared_secret || shared_secret_len < 48 || !packet || packet_len < 16 || !output || !rc4)
    {
        return -1;
    }

    if (output_capacity < packet_len)
    {
        return -2;
    }

    memcpy(output, packet, packet_len);
    iv = read_u32_be(output);
    memset(rc4, 0, sizeof(*rc4));
    Skype_RC4_Expand_IV(iv, shared_secret, rc4, 1, 48);
    RC4_crypt(output + 4, 10, rc4, 1);
    remaining = packet_len - 14;
    if (remaining > 0)
    {
        RC4_crypt(output + 14, (uint32_t)remaining, rc4, 0);
    }

    return packet_len;
}

__declspec(dllexport) int __stdcall skype_make_server_handshake(
    const unsigned char *shared_secret,
    int shared_secret_len,
    uint32_t iv,
    uint16_t sequence,
    int garbage_len,
    unsigned char *output,
    int output_capacity)
{
    int packet_len;

    RC4_context rc4;
    packet_len = make_server_handshake_with_context(&rc4, shared_secret, shared_secret_len, iv, sequence, garbage_len, output, output_capacity);
    return packet_len;
}

__declspec(dllexport) int __stdcall skype_probe_decrypt_handshake(
    const unsigned char *shared_secret,
    int shared_secret_len,
    const unsigned char *packet,
    int packet_len,
    unsigned char *output,
    int output_capacity)
{
    RC4_context rc4;
    return decrypt_client_handshake_with_context(&rc4, shared_secret, shared_secret_len, packet, packet_len, output, output_capacity);
}

__declspec(dllexport) void * __stdcall skype_session_create(void)
{
    skype_rc4_session *session = (skype_rc4_session *)malloc(sizeof(skype_rc4_session));
    if (!session)
    {
        return 0;
    }

    memset(session, 0, sizeof(*session));
    return session;
}

__declspec(dllexport) void __stdcall skype_session_free(void *session)
{
    if (session)
    {
        free(session);
    }
}

__declspec(dllexport) int __stdcall skype_session_make_server_handshake(
    void *session_ptr,
    const unsigned char *shared_secret,
    int shared_secret_len,
    uint32_t iv,
    uint16_t sequence,
    int garbage_len,
    unsigned char *output,
    int output_capacity)
{
    skype_rc4_session *session = (skype_rc4_session *)session_ptr;
    int result;

    if (!session)
    {
        return -3;
    }

    result = make_server_handshake_with_context(&session->send, shared_secret, shared_secret_len, iv, sequence, garbage_len, output, output_capacity);
    if (result > 0)
    {
        session->send_ready = 1;
    }

    return result;
}

__declspec(dllexport) int __stdcall skype_session_decrypt_client_handshake(
    void *session_ptr,
    const unsigned char *shared_secret,
    int shared_secret_len,
    const unsigned char *packet,
    int packet_len,
    unsigned char *output,
    int output_capacity)
{
    skype_rc4_session *session = (skype_rc4_session *)session_ptr;
    int result;

    if (!session)
    {
        return -3;
    }

    result = decrypt_client_handshake_with_context(&session->recv, shared_secret, shared_secret_len, packet, packet_len, output, output_capacity);
    if (result > 0)
    {
        session->recv_ready = 1;
    }

    return result;
}

__declspec(dllexport) int __stdcall skype_session_decrypt_from_client(
    void *session_ptr,
    const unsigned char *packet,
    int packet_len,
    unsigned char *output,
    int output_capacity)
{
    skype_rc4_session *session = (skype_rc4_session *)session_ptr;

    if (!session || !session->recv_ready)
    {
        return -3;
    }

    if (!packet || packet_len < 0 || !output || output_capacity < packet_len)
    {
        return -1;
    }

    memcpy(output, packet, packet_len);
    RC4_crypt(output, (uint32_t)packet_len, &session->recv, 0);
    return packet_len;
}

__declspec(dllexport) int __stdcall skype_session_encrypt_to_client(
    void *session_ptr,
    const unsigned char *packet,
    int packet_len,
    unsigned char *output,
    int output_capacity)
{
    skype_rc4_session *session = (skype_rc4_session *)session_ptr;

    if (!session || !session->send_ready)
    {
        return -3;
    }

    if (!packet || packet_len < 0 || !output || output_capacity < packet_len)
    {
        return -1;
    }

    memcpy(output, packet, packet_len);
    RC4_crypt(output, (uint32_t)packet_len, &session->send, 0);
    return packet_len;
}

__declspec(dllexport) int __stdcall skype_udp_crypt(
    uint32_t iv,
    const unsigned char *input,
    int input_len,
    unsigned char *output,
    int output_capacity)
{
    RC4_context rc4;

    if (!input || input_len < 0 || !output || output_capacity < input_len)
    {
        return -1;
    }

    memcpy(output, input, input_len);
    memset(&rc4, 0, sizeof(rc4));
    Skype_RC4_Expand_IV_udp(&rc4, iv, 1);
    RC4_crypt(output, (uint32_t)input_len, &rc4, 0);
    return input_len;
}
