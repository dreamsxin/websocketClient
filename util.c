#include "util.h"

static int _addr_binary_set_port(struct sockaddr_storage *in, uint16_t port)
{
    if (in->ss_family == AF_INET)
    {
        struct sockaddr_in *addr4 = (struct sockaddr_in *) in;
        addr4->sin_port = port;
    }
    else if (in->ss_family == AF_INET6)
    {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) in;
        addr6->sin6_port = port;
    }
    else
    {
        return -1;
    }

    return -1;
}

static int _get_addr_by_hostname(int domain, int socktype, const char *hostname, uint16_t port, struct sockaddr_storage *out, uint32_t *size)
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

int ut_connect(const char *hostname, uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_storage addr_remote = {0};
    uint32_t addr_len = 0;
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