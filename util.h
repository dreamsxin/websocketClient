/* 
 * File:   util.h
 * Author: sundq
 *
 * Created on 2014年4月23日, 下午1:33
 */

#ifndef UTIL_H
#define	UTIL_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>  
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include <netdb.h>

uint64_t ntohll(uint64_t val);
uint64_t htonll(uint64_t val);
int ut_connect(const char *hostname, uint16_t port);

#ifdef	__cplusplus
}
#endif

#endif	/* UTIL_H */

