websocketClient
===============

a websocket client by C language


##Usage

```c
#include <stdio.h>
#include <stdlib.h>
#include "websocket.h"

int main()
{ 
    char *str = "hello websocket\n";
    wsContext_t *ctx = NULL;
    ctx = wsContextNew(NULL);
    wsCreateConnection(ctx,"ws://10.0.0.150:1238/");
    sendUtf8Data(ctx,str,strlen(str));
    while(1)
    {
        int len =  recvData(ctx,buff, 1*1024*1024);
        if(len)
        {
           fprintf(stderr,"recv ok %d\n",len);
        }
        
        if(len < 0)
        {
           break;
        }
    }    
    return 0;
}
```