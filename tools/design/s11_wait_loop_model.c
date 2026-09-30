/* Model of the intended S1.1 design: cooperative poll of {connection, UDP}
   in short slices, non-blocking reads, absolute deadline. Validated against the
   four failing hostile checks BEFORE porting any of it to LLVM IR. */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>

static int lfd, usock;
static unsigned char pool[16][65536];
static int slot_conn[16], slot_need[16], slot_got[16], slot_active[16];
static int pending = 0;

/* one UDP datagram answered entirely locally (sinkhole-like), no upstream */
static int service_udp(void){
    unsigned char b[4096];
    struct sockaddr_in ca; socklen_t cl = sizeof ca;
    ssize_t n = recvfrom(usock, b, sizeof b, 0, (struct sockaddr*)&ca, &cl);
    if (n < 12) return 0;
    unsigned char out[4096];
    memcpy(out, b, 16);
    out[2] = 0x81; out[3] = 0x80;          /* QR RD RA, rcode 0 */
    out[6] = 0; out[7] = 1; out[8] = 0; out[9] = 0; out[10] = 0; out[11] = 0;
    int i = 12;
    while (i < n && out[i] != 0) i += out[i] + 1;
    int qend = i + 1 + 4;
    memcpy(out + qend, b + qend, 16);
    out[qend] = 0xc0; out[qend+1] = 0x0c;
    out[qend+3] = 0; out[qend+5] = 1;
    out[qend+6] = 0; out[qend+7] = 0; out[qend+8] = 0; out[qend+9] = 0x3c;
    out[qend+10] = 0; out[qend+11] = 4;
    sendto(usock, out, qend + 16, 0, (struct sockaddr*)&ca, 16);
    return 1;
}

static void serve_slot(int s){
    int n = slot_need[s] - slot_got[s];
    ssize_t r = recv(slot_conn[s], pool[s] + slot_got[s], n, 0);
    if (r > 0) slot_got[s] += r;
    if (slot_got[s] >= 2 && slot_need[s] == 2){
        slot_need[s] = 2 + ((pool[s][0] << 8) | pool[s][1]);
        if (slot_need[s] <= 2) slot_need[s] = 0;
    }
    if (slot_need[s] > 0 && slot_got[s] >= slot_need[s]){
        unsigned char out[16];
        memcpy(out, pool[s] + 2, 12);
        write(slot_conn[s], out, 12);
        close(slot_conn[s]);
        slot_active[s] = 0; pending--;
    }
}

static void run(int seconds){
    time_t deadline = time(NULL) + seconds;
    while (time(NULL) < deadline) {
        struct pollfd pf[1 + 16];
        int nf = 0;
        pf[nf].fd = usock; pf[nf].events = POLLIN; pf[nf].revents = 0; nf++;
        int live[16], nl = 0;
        for (int i = 0; i < 16; i++)
            if (slot_active[i]) { pf[nf].fd = slot_conn[i]; pf[nf].events = POLLIN; pf[nf].revents = 0; nf++; live[nl++] = i; }
        poll(pf, nf, 50);
        if (pf[0].revents & POLLIN) service_udp();
        for (int k = 0; k < nl; k++) if (pf[1 + k].revents & POLLIN) serve_slot(live[k]);
    }
}

int main(void){
    int one = 1;
    usock = socket(AF_INET, SOCK_DGRAM, 17);
    struct sockaddr_in la; memset(&la,0,sizeof la);
    la.sin_len=sizeof la; la.sin_family=AF_INET; la.sin_port=htons(15354);
    la.sin_addr.s_addr=htonl(0x7F000001);
    if (bind(usock,(struct sockaddr*)&la,sizeof la)) { perror("bind"); return 1; }
    setsockopt(usock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    lfd = socket(AF_INET, SOCK_STREAM, 6);
    memset(&la,0,sizeof la); la.sin_len=sizeof la; la.sin_family=AF_INET;
    la.sin_port=htons(15355); la.sin_addr.s_addr=htonl(0x7F000001);
    if (bind(lfd,(struct sockaddr*)&la,sizeof la)) { perror("bind tcp"); return 1; }
    listen(lfd, 16);

    pid_t child = fork();
    if (child == 0) {
        /* the "attacker" side: slow-loris, idle-65534, four concurrent */
        struct sockaddr_in d = la;
        for (int i = 0; i < 4; i++){
            int c = socket(AF_INET, SOCK_STREAM, 17);
            if (connect(c,(struct sockaddr*)&d,sizeof d)) continue;
            unsigned char len[2] = {0x02, 0x00};
            send(c,len,2,0);
            if (i == 0){ for (int k=0;k<4;k++){ usleep(900000); send(c,"\0",1,0);} }
            else if (i == 1){ unsigned char big[2] = {0xff,0xde}; send(c,big,2,0); }
            else sleep(20);
        }
        /* probe UDP while all that is in flight */
        sleep(3);
        for (int k = 0; k < 6; k++){
            int u = socket(AF_INET, SOCK_DGRAM, 17);
            struct timeval tv = {2,0};
            setsockopt(u,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
            unsigned char q[64]; int n=0;
            q[n++]=0x12;q[n++]=0x34;q[n++]=1;q[n++]=0;q[n++]=0;q[n++]=1;
            q[n++]=0;q[n++]=0;q[n++]=0;q[n++]=0;q[n++]=0;q[n++]=0;
            q[n++]=12;q[n++]=0; send(u,q,17,0);
            unsigned char r[4096];
            ssize_t got = recv(u,r,sizeof r,0);
            printf("  udp probe %d: %s\n", k, got>0 ? "ANSWERED" : "BLOCKED");
            close(u);
            usleep(400000);
        }
        _exit(0);
    }
    run(6);
    kill(child, 9); waitpid(child, NULL, 0);
    return 0;
}
