#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>

#pragma comment(lib,"ws2_32.lib")

/* -------- SDES TABLES -------- */
int P10[]={3,5,2,7,4,10,1,9,8,6};
int P8[]={6,3,7,4,8,5,10,9};
int IP[]={2,6,3,1,4,8,5,7};
int IP_INV[]={4,1,3,5,7,2,8,6};
int EP[]={4,1,2,3,2,3,4,1};
int P4[]={2,4,3,1};

int S0[4][4]={{1,0,3,2},{3,2,1,0},{0,2,1,3},{3,1,3,2}};
int S1[4][4]={{0,1,2,3},{2,0,1,3},{3,0,1,0},{2,1,0,3}};

/* -------- SDES FUNCTIONS -------- */
void perm(int *in,int *out,int *p,int n){
    for(int i=0;i<n;i++) out[i]=in[p[i]-1];
}
void lshift(int *a){
    int t=a[0];
    for(int i=0;i<4;i++) a[i]=a[i+1];
    a[4]=t;
}
void keygen(int *k,int *k1,int *k2){
    int p10[10],l[5],r[5],tmp[10];
    perm(k,p10,P10,10);
    memcpy(l,p10,5*sizeof(int));
    memcpy(r,p10+5,5*sizeof(int));

    lshift(l); lshift(r);
    memcpy(tmp,l,5*sizeof(int));
    memcpy(tmp+5,r,5*sizeof(int));
    perm(tmp,k1,P8,8);

    lshift(l); lshift(l);
    lshift(r); lshift(r);
    memcpy(tmp,l,5*sizeof(int));
    memcpy(tmp+5,r,5*sizeof(int));
    perm(tmp,k2,P8,8);
}
void fk(int *b,int *k){
    int l[4],r[4],ep[8],p4res[4];
    memcpy(l,b,4*sizeof(int));
    memcpy(r,b+4,4*sizeof(int));

    perm(r,ep,EP,8);
    for(int i=0;i<8;i++) ep[i]^=k[i];

    int r0=(ep[0]<<1)|ep[3], c0=(ep[1]<<1)|ep[2];
    int r1=(ep[4]<<1)|ep[7], c1=(ep[5]<<1)|ep[6];

    int s[4]={
        (S0[r0][c0]>>1)&1, S0[r0][c0]&1,
        (S1[r1][c1]>>1)&1, S1[r1][c1]&1
    };

    perm(s,p4res,P4,4);
    for(int i=0;i<4;i++) b[i]=l[i]^p4res[i];
}
void encrypt(int *pt,int *k,int *ct){
    int k1[8],k2[8],ip[8];
    keygen(k,k1,k2);
    perm(pt,ip,IP,8);
    fk(ip,k1);
    for(int i=0;i<4;i++){ int t=ip[i]; ip[i]=ip[i+4]; ip[i+4]=t; }
    fk(ip,k2);
    perm(ip,ct,IP_INV,8);
}

/* -------- MAIN -------- */
int main(){
    int key[10];
    char plaintext[256];

    printf("Enter 10-bit key: ");
    for(int i=0;i<10;i++) scanf("%1d",&key[i]);

    printf("Enter plaintext bits: ");
    scanf("%s", plaintext);

    int bitlen = strlen(plaintext);
    int blocks = (bitlen + 7) / 8;

    int ciphertext[blocks][8];

    for(int b=0;b<blocks;b++){
        int pt[8]={0};
        for(int i=0;i<8;i++){
            int idx = b*8 + i;
            if(idx < bitlen)
                pt[i] = plaintext[idx] - '0';
        }
        encrypt(pt,key,ciphertext[b]);
    }

    WSADATA w;
    WSAStartup(MAKEWORD(2,2), &w);
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in srv;
    srv.sin_family = AF_INET;
    srv.sin_port = htons(8080);
    srv.sin_addr.s_addr = inet_addr("127.0.0.1");

    connect(s,(struct sockaddr*)&srv,sizeof(srv));

    send(s,(char*)&blocks,sizeof(int),0);
    send(s,(char*)&bitlen,sizeof(int),0);
    send(s,(char*)ciphertext,sizeof(ciphertext),0);

    closesocket(s);
    WSACleanup();

    printf("Ciphertext sent successfully\n");
    return 0;
}
