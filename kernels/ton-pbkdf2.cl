// SHA512 compression adapted from ton-vanity-cuda, commit d2fdc46fe2f1f7718fa0efea57078170c5170083.
#define SHA512_ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

// compression function over 16 big-endian message words
inline void sha512_transform_words(ulong st[8], const ulong m[16]) {
    const ulong K[80] = {
        0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
        0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
        0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
        0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
        0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
        0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
        0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
        0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
        0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
        0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
        0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
        0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
        0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
        0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
        0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
        0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
        0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
        0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
        0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
        0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL,
    };
    ulong w[16];

    #pragma unroll

    for (int i = 0; i < 16; i++) w[i] = m[i];

    ulong a = st[0], b = st[1], c = st[2], d = st[3];
    ulong e = st[4], f = st[5], g = st[6], h = st[7];


    #pragma unroll

    for (int i = 0; i < 80; i++) {
        if (i >= 16) {   // extend the schedule in place: w[i&15] becomes W[i]
            ulong x15 = w[(i + 1) & 15], x2 = w[(i + 14) & 15];
            ulong s0 = SHA512_ROTR(x15, 1) ^ SHA512_ROTR(x15, 8) ^ (x15 >> 7);
            ulong s1 = SHA512_ROTR(x2, 19) ^ SHA512_ROTR(x2, 61) ^ (x2 >> 6);
            w[i & 15] += s0 + w[(i + 9) & 15] + s1;
        }
        ulong S1 = SHA512_ROTR(e, 14) ^ SHA512_ROTR(e, 18) ^ SHA512_ROTR(e, 41);
        ulong ch = (e & f) ^ (~e & g);
        ulong temp1 = h + S1 + ch + K[i] + w[i & 15];
        ulong S0 = SHA512_ROTR(a, 28) ^ SHA512_ROTR(a, 34) ^ SHA512_ROTR(a, 39);
        ulong maj = (a & b) ^ (a & c) ^ (b & c);
        ulong temp2 = S0 + maj;

        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
    st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

inline void sha512_init_state(ulong st[8]) {
    st[0] = 0x6a09e667f3bcc908UL;
    st[1] = 0xbb67ae8584caa73bUL;
    st[2] = 0x3c6ef372fe94f82bUL;
    st[3] = 0xa54ff53a5f1d36f1UL;
    st[4] = 0x510e527fade682d1UL;
    st[5] = 0x9b05688c2b3e6c1fUL;
    st[6] = 0x1f83d9abfb41bd6bUL;
    st[7] = 0x5be0cd19137e2179UL;
}


inline void hmac_digest(const ulong ist[8], const ulong ost[8], const ulong msg[8], ulong out[8]) {
    ulong m[16], st[8];
    #pragma unroll
    for (int j=0;j<8;j++) { m[j]=msg[j]; st[j]=ist[j]; }
    m[8]=0x8000000000000000UL;
    #pragma unroll
    for (int j=9;j<15;j++) m[j]=0;
    m[15]=1536;
    sha512_transform_words(st,m);
    #pragma unroll
    for (int j=0;j<8;j++) { m[j]=st[j]; out[j]=ost[j]; }
    sha512_transform_words(out,m);
}
__kernel void init_pbkdf(__global const ulong *keys, __global const uchar *salt, uint saltlen,
                         __global ulong *states, uint n, uint key_words) {
    uint id=get_global_id(0); if(id>=n) return;
    ulong ist[8],ost[8],m[16],u[8];
    sha512_init_state(ist); sha512_init_state(ost);
    #pragma unroll
    for(int j=0;j<16;j++) m[j]=(j<key_words?keys[id*key_words+j]:0UL)^0x3636363636363636UL;
    sha512_transform_words(ist,m);
    #pragma unroll
    for(int j=0;j<16;j++) m[j]^=0x3636363636363636UL^0x5c5c5c5c5c5c5c5cUL;
    sha512_transform_words(ost,m);
    #pragma unroll
    for(int j=0;j<16;j++) m[j]=0;
    for(uint j=0;j<saltlen;j++) m[j/8]|=((ulong)salt[j])<<(56-8*(j%8));
    uint end=saltlen+3;
    m[end/8]|=1UL<<(56-8*(end%8));
    end++;
    m[end/8]|=0x80UL<<(56-8*(end%8));
    m[15]=(128UL+saltlen+4)*8;
    ulong st[8];
    #pragma unroll
    for(int j=0;j<8;j++) st[j]=ist[j];
    sha512_transform_words(st,m);
    #pragma unroll
    for(int j=0;j<8;j++) { m[j]=st[j]; u[j]=ost[j]; }
    m[8]=0x8000000000000000UL;
    #pragma unroll
    for(int j=9;j<15;j++) m[j]=0;
    m[15]=1536;
    sha512_transform_words(u,m);
    #pragma unroll
    for(int j=0;j<8;j++) {
        states[(j+0)*n+id]=ist[j]; states[(j+8)*n+id]=ost[j];
        states[(j+16)*n+id]=u[j]; states[(j+24)*n+id]=u[j];
    }
}
__kernel void loop_pbkdf(__global ulong *states, uint n, uint iterations) {
    uint id=get_global_id(0); if(id>=n) return;
    ulong ist[8],ost[8],u[8],t[8];
    #pragma unroll
    for(int j=0;j<8;j++) {
        ist[j]=states[j*n+id]; ost[j]=states[(j+8)*n+id];
        u[j]=states[(j+16)*n+id]; t[j]=states[(j+24)*n+id];
    }
    for(uint c=0;c<iterations;c++) {
        hmac_digest(ist,ost,u,u);
        #pragma unroll
        for(int j=0;j<8;j++) t[j]^=u[j];
    }
    #pragma unroll
    for(int j=0;j<8;j++) { states[(j+16)*n+id]=u[j]; states[(j+24)*n+id]=t[j]; }
}
__kernel void result_pbkdf(__global const ulong *states, uint n, __global ulong *out) {
    uint id=get_global_id(0); if(id>=n) return;
    #pragma unroll
    for(int j=0;j<8;j++) out[id*8+j]=states[(j+24)*n+id];
}

// CSPRNG indices are supplied by the host. Phrase construction and the native
// TON HMAC-SHA512(phrase, empty) run on GPU; no candidate phrase is persisted.
__kernel void mnemonic_entropy(__global const ushort *indices, __global const uchar *words,
                                __global ulong *keys, uint n) {
    uint id=get_global_id(0); if(id>=n) return;
    uchar phrase[256], key[128];
    uint length=0;
    for(int i=0;i<24;i++) {
        if(i) phrase[length++]=32;
        uint index=indices[id*24+i]&2047;
        for(int j=0;j<8;j++) {
            uchar c=words[index*9+j]; if(!c) break;
            phrase[length++]=c;
        }
    }
    for(int j=0;j<128;j++) key[j]=0;
    ulong st[8],m[16];
    if(length>128) {
        sha512_init_state(st);
        uint offset=0;
        while(length-offset>=128) {
            for(int j=0;j<16;j++) {
                m[j]=0;
                for(int k=0;k<8;k++) m[j]=(m[j]<<8)|phrase[offset+j*8+k];
            }
            sha512_transform_words(st,m); offset+=128;
        }
        for(int j=0;j<16;j++) m[j]=0;
        uint rem=length-offset;
        for(uint j=0;j<rem;j++) m[j/8]|=((ulong)phrase[offset+j])<<(56-8*(j%8));
        m[rem/8]|=0x80UL<<(56-8*(rem%8));
        if(rem>=112) {
            sha512_transform_words(st,m);
            for(int j=0;j<16;j++) m[j]=0;
        }
        m[15]=length*8UL;
        sha512_transform_words(st,m);
        for(int j=0;j<64;j++) key[j]=(uchar)(st[j/8]>>(56-8*(j%8)));
    } else {
        for(uint j=0;j<length;j++) key[j]=phrase[j];
    }
    ulong ost[8];
    sha512_init_state(st); sha512_init_state(ost);
    for(int j=0;j<16;j++) {
        m[j]=0;
        for(int k=0;k<8;k++) m[j]=(m[j]<<8)|key[j*8+k];
        m[j]^=0x3636363636363636UL;
    }
    sha512_transform_words(st,m);
    for(int j=0;j<16;j++) m[j]^=0x3636363636363636UL^0x5c5c5c5c5c5c5c5cUL;
    sha512_transform_words(ost,m);
    for(int j=0;j<16;j++) m[j]=0;
    m[0]=0x8000000000000000UL; m[15]=1024;
    sha512_transform_words(st,m);
    for(int j=0;j<8;j++) m[j]=st[j];
    m[8]=0x8000000000000000UL;
    for(int j=9;j<15;j++) m[j]=0;
    m[15]=1536;
    sha512_transform_words(ost,m);
    for(int j=0;j<8;j++) keys[id*8+j]=ost[j];
}

__kernel void gather_entropy(__global const ulong *keys, __global const uint *indices,
                             __global ulong *out, uint n) {
    uint id=get_global_id(0); if(id>=n) return;
    for(int j=0;j<8;j++) out[id*8+j]=keys[indices[id]*8+j];
}

inline void hmac_short(const ulong key[16], const ulong msg[16], uint length, ulong out[8]) {
    ulong m[16],ist[8],ost[8];
    sha512_init_state(ist);sha512_init_state(ost);
    for(int j=0;j<16;j++) m[j]=key[j]^0x3636363636363636UL;
    sha512_transform_words(ist,m);
    for(int j=0;j<16;j++) m[j]^=0x3636363636363636UL^0x5c5c5c5c5c5c5c5cUL;
    sha512_transform_words(ost,m);
    for(int j=0;j<16;j++) m[j]=msg[j];
    m[length/8]|=0x80UL<<(56-8*(length%8));m[15]=(128UL+length)*8;
    sha512_transform_words(ist,m);
    for(int j=0;j<8;j++) m[j]=ist[j];
    m[8]=0x8000000000000000UL;
    for(int j=9;j<15;j++) m[j]=0;
    m[15]=1536;
    for(int j=0;j<8;j++) out[j]=ost[j];
    sha512_transform_words(out,m);
}
__kernel void slip10_ton(__global const ulong *seeds, __global uchar *private_keys, uint n) {
    uint id=get_global_id(0);if(id>=n)return;
    ulong key[16],msg[16],value[8];
    for(int j=0;j<16;j++){key[j]=0;msg[j]=0;}
    key[0]=0x6564323535313920UL;key[1]=0x7365656400000000UL;
    for(int j=0;j<8;j++) msg[j]=seeds[id*8+j];
    hmac_short(key,msg,64,value);
    const uint path[3]={0x8000002cU,0x8000025fU,0x80000000U};
    for(int level=0;level<3;level++) {
        for(int j=0;j<16;j++){key[j]=0;msg[j]=0;}
        for(int j=0;j<4;j++)key[j]=value[j+4];
        for(int j=0;j<32;j++){
            uint dest=j+1;
            ulong b=(value[j/8]>>(56-8*(j%8)))&255;
            msg[dest/8]|=b<<(56-8*(dest%8));
        }
        for(int j=0;j<4;j++){
            uint dest=j+33;
            ulong b=(path[level]>>(24-8*j))&255;
            msg[dest/8]|=b<<(56-8*(dest%8));
        }
        hmac_short(key,msg,37,value);
    }
    for(int j=0;j<32;j++)private_keys[id*32+j]=(uchar)(value[j/8]>>(56-8*(j%8)));
}
