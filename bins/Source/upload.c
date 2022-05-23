#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <spng.h>

char v2a(int c)
{
    const char hex[] = "0123456789abcdef";
    return hex[c];
}

char *hexlify(char *bstr, int length) {
    char *hstr=malloc((length*2)+1);
    bzero(hstr,(length*2)+1);
    char *phstr=hstr;
    for(int i=0; i<length;i++) {
        *phstr++ =v2a((bstr[i]>>4)&0x0F);
        *phstr++ =v2a((bstr[i])&0x0F);
    }
    *phstr++ ='\0';
    return hstr;
}

#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>

#define SHA256_BLOCK_SIZE 32

typedef unsigned char BYTE;
typedef unsigned int  WORD;

typedef struct {
	BYTE data[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[8];
} SHA256_CTX;

#endif

#include <stdlib.h>
#include <memory.h>

#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const WORD k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void sha256_transform(SHA256_CTX *ctx, const BYTE data[])
{
	WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for ( ; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len)
{
	WORD i;

	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			sha256_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

void sha256_final(SHA256_CTX *ctx, BYTE hash[])
{
	WORD i;

	i = ctx->datalen;

	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		sha256_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	sha256_transform(ctx, ctx->data);

	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};


char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = malloc(*output_length);
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}


unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length) {

    if (decoding_table == NULL) build_decoding_table();

    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char *decoded_data = malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}


void build_decoding_table() {

    decoding_table = malloc(256);

    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}


void base64_cleanup() {
    free(decoding_table);
}

int main(int argc, char* argv[]){
	int endian = 1;
	int test_n = -2147483648;
	char* test_c = &test_n;
	if (test_c[0] == 1){
		endian = 0;
	} //检测大端序或小端序 1是小端序
	/*
	如果是大端序, -2147483648的储存方式是10000000 00000000 00000000 00000000
	如果是小端序, -2147483648的储存方式是00000000 00000000 00000000 10000000
	*/
	int ll;
	scanf("%d", &ll); //输入获取消息长度
	char* inDat = calloc(sizeof(char)*(ll)+1, 1);
	scanf(" %s", inDat); //输入获取图片(base64)
	long long fsize;
	long long bsize;
	unsigned char* ImageRaw = base64_decode(inDat, ll, &fsize); //图片
	spng_ctx *ctx = spng_ctx_new(0);
	spng_set_png_buffer(ctx, ImageRaw, fsize); //加载进library
	long long out_size = 0;
	spng_decoded_image_size(ctx, SPNG_FMT_RGBA8, &out_size); //buffer大小
	unsigned char* out = malloc(out_size);
	struct spng_ihdr ihdr;
	spng_decode_image(ctx, (void*)out, out_size, SPNG_FMT_RGBA8, 0); //存进buffer
	spng_get_ihdr(ctx, &ihdr); //获取header长度信息
	unsigned int width = out_size/4/ihdr.height; //宽(注:如果不是有效png的话idhr.height会是0 就会出arithmeticerror
	unsigned int height = ihdr.height;
	unsigned char* buff_img = calloc(sizeof(char)*(width*height*4+8), 1); //初始化pixel array
	/*
	(0, 0), (0, 1), (0, 2), ...(1, 0), (1, 1), (1, 2)...
	*/
	*((unsigned int*) buff_img) = width;
	*((unsigned int*) (buff_img + 4)) = height;
	if (endian){ //小端序转大端序 (交换1,4和2,3字节)
		char tmp2 = buff_img[3];
		buff_img[3] = buff_img[0];
		buff_img[0] = tmp2;
		tmp2 = buff_img[2];
		buff_img[2] = buff_img[1];
		buff_img[1] = tmp2;
		tmp2 = buff_img[7];
		buff_img[7] = buff_img[4];
		buff_img[4] = tmp2;
		tmp2 = buff_img[6];
		buff_img[6] = buff_img[5];
		buff_img[5] = tmp2;
	}
	for (unsigned int x = 0; x < width; x++){
		for (unsigned int y = 0; y < height; y++){
			unsigned char* offset = buff_img + ((y + x * height) * 4 + 8);
			buff_img[(y+x*height)*4+8] = out[(width*y+x)*4+3];
			buff_img[(y+x*height)*4+9] = out[(width*y+x)*4+3]==0 ? 0 : out[(width*y+x)*4+0];
			buff_img[(y+x*height)*4+10] = out[(width*y+x)*4+3]==0 ? 0 : out[(width*y+x)*4+1];
			buff_img[(y+x*height)*4+11] = out[(width*y+x)*4+3]==0 ? 0 : out[(width*y+x)*4+2];
		}
	}
	/*
	在第(y+x*height)*4+8的位置填入以下信息
	该pixel的ARGB
	如果alpha=0则rgb全部视为0
	*/
	spng_ctx_free(ctx);
	SHA256_CTX ct;
	BYTE buf[SHA256_BLOCK_SIZE]; //初始化SHA256 buffer
	sha256_init(&ct);
	sha256_update(&ct, buff_img, width*height*4+8); //填充资料 (sha256)
	sha256_final(&ct, buf);
	char* out_print = hexlify(buf, 32); //转换成hex
	printf("%s", out_print);
	free(ImageRaw);
	return 0;
}