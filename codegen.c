#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void mMpswd_make_passcode( unsigned char*, unsigned int, unsigned int, unsigned char*,
                           unsigned char*, unsigned int, unsigned int, unsigned char );
void mMpswd_substitution_cipher( unsigned char* );
void mMpswd_transposition_cipher( unsigned char*, unsigned int, unsigned int );
void mMpswd_bit_shuffle( unsigned char*, unsigned int );
void mMpswd_chg_RSA_cipher( unsigned char* );
void mMpswd_get_RSA_key_code( unsigned short*, unsigned short*,
                              unsigned short*, unsigned char**,
                              unsigned char* );
void mMpswd_bit_mix_code( unsigned char* );
void mMpswd_bit_arrange_reverse( unsigned char* );
void mMpswd_bit_shift( unsigned char*, unsigned int );
void mMpswd_bit_reverse( unsigned char* );
void mMpswd_chg_6bits_code( unsigned char*, unsigned char* );
void mMpswd_chg_common_font_code( unsigned char* );
unsigned int hex2dec( unsigned char* );

unsigned char usable_to_fontnum[64] = {
	0x62, 0x4b, 0x7a, 0x35, 0x63, 0x71, 0x59, 0x5a,
	0x4f, 0x64, 0x74, 0x36, 0x6e, 0x6c, 0x42, 0x79,
	0x6f, 0x38, 0x34, 0x4c, 0x6b, 0x25, 0x41, 0x51,
	0x6d, 0x44, 0x50, 0x49, 0x37, 0x26, 0x52, 0x73,
	0x77, 0x55, 0x23, 0x72, 0x33, 0x45, 0x78, 0x4d,
	0x43, 0x40, 0x65, 0x39, 0x67, 0x76, 0x56, 0x47,
	0x75, 0x4e, 0x69, 0x58, 0x57, 0x66, 0x54, 0x4a,
	0x46, 0x53, 0x48, 0x70, 0x32, 0x61, 0x6a, 0x68 };

unsigned char  mMpswd_select_idx0[8] =  { 0x11, 0x0b, 0x00, 0x0a, 0x0c, 0x06, 0x08, 0x04 };
unsigned char  mMpswd_select_idx1[8] =  { 0x03, 0x08, 0x0b, 0x10, 0x04, 0x06, 0x09, 0x13 };
unsigned char  mMpswd_select_idx2[8] =  { 0x09, 0x0e, 0x11, 0x12, 0x0b, 0x0a, 0x0c, 0x02 };
unsigned char  mMpswd_select_idx3[8] =  { 0x00, 0x02, 0x01, 0x04, 0x12, 0x0a, 0x0c, 0x08 };
unsigned char  mMpswd_select_idx4[8] =  { 0x11, 0x13, 0x10, 0x07, 0x0c, 0x08, 0x02, 0x09 };
unsigned char  mMpswd_select_idx5[8] =  { 0x10, 0x03, 0x01, 0x08, 0x12, 0x04, 0x07, 0x06 };
unsigned char  mMpswd_select_idx6[8] =  { 0x13, 0x06, 0x0a, 0x11, 0x03, 0x10, 0x08, 0x09 };
unsigned char  mMpswd_select_idx7[8] =  { 0x11, 0x07, 0x12, 0x10, 0x0c, 0x02, 0x0b, 0x00 };
unsigned char  mMpswd_select_idx8[8] =  { 0x06, 0x02, 0x0c, 0x01, 0x08, 0x0e, 0x00, 0x10 };
unsigned char  mMpswd_select_idx9[8] =  { 0x13, 0x10, 0x0b, 0x08, 0x11, 0x03, 0x06, 0x0e };
unsigned char  mMpswd_select_idx10[8] = { 0x12, 0x0c, 0x02, 0x07, 0x0a, 0x0b, 0x01, 0x0e };
unsigned char  mMpswd_select_idx11[8] = { 0x08, 0x00, 0x0e, 0x02, 0x07, 0x0b, 0x0c, 0x11 };
unsigned char  mMpswd_select_idx12[8] = { 0x09, 0x03, 0x02, 0x00, 0x0b, 0x08, 0x0e, 0x0a };
unsigned char  mMpswd_select_idx13[8] = { 0x0a, 0x0b, 0x0c, 0x10, 0x13, 0x07, 0x11, 0x08 };
unsigned char  mMpswd_select_idx14[8] = { 0x13, 0x08, 0x06, 0x01, 0x11, 0x09, 0x0e, 0x0a };
unsigned char  mMpswd_select_idx15[8] = { 0x09, 0x07, 0x11, 0x0c, 0x13, 0x0a, 0x01, 0x0b };
unsigned char *mMpswd_select_idx_table[16] = {
	mMpswd_select_idx0,  mMpswd_select_idx1,  mMpswd_select_idx2,  mMpswd_select_idx3,
	mMpswd_select_idx4,  mMpswd_select_idx5,  mMpswd_select_idx6,  mMpswd_select_idx7,
	mMpswd_select_idx8,  mMpswd_select_idx9,  mMpswd_select_idx10, mMpswd_select_idx11,
	mMpswd_select_idx12, mMpswd_select_idx13, mMpswd_select_idx14, mMpswd_select_idx15 };

unsigned short mMpswd_prime_number[256] = {
    0x0011, 0x0013, 0x0017, 0x001d, 0x001f, 0x0025, 0x0029, 0x002b,
    0x002f, 0x0035, 0x003b, 0x003d, 0x0043, 0x0047, 0x0049, 0x004f,
    0x0053, 0x0059, 0x0061, 0x0065, 0x0067, 0x006b, 0x006d, 0x0071,
    0x007f, 0x0083, 0x0089, 0x008b, 0x0095, 0x0097, 0x009d, 0x00a3,
    0x00a7, 0x00ad, 0x00b3, 0x00b5, 0x00bf, 0x00c1, 0x00c5, 0x00c7,
    0x00d3, 0x00df, 0x00e3, 0x00e5, 0x00e9, 0x00ef, 0x00f1, 0x00fb,
    0x0101, 0x0107, 0x010d, 0x010f, 0x0115, 0x0119, 0x011b, 0x0125,
    0x0133, 0x0137, 0x0139, 0x013d, 0x014b, 0x0151, 0x015b, 0x015d,
    0x0161, 0x0167, 0x016f, 0x0175, 0x017b, 0x017f, 0x0185, 0x018d,
    0x0191, 0x0199, 0x01a3, 0x01a5, 0x01af, 0x01b1, 0x01b7, 0x01bb,
    0x01c1, 0x01c9, 0x01cd, 0x01cf, 0x01d3, 0x01df, 0x01e7, 0x01eb,
    0x01f3, 0x01f7, 0x01fd, 0x0209, 0x020b, 0x021d, 0x0223, 0x022d,
    0x0233, 0x0239, 0x023b, 0x0241, 0x024b, 0x0251, 0x0257, 0x0259,
    0x025f, 0x0265, 0x0269, 0x026b, 0x0277, 0x0281, 0x0283, 0x0287,
    0x028d, 0x0293, 0x0295, 0x02a1, 0x02a5, 0x02ab, 0x02b3, 0x02bd,
    0x02c5, 0x02cf, 0x02d7, 0x02dd, 0x02e3, 0x02e7, 0x02ef, 0x02f5,
    0x02f9, 0x0301, 0x0305, 0x0313, 0x031d, 0x0329, 0x032b, 0x0335,
    0x0337, 0x033b, 0x033d, 0x0347, 0x0355, 0x0359, 0x035b, 0x035f,
    0x036d, 0x0371, 0x0373, 0x0377, 0x038b, 0x038f, 0x0397, 0x03a1,
    0x03a9, 0x03ad, 0x03b3, 0x03b9, 0x03c7, 0x03cb, 0x03d1, 0x03d7,
    0x03df, 0x03e5, 0x03f1, 0x03f5, 0x03fb, 0x03fd, 0x0407, 0x0409,
    0x040f, 0x0419, 0x041b, 0x0425, 0x0427, 0x042d, 0x043f, 0x0443,
    0x0445, 0x0449, 0x044f, 0x0455, 0x045d, 0x0463, 0x0469, 0x047f,
    0x0481, 0x048b, 0x0493, 0x049d, 0x04a3, 0x04a9, 0x04b1, 0x04bd,
    0x04c1, 0x04c7, 0x04cd, 0x04cf, 0x04d5, 0x04e1, 0x04eb, 0x04fd,
    0x04ff, 0x0503, 0x0509, 0x050b, 0x0511, 0x0515, 0x0517, 0x051b,
    0x0527, 0x0529, 0x052f, 0x0551, 0x0557, 0x055d, 0x0565, 0x0577,
    0x0581, 0x058f, 0x0593, 0x0595, 0x0599, 0x059f, 0x05a7, 0x05ab,
    0x05ad, 0x05b3, 0x05bf, 0x05c9, 0x05cb, 0x05cf, 0x05d1, 0x05d5,
    0x05db, 0x05e7, 0x05f3, 0x05fb, 0x0607, 0x060d, 0x0611, 0x0617,
    0x061f, 0x0623, 0x062b, 0x062f, 0x063d, 0x0641, 0x0647, 0x0649,
    0x064d, 0x0653, 0x0655, 0x065b, 0x0665, 0x0679, 0x067f, 0x0683 };

unsigned char mMpswd_chg_code_table[256] = {
    0xf0, 0x83, 0xfd, 0x62, 0x93, 0x49, 0x0d, 0x3e, 0xe1, 0xa4, 0x2b, 0xaf, 0x3a, 0x25, 0xd0, 0x82,
    0x7f, 0x97, 0xd2, 0x03, 0xb2, 0x32, 0xb4, 0xe6, 0x09, 0x42, 0x57, 0x27, 0x60, 0xea, 0x76, 0xab,
    0x2d, 0x65, 0xa8, 0x4d, 0x8b, 0x95, 0x01, 0x37, 0x59, 0x79, 0x33, 0xac, 0x2f, 0xae, 0x9f, 0xfe,
    0x56, 0xd9, 0x04, 0xc6, 0xb9, 0x28, 0x06, 0x5c, 0x54, 0x8d, 0xe5, 0x00, 0xb3, 0x7b, 0x5e, 0xa7,
    0x3c, 0x78, 0xcb, 0x2e, 0x6d, 0xe4, 0xe8, 0xdc, 0x40, 0xa0, 0xde, 0x2c, 0xf5, 0x1f, 0xcc, 0x85,
    0x71, 0x3d, 0x26, 0x74, 0x9c, 0x13, 0x7d, 0x7e, 0x66, 0xf2, 0x9e, 0x02, 0xa1, 0x53, 0x15, 0x4f,
    0x51, 0x20, 0xd5, 0x39, 0x1a, 0x67, 0x99, 0x41, 0xc7, 0xc3, 0xa6, 0xc4, 0xbc, 0x38, 0x8c, 0xaa,
    0x81, 0x12, 0xdd, 0x17, 0xb7, 0xef, 0x2a, 0x80, 0x9d, 0x50, 0xdf, 0xcf, 0x89, 0xc8, 0x91, 0x1b,
    0xbb, 0x73, 0xf8, 0x14, 0x61, 0xc2, 0x45, 0xc5, 0x55, 0xfc, 0x8e, 0xe9, 0x8a, 0x46, 0xdb, 0x4e,
    0x05, 0xc1, 0x64, 0xd1, 0xe0, 0x70, 0x16, 0xf9, 0xb6, 0x36, 0x44, 0x8f, 0x0c, 0x29, 0xd3, 0x0e,
    0x6f, 0x7c, 0xd7, 0x4a, 0xff, 0x75, 0x6c, 0x11, 0x10, 0x77, 0x3b, 0x98, 0xba, 0x69, 0x5b, 0xa3,
    0x6a, 0x72, 0x94, 0xd6, 0xd4, 0x22, 0x08, 0x86, 0x31, 0x47, 0xbe, 0x87, 0x63, 0x34, 0x52, 0x3f,
    0x68, 0xf6, 0x0f, 0xbf, 0xeb, 0xc0, 0xce, 0x24, 0xa5, 0x9a, 0x90, 0xed, 0x19, 0xb8, 0xb5, 0x96,
    0xfa, 0x88, 0x6e, 0xfb, 0x84, 0x23, 0x5d, 0xcd, 0xee, 0x92, 0x58, 0x4c, 0x0b, 0xf7, 0x0a, 0xb1,
    0xda, 0x35, 0x5f, 0x9b, 0xc9, 0xa9, 0xe7, 0x07, 0x1d, 0x18, 0xf3, 0xe3, 0xf1, 0xf4, 0xca, 0xb0,
    0x6b, 0x30, 0xec, 0x4b, 0x48, 0x1c, 0xad, 0xe2, 0x21, 0x1e, 0xa2, 0xbd, 0x5a, 0xd8, 0x43, 0x7a };

unsigned char mMpswd_transposition_cipher_char0_0[24] = { 0x4e, 0x69, 0x69, 0x4d, 0x61, 0x73, 0x61, 0x72, 0x75, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char0_1[24] = { 0x4b, 0x6f, 0x6d, 0x61, 0x74, 0x73, 0x75, 0x4b, 0x75, 0x6e, 0x69, 0x68, 0x69, 0x72, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char0_2[24] = { 0x54, 0x61, 0x6b, 0x61, 0x6b, 0x69, 0x47, 0x65, 0x6e, 0x74, 0x61, 0x72, 0x6f, 0x75, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char0_3[24] = { 0x4d, 0x69, 0x79, 0x61, 0x6b, 0x65, 0x48, 0x69, 0x72, 0x6f, 0x6d, 0x69, 0x63, 0x68, 0x69, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char0_4[24] = { 0x48, 0x61, 0x79, 0x61, 0x6b, 0x61, 0x77, 0x61, 0x4b, 0x65, 0x6e, 0x7a, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char0_5[24] = { 0x4b, 0x61, 0x73, 0x61, 0x6d, 0x61, 0x74, 0x73, 0x75, 0x53, 0x68, 0x69, 0x67, 0x65, 0x68, 0x69, 0x72, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char0_6[24] = { 0x53, 0x75, 0x6d, 0x69, 0x79, 0x6f, 0x73, 0x68, 0x69, 0x4e, 0x6f, 0x62, 0x75, 0x68, 0x69, 0x72, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char0_7[24] = { 0x4e, 0x6f, 0x6d, 0x61, 0x54, 0x61, 0x6b, 0x61, 0x66, 0x75, 0x6d, 0x69, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char0_8[24] = { 0x45, 0x67, 0x75, 0x63, 0x68, 0x69, 0x4b, 0x61, 0x74, 0x73, 0x75, 0x79, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char0_9[24] = { 0x4e, 0x6f, 0x67, 0x61, 0x6d, 0x69, 0x48, 0x69, 0x73, 0x61, 0x73, 0x68, 0x69, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char0_10[24] = { 0x49, 0x69, 0x64, 0x61, 0x54, 0x6f, 0x6b, 0x69, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char0_11[24] = { 0x49, 0x6b, 0x65, 0x67, 0x61, 0x77, 0x61, 0x4e, 0x6f, 0x72, 0x69, 0x6b, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char0_12[24] = { 0x4b, 0x61, 0x77, 0x61, 0x73, 0x65, 0x54, 0x6f, 0x6d, 0x6f, 0x68, 0x69, 0x72, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char0_13[24] = { 0x42, 0x61, 0x6e, 0x64, 0x6f, 0x54, 0x61, 0x72, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char0_14[24] = { 0x54, 0x6f, 0x74, 0x61, 0x6b, 0x61, 0x4b, 0x61, 0x7a, 0x75, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char0_15[24] = { 0x57, 0x61, 0x74, 0x61, 0x6e, 0x61, 0x62, 0x65, 0x4b, 0x75, 0x6e, 0x69, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char1_0[24] = { 0x52, 0x69, 0x63, 0x68, 0x41, 0x6d, 0x74, 0x6f, 0x77, 0x65, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char1_1[24] = { 0x4b, 0x79, 0x6c, 0x65, 0x48, 0x75, 0x64, 0x73, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char1_2[24] = { 0x4d, 0x69, 0x63, 0x68, 0x61, 0x65, 0x6c, 0x4b, 0x65, 0x6c, 0x62, 0x61, 0x75, 0x67, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char1_3[24] = { 0x52, 0x61, 0x79, 0x63, 0x68, 0x6f, 0x6c, 0x65, 0x4c, 0x41, 0x6e, 0x65, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char1_4[24] = { 0x4c, 0x65, 0x73, 0x6c, 0x69, 0x65, 0x53, 0x77, 0x61, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char1_5[24] = { 0x59, 0x6f, 0x73, 0x68, 0x69, 0x6e, 0x6f, 0x62, 0x75, 0x4d, 0x61, 0x6e, 0x74, 0x61, 0x6e, 0x69, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char1_6[24] = { 0x4b, 0x69, 0x72, 0x6b, 0x42, 0x75, 0x63, 0x68, 0x61, 0x6e, 0x61, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char1_7[24] = { 0x54, 0x69, 0x6d, 0x4f, 0x4c, 0x65, 0x61, 0x72, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char1_8[24] = { 0x42, 0x69, 0x6c, 0x6c, 0x54, 0x72, 0x69, 0x6e, 0x65, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char1_9[24] = { 0x6e, 0x41, 0x6b, 0x41, 0x79, 0x4f, 0x73, 0x49, 0x6e, 0x6f, 0x4e, 0x79, 0x75, 0x75, 0x53, 0x61, 0x6e, 0x6b, 0x69, 0x6e, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char1_10[24] = { 0x7a, 0x65, 0x6e, 0x64, 0x61, 0x6d, 0x61, 0x4b, 0x49, 0x4e, 0x41, 0x4b, 0x55, 0x44, 0x41, 0x4d, 0x41, 0x6b, 0x69, 0x6e, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char1_11[24] = { 0x4f, 0x69, 0x73, 0x68, 0x69, 0x6b, 0x75, 0x74, 0x65, 0x74, 0x55, 0x59, 0x4f, 0x4b, 0x55, 0x4e, 0x41, 0x52, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char1_12[24] = { 0x41, 0x73, 0x65, 0x74, 0x6f, 0x41, 0x6d, 0x69, 0x6e, 0x6f, 0x66, 0x65, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char1_13[24] = { 0x66, 0x63, 0x53, 0x46, 0x43, 0x6e, 0x36, 0x34, 0x47, 0x43, 0x67, 0x62, 0x43, 0x47, 0x42, 0x61, 0x67, 0x62, 0x56, 0x42, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char1_14[24] = { 0x59, 0x6f, 0x73, 0x73, 0x79, 0x49, 0x73, 0x6c, 0x61, 0x6e, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char mMpswd_transposition_cipher_char1_15[24] = { 0x4b, 0x65, 0x64, 0x61, 0x6d, 0x6f, 0x6e, 0x6f, 0x4e, 0x6f, 0x4d, 0x6f, 0x72, 0x69, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

unsigned char* chg_ptr[32] = {
    mMpswd_transposition_cipher_char0_0, mMpswd_transposition_cipher_char0_1,
    mMpswd_transposition_cipher_char0_2, mMpswd_transposition_cipher_char0_3,
    mMpswd_transposition_cipher_char0_4, mMpswd_transposition_cipher_char0_5,
    mMpswd_transposition_cipher_char0_6, mMpswd_transposition_cipher_char0_7,
    mMpswd_transposition_cipher_char0_8, mMpswd_transposition_cipher_char0_9,
    mMpswd_transposition_cipher_char0_10, mMpswd_transposition_cipher_char0_11,
    mMpswd_transposition_cipher_char0_12, mMpswd_transposition_cipher_char0_13,
    mMpswd_transposition_cipher_char0_14, mMpswd_transposition_cipher_char0_15,
    mMpswd_transposition_cipher_char1_0, mMpswd_transposition_cipher_char1_1,
    mMpswd_transposition_cipher_char1_2, mMpswd_transposition_cipher_char1_3,
    mMpswd_transposition_cipher_char1_4, mMpswd_transposition_cipher_char1_5,
    mMpswd_transposition_cipher_char1_6, mMpswd_transposition_cipher_char1_7,
    mMpswd_transposition_cipher_char1_8, mMpswd_transposition_cipher_char1_9,
    mMpswd_transposition_cipher_char1_10, mMpswd_transposition_cipher_char1_11,
    mMpswd_transposition_cipher_char1_12, mMpswd_transposition_cipher_char1_13,
    mMpswd_transposition_cipher_char1_14, mMpswd_transposition_cipher_char1_15 };

unsigned char chg_len[32] = {
    0x00000009, 0x0000000f, 0x0000000e, 0x0000000f,
    0x0000000d, 0x00000012, 0x00000011, 0x0000000c,
    0x0000000d, 0x0000000d, 0x00000008, 0x0000000d,
    0x0000000e, 0x00000009, 0x0000000b, 0x0000000d,
    0x0000000b, 0x0000000a, 0x0000000f, 0x0000000e,
    0x0000000a, 0x00000010, 0x0000000c, 0x00000009,
    0x0000000a, 0x00000014, 0x00000014, 0x00000013,
    0x0000000d, 0x00000014, 0x0000000b, 0x0000000e };

unsigned int key_idx[2] = { 0x00000012, 0x00000009 };

void DisplayCode( unsigned char *cCode, int nNumChars )
{
    int idx;
    for( idx = 0; idx < nNumChars; idx++ )
    {
        printf( "%02x ", cCode[idx] );
        if( idx == 24 ) { printf( "\n" ); }
    }
    printf( "\n" );
}

int main( int argc, char **argv )
{
	unsigned int idx;
	unsigned char codetype;
	unsigned char townname[10] = { 'N', 'a', 'r', 's', 'h', 'e', ' ', ' ', 0, 0 };
	unsigned char playername[10] = { 'K', 'u', 't', 'a', 'n', ' ', ' ' ,' ', 0, 0 };
	unsigned char passcode[21];
	unsigned char finalcode[28];
	unsigned char itemstr[6] = { 0x31, 0x35, 0x35, 0x34, 0, 0 };
	unsigned int itemnum = 0x1554;

	for( idx = 0; idx < 21; idx++ ) passcode[idx] = 0;
	for( idx = 0; idx < 28; idx++ ) finalcode[idx] = 0;

	if( argc < 5 )
	{
		printf( "Nope, you need to supply a code type, player name, town name, and item number.\n" );
		return 1;
	}

	codetype = argv[1][0] & 0xdf;
    strcpy( playername, argv[2] );
    strcpy( townname, argv[3] );
    strcpy( itemstr, argv[4] );

	itemnum = hex2dec( itemstr );

	mMpswd_make_passcode( passcode, 4, 1, playername, townname, itemnum, 0, codetype );
	DisplayCode( passcode, 21 );
	mMpswd_substitution_cipher( passcode );
	DisplayCode( passcode, 21 );
	mMpswd_transposition_cipher( passcode, 1, 0 );
	DisplayCode( passcode, 21 );
	mMpswd_bit_shuffle( passcode, 0 );
	DisplayCode( passcode, 21 );
	mMpswd_chg_RSA_cipher( passcode );
	DisplayCode( passcode, 21 );
	mMpswd_bit_mix_code( passcode );
	DisplayCode( passcode, 21 );
	mMpswd_bit_shuffle( passcode, 1 );
	DisplayCode( passcode, 21 );
	mMpswd_transposition_cipher( passcode, 0, 1 );
	DisplayCode( passcode, 21 );
	mMpswd_chg_6bits_code( finalcode, passcode );
	DisplayCode( finalcode, 28 );
	mMpswd_chg_common_font_code( finalcode );
	DisplayCode( finalcode, 28 );

	printf( "\n" );

	for( idx = 0; idx < 14; idx++ )
	{
		printf( "%c", finalcode[idx] );
	}

	printf( "\n" );

	for( idx = 14; idx < 28; idx++ )
	{
		printf( "%c", finalcode[idx] );
	}

	printf( "\n" );

	return 0;
}

/*************************************************************\
*+-----------------------------------------------------------+*
*|                                                           |*
*|  This function is a bit misnamed, a better name would be  |*
*|  mMpswd_bit_invert. For those of you who aren't familiar  |*
*|  with boolean logic, XORing a value with 0xFF in hex,     |*
*|  which is 11111111 in binary, will cause all 0 bits to    |*
*|  become 1 bits, and vice-versa. As I'm sure you've        |*
*|  guessed by now, this routine inverts the bits in all 21  |*
*|  bytes of the passcode.                                   |*
*|                                                           |*
*+-----------------------------------------------------------+*
\*************************************************************/

void mMpswd_bit_reverse( unsigned char* passcode )
{
	unsigned int idx;
    for(idx = 0; idx < 21; idx++)
    {
        if(idx != 1)
            passcode[idx] ^= 0xff;
    }
}

/*************************************************************\
*+-----------------------------------------------------------+*
*|                                                           |*
*|  This function accepts a pointer to an empty buffer of    |*
*|  28 chars and accepts a buffer of 21 chars which should   |*
*|  contain the 168 bits to split from 21 8-bit groups into  |*
*|  28 6-bit groups, which is what this function does. It    |*
*|  may be slightly difficult to understand, so this should  |*
*|  explain it. To put things a bit simply, essentially it   |*
*|  has two indices into the final and input buffers         |*
*|  respectively, as well as two counters for the final and  |*
*|  input byte respectively. It also has a source byte and   |*
*|  a destination byte. In order to go from 8 bits to 6      |*
*|  bits, it fetches a source byte, then it proceeds to      |*
*|  shift bits off of the source byte and into the           |*
*|  destination byte, fetching a new source byte when the    |*
*|  source byte's counter is equal to eight, and storing     |*
*|  the final byte's value when the final byte's counter is  |*
*|  equal to six. When a source byte is fetched or a         |*
*|  destination byte is stored, the source buffer and        |*
*|  destination buffer pointers are incremented respective   |*
*|  to which event has occurred. When the destination        |*
*|  buffer pointer is equal to 28, the routine exits.        |*
*|                                                           |*
*+-----------------------------------------------------------+*
\*************************************************************/

void mMpswd_chg_6bits_code( unsigned char* finalcode, unsigned char* passcode )
{
    long code8bitsIndex = 0;
    long code6bitsIndex = 0;
    unsigned char passbyte = 0;
    unsigned char destbyte = 0;
    long bytectr = 0;
    long ctr8bits = 0;
    long ctr6bits = 0;
    while( 1 )
    {
        passbyte = passcode[code8bitsIndex] >> ctr8bits;
        ctr8bits++;
        passbyte = ( passbyte & 0x00000001 ) << ctr6bits;
        ctr6bits++;
        destbyte |= passbyte;
        if( ctr6bits == 6 )
        {
            bytectr++;
            finalcode[code6bitsIndex] = destbyte;
            ctr6bits = 0;
            code6bitsIndex++;
            if( bytectr == 28 )
                return;
            destbyte = 0;
        }
        if( ctr8bits == 8 )
        {
            ctr8bits = 0;
            code8bitsIndex++;
        }
    }
}

/*************************************************************\
*+-----------------------------------------------------------+*
*|                                                           |*
*|  mMpswd_chg_common_font_code converts the final bytes     |*
*|  from their numeric form, 0x00 to 0x3f, to Animal         |*
*|  Crossing-style ASCII values, the modification table      |*
*|  being named usable_to_fontnum. This deviates from the    |*
*|  ASCII standard by having the pound symbol (#) equal to   |*
*|  0xD1 instead of 0x23. The manner by which this function  |*
*|  operates should be obvious.                              |*
*|                                                           |*
*+-----------------------------------------------------------+*
\*************************************************************/

void mMpswd_chg_common_font_code( unsigned char* finalcode )
{
		unsigned int idx;
    for(idx = 0; idx < 28; idx++)
    {
        finalcode[idx] = usable_to_fontnum[ finalcode[idx] ];
    }
}

/*************************************************************\
*+-----------------------------------------------------------+*
*|                                                           |*
*|  mMpswd_make_passcode is an evil little routine which     |*
*|  has caused me a great deal of grief in my efforts to     |*
*|  fully support NES Contest Codes as well as Universal     |*
*|  Codes. The actual routine as found in Animal Crossing    |*
*|  lacks the switch( codetype ) functionality and is hard-  |*
*|  coded to form only Player-To-Player trade codes. It was  |*
*|  only thanks to pre-existing Universal Codes and pre-     |*
*|  existing NES Contest Codes that allowed me to deduce     |*
*|  what needs to be changed in the checksum byte. This      |*
*|  function's operation is fairly simple; it forms a        |*
*|  checksum byte based on several passed parameters, the    |*
*|  destination name and town, the item number, and the      |*
*|  desired code type, copies it and an 0xFF byte into the   |*
*|  passcode buffer, then copies the destination name,       |*
*|  town, and item number to the appropriate spots in the    |*
*|  passcode buffer.                                         |*
*|                                                           |*
*+-----------------------------------------------------------+*
\*************************************************************/

void mMpswd_make_passcode( unsigned char* passcode, unsigned int paramR4, unsigned int paramR5,
                           unsigned char* playername, unsigned char* townname,
                           unsigned int itemnum, unsigned int paramR9, unsigned char codetype )
{
    unsigned int checksum, checkbyte;
	unsigned int idx;

    passcode[0] = ( ( paramR4 & 0x00000007 ) << 5 ) | ( paramR5 << 1 ) | ( paramR9 & 0x00000001 );
    passcode[1] = 255;

    memcpy( passcode+2, playername, 8 );
    memcpy( passcode+10, townname, 8 );

    passcode[18] = (itemnum >> 8) & 0x000000FF;
    passcode[19] = itemnum & 0x000000FF;

    checksum = 0;

    for(idx = 0; idx < 8; idx++)
    {
        checksum += playername[idx];
        checksum += townname[idx];
    }

    checksum += itemnum;
    checksum += 0x000000FF;

    checkbyte = passcode[0] | ( (checksum & 0x00000003) << 3 );
    switch( codetype )
    {
    case 'P':
        break;
    case 'N':
        checkbyte &= 0x0000001f;
        break;
    case 'U':
        checkbyte &= 0x00000018;
        checkbyte |= 0x61;
        break;
    }
    passcode[0] = checkbyte;
}

/*************************************************************\
*+-----------------------------------------------------------+*
*|                                                           |*
*|  mMpswd_get_RSA_key_code returns three prime numbers and  |*
*|  the pointer to a table of bytes to modify. The first     |*
*|  two prime numbers are derived from the 16th byte in the  |*
*|  passcode, whereas the third prime number is the entry    |*
*|  in mMpswd_prime_number corresponding directly to the     |*
*|  6th byte in the passcode. In other words, the third      |*
*|  prime number is the nth prime number where n is 6 +      |*
*|  the 6th passcode byte. The table of bytes to modify is   |*
*|  selected according to the value of bits 5..2 in the      |*
*|  16th byte in the passcode. Quite frankly, I find that    |*
*|  the manner in which the first and second primes are      |*
*|  selected is simply "FM", or "Freaking Magic", in that    |*
*|  even I'm not entirely sure how it's supposed to work.    |*
*|  Suffice it to say that it works.                         |*
*|                                                           |*
*+-----------------------------------------------------------+*
\*************************************************************/

void mMpswd_get_RSA_key_code( unsigned short* param1, unsigned short* param2,
                              unsigned short* param3, unsigned char** param4,
                              unsigned char* passcode )
{
    unsigned int bit10 = 0, bit32 = 0, bytetable;

    bit10 = passcode[15] % 4;
    bit32 = ( passcode[15] & 0x0000000f ) / 4;

    if( bit10 == 3 )
    {
        bit10 = ( bit10 ^ bit32 ) & 0x00000003;
        if( bit10 == 3 ) bit10 = 0;
    }

    if( bit32 == 3 )
    {
        bit32 = (bit10 + 1) & 0x00000003;
        if( bit32 == 3 ) bit32 = 1;
    }

    if( bit10 == bit32 )
    {
        bit32 = (bit10 + 1) & 0x00000003;
        if( bit32 == 3 ) bit32 = 1;
    }

    bytetable = ( ( passcode[15] >> 2 ) & 0x0000003c ) >> 2;

    *param1 = mMpswd_prime_number[bit10];
    *param2 = mMpswd_prime_number[bit32];
    *param3 = mMpswd_prime_number[passcode[5]];
    *param4 = mMpswd_select_idx_table[bytetable];
}

/*************************************************************\
*+-----------------------------------------------------------+*
*|                                                           |*
*|  mMpswd_chg_RSA_cipher is a slightly modified RSA         |*
*|  routine which takes three primes and a list of eight     |*
*|  bytes to modify. The first and second primes are used    |*
*|  to form the standard product PQ, but the third primes    |*
*|  is used as E, which is in fact supposed to be            |*
*|  relatively prime to (P-1)(Q-1) and less than PQ, but     |*
*|  (P-1)(Q-1) is never actually used in this algorithm,     |*
*|  not to mention the fact that since E can be any of the   |*
*|  256 entries in mMpswd_prime_number and PQ is invariably  |*
*|  going to be bigger than at least the first 55 entries    |*
*|  in mMpswd_prime_number, this violates that rule of the   |*
*|  RSA algorithm, but I digress. After selecting the three  |*
*|  prime numbers and the table of the eight bytes to        |*
*|  change, the eight bytes are changed via the standard     |*
*|  C = T^E mod PQ formula, where P and Q are the first two  |*
*|  primes, E is the third prime, C is the modified byte,    |*
*|  T is the original byte, and ^ indicates exponentiation.  |*
*|  However, the 21st byte in the passcode is changed into   |*
*|  a checksum made up of bit 8 from all eight results.      |*
*|                                                           |*
*+-----------------------------------------------------------+*
\*************************************************************/

void mMpswd_chg_RSA_cipher( unsigned char* passcode )
{
    unsigned int bytectr, idx;
    unsigned short prime1, prime2, prime3;
    unsigned int primeproduct;
    unsigned int currentbyte;
    unsigned int newbyte;
    unsigned int checkbyte;
    unsigned char* idxtableptr = NULL;

    mMpswd_get_RSA_key_code( &prime1, &prime2, &prime3, &idxtableptr, passcode );
    checkbyte = 0;
    primeproduct = prime1 * prime2;

    for(bytectr = 0; bytectr < 8; bytectr++)
    {
        newbyte = currentbyte = (unsigned int)passcode[idxtableptr[bytectr]];
        for(idx = 0; idx < prime3-1; idx++)
        {
            newbyte = (newbyte * currentbyte) % primeproduct;
        }

        passcode[idxtableptr[bytectr]] = newbyte;
        newbyte = (newbyte >> 8) & 0x00000001;
        checkbyte |= (newbyte << bytectr);
    }
    passcode[20] = checkbyte;
}

/*************************************************************\
*+-----------------------------------------------------------+*
*|                                                           |*
*|  mMpswd_substitution_cipher is self-explanatory in        |*
*|  nature. It changes all 21 bytes in the passcode via a    |*
*|  simple substitution cipher, the table of values being    |*
*|  named mMpswd_chg_code_table. The function's operation    |*
*|  is self-explanatory.                                     |*
*|                                                           |*
*+-----------------------------------------------------------+*
\*************************************************************/

void mMpswd_substitution_cipher( unsigned char* passcode )
{
		unsigned int idx;
    for(idx = 0; idx < 21; idx++)
    {
        passcode[idx] = mMpswd_chg_code_table[ passcode[idx] ];
    }
}

/*************************************************************\
*+-----------------------------------------------------------+*
*|                                                           |*
*|  mMpswd_transposition_cipher transposes each byte in the  |*
*|  passcode by an amount determined in the                  |*
*|  mMpswd_transposition_cipher_char* tables. The table      |*
*|  of offsets is selected via the third parameter combined  |*
*|  with the low-order four bits of a key byte in the        |*
*|  passcode, the key byte determined by the entry in        |*
*|  key_idx corresponding to the third parameter. The        |*
*|  routine then iterates through the passcode buffer,       |*
*|  either adding or subtracting the current transposition   |*
*|  table entry's character depending on whether or not      |*
*|  the second parameter is true or false, making sure to    |*
*|  skip the key byte so that the transposition cipher can   |*
*|  be undone when it comes time to decrypt the code.        |*
*|                                                           |*
*+-----------------------------------------------------------+*
\*************************************************************/

void mMpswd_transposition_cipher( unsigned char* passcode, unsigned int negval,
                                  unsigned int paramR5 )
{
    unsigned char transdir, transoffset, chgstrlen, chgstroffset, chgstrnum, chgstridx;
    unsigned char* chgstrptr;
	unsigned short idx;

    if( negval == 1 ) transdir = -1;
    else transdir = 1;

    chgstroffset = passcode[key_idx[paramR5]] & 0x0f;
    chgstrnum    = chgstroffset + (paramR5 * 16);


    chgstrptr = chg_ptr[chgstrnum];    /* R6 */
    chgstrlen = chg_len[chgstrnum];    /* R7 */

    chgstridx = 0;

    for(idx = 0; idx < 21; idx++)
    {
        if( key_idx[paramR5] != idx )
        {
            transoffset  = chgstrptr[chgstridx] * transdir;
            passcode[idx] += transoffset;
            chgstridx++;
            chgstridx %= chgstrlen;
        }
    }
}

/*************************************************************\
*+-----------------------------------------------------------+*
*|                                                           |*
*|  mMpswd_bit_shuffle rearranges the bits in a seemingly    |*
*|  random manner throughout the passcode via offsets        |*
*|  specified by the tables in mMpswd_select_idx_table.      |*
*|  Functionally, the routine first determines the key via   |*
*|  the function's second parameter, then moves each bit     |*
*|  in each byte a specific offset away from the current     |*
*|  byte position.                                           |*
*|                                                           |*
*+-----------------------------------------------------------+*
\*************************************************************/

void mMpswd_bit_shuffle( unsigned char* passcode, unsigned int keynum )
{
    unsigned int charoffset, numchars, tablenum;
    unsigned char inbyte, outbyte, tempbyte, outoffset;
    unsigned char tempbuf[21];
    unsigned char newbuf[21];
    unsigned char *idxPtr;
	unsigned int idx1, idx2;

    memset( tempbuf, 0x00, 21 );
    memset( newbuf,  0x00, 21 );

    if( keynum == 0 )
    {
        charoffset = 13;
        numchars = 19;
    }
    else
    {
        charoffset = 2;
        numchars = 20;
    }

    memcpy( tempbuf, passcode, charoffset );
    memcpy( tempbuf+charoffset, passcode+charoffset+1, 20-charoffset );

    tablenum = (passcode[charoffset] << 2) & 0x0000000c;

    idxPtr = mMpswd_select_idx_table[tablenum>>2];

    for(idx1 = 0; idx1 < numchars; idx1++)
    {
        tempbyte = tempbuf[idx1];
        for(idx2 = 0; idx2 < 8; idx2++)
        {
            outoffset = idxPtr[idx2] + idx1;
            outoffset %= numchars;
            inbyte = tempbyte >> idx2;
            outbyte = newbuf[outoffset];
            inbyte = inbyte & 0x00000001;
            inbyte = inbyte << idx2;
            inbyte = inbyte | outbyte;
            newbuf[outoffset] = inbyte;
        }
    }

    memcpy( passcode, newbuf, charoffset );
    memcpy( passcode+charoffset+1, newbuf+charoffset, 20-charoffset );
}

/*************************************************************\
*+-----------------------------------------------------------+*
*|                                                           |*
*|  mMpswd_bit_arrange_reverse is a fairly straightforward   |*
*|  function which reverses the ordering of the bits in      |*
*|  the passcode buffer, with the exception of byte 1.       |*
*|  for example, bit 7 of byte 0 now corresponds to bit 0    |*
*|  of byte 20, bit 6 of byte 0 now corresponds to bit 1 of  |*
*|  byte 20, and so on.                                      |*
*|                                                           |*
*+-----------------------------------------------------------+*
\*************************************************************/

void mMpswd_bit_arrange_reverse( unsigned char* passcode )
{
    unsigned char tempbuf[21] = { 0x00 };
    unsigned char tempbuf2[21] = { 0x00 };
    unsigned char srcbyte, destbyte;
		unsigned int idx1;

    memcpy( tempbuf, passcode, 1 );
    memcpy( tempbuf+1, passcode+2, 19 );

    for(idx1 = 0; idx1 <= 19; idx1++)
    {
        srcbyte = tempbuf[19-idx1];
        destbyte = ( ( srcbyte & 0x80 ) >> 7 ) |
                   ( ( srcbyte & 0x40 ) >> 5 ) |
                   ( ( srcbyte & 0x20 ) >> 3 ) |
                   ( ( srcbyte & 0x10 ) >> 1 ) |
                   ( ( srcbyte & 0x08 ) << 1 ) |
                   ( ( srcbyte & 0x04 ) << 3 ) |
                   ( ( srcbyte & 0x02 ) << 5 ) |
                   ( ( srcbyte & 0x01 ) << 7 );
        tempbuf2[idx1] = destbyte;
    }

    memcpy( passcode, tempbuf2, 1 );
    memcpy( passcode+2, tempbuf2+1, 19 );
}

/*************************************************************\
*+-----------------------------------------------------------+*
*|                                                           |*
*|  mMpswd_bit_shift is one evil, horrible routine that      |*
*|  caused me an inordinate amount of problems when I was    |*
*|  converting it over to my own code. In essence, it        |*
*|  performs a massive rotate operation on all of the        |*
*|  passcode buffer, with the exception of byte 1. A rotate  |*
*|  operation, for those who do not know, treats the entire  |*
*|  bit space as if it is circular. Using an alphabetical    |*
*|  example, ABCDEFGHIJKL when rotated four characters to    |*
*|  the left would become EFGHIJKLABCD. This function        |*
*|  operates on the same general principal, wherein the      |*
*|  individual bits are rotated by an amount specified by    |*
*|  the second parameter.                                    |*
*|                                                           |*
*+-----------------------------------------------------------+*
\*************************************************************/

void mMpswd_bit_shift( unsigned char* passcode, unsigned int shiftamt )
{
    unsigned int idx;
    unsigned char tempbuf[21]  = { '\0' };
    unsigned char tempbuf2[21] = { '\0' };
    unsigned char destpos;
    unsigned char destoffs;

    memcpy( tempbuf,   passcode,    1 );
    memcpy( tempbuf+1, passcode+2, 19 );

    if( (int)shiftamt > 0 )
    {
        destpos  = shiftamt / 8;
        destoffs = shiftamt % 8;

        for(idx = 0; idx < 20; idx++)
        {
            tempbuf2[ ( idx + destpos ) % 20 ] = (tempbuf[idx] << destoffs) | (tempbuf[(idx+19)%20] >> (8-destoffs));
        }

        for(idx = 0; idx < 20; idx++) tempbuf[idx] = tempbuf2[/*19-*/idx];
    }
    else if( (int)shiftamt < 0 )
    {
        for(idx = 0; idx < 20; idx++)
        {
            tempbuf2[idx] = tempbuf[19-idx];
        }

        destpos  = ( 0 - (int)shiftamt ) / 8;
        destoffs = ( 0 - (int)shiftamt ) % 8;

        for(idx = 0; idx < 20; idx++)
        {
            tempbuf[( idx + destpos ) % 20] = tempbuf2[idx];
        }

        tempbuf2[0] = ( tempbuf[0] >> destoffs ) | ( tempbuf[19] << (8-destoffs) );

        for(idx = 1; idx < 20; idx++)
        {
            tempbuf2[idx] = (tempbuf[idx] >> destoffs) | (tempbuf[(idx-1)%20] << (8-destoffs));
        }

        for(idx = 0; idx < 20; idx++)
        {
            tempbuf[idx] = tempbuf2[19-idx];
        }
    }

    memcpy( passcode,   tempbuf,    1 );
    memcpy( passcode+2, tempbuf+1, 19 );

}

/*************************************************************\
*+-----------------------------------------------------------+*
*|                                                           |*
*|  mMpswd_bit_mix_code is fairly straightforward. It calls  |*
*|  a combination of mMpswd_bit_shift, mMpswd_bit_reverse,   |*
*|  and mMpswd_bit_arrange_reverse depending on bits 3..2    |*
*|  of byte 1 in the passcode buffer.                        |*
*|                                                           |*
*+-----------------------------------------------------------+*
\*************************************************************/

void mMpswd_bit_mix_code( unsigned char* passcode )
{
    unsigned int switchbyte;
    switchbyte = passcode[1] & 0x0f;
    printf( "switchbyte = %d\n", switchbyte );
    switch( switchbyte )
    {
    case 13:
    case 14:
    case 15:
        mMpswd_bit_arrange_reverse( passcode );
        DisplayCode( passcode, 21 );
        mMpswd_bit_reverse( passcode );
        DisplayCode( passcode, 21 );
        mMpswd_bit_shift( passcode, switchbyte * 3 );
        DisplayCode( passcode, 21 );
        break;
    case 9:
    case 10:
    case 11:
    case 12:
        mMpswd_bit_arrange_reverse( passcode );
        DisplayCode( passcode, 21 );
        mMpswd_bit_shift( passcode, ( 0 - switchbyte ) * 5 );
        DisplayCode( passcode, 21 );
        break;
    case 5:
    case 6:
    case 7:
    case 8:
        mMpswd_bit_shift( passcode, ( 0 - switchbyte ) * 5 );
        DisplayCode( passcode, 21 );
        mMpswd_bit_reverse( passcode );
        DisplayCode( passcode, 21 );
        break;
    case 0:
    case 1:
    case 2:
    case 3:
    case 4:
        mMpswd_bit_shift( passcode, switchbyte * 3 );
        DisplayCode( passcode, 21 );
        mMpswd_bit_arrange_reverse( passcode );
        DisplayCode( passcode, 21 );
        break;
    }
}

unsigned int hex2dec( unsigned char* numstr )
{
	int idx, idx2;
	unsigned int multiplier = 1;
	unsigned int finalval = 0;
	unsigned char tempstr[5];
	unsigned char convbytes[16] = {
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

	for( idx = 0; idx < 4; idx++ )
	{
		if( numstr[idx] > 0x39 )
		{
			tempstr[idx] = numstr[idx] & 0xDF;
		}
		else
		{
			tempstr[idx] = numstr[idx];
		}
	}

	for( idx = 3; idx >= 0; idx-- )
	{
		for( idx2 = 0; idx2 < 16; idx2++ )
		{
			if( tempstr[idx] == convbytes[idx2] )
			{
				break;
			}
		}
		if( idx2 < 16 )
		{
			finalval += multiplier * idx2;
		}
		multiplier *= 16;
	}
	return finalval;
}
