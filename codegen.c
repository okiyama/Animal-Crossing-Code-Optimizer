#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

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
void init_char_to_location();
unsigned int calculate_item_cost( unsigned char* );

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


//TODO: This is actually backwards. What I want is a way to give a character and get out an x, y, keyboard(z) co-ordinate that I can then take distance of
// unsigned char small_keyboard[10][4] =
//   {  0,   0,   0,   0,   0,   0,   0,   0,   0,   0 }, //Never use top row of small
//   { 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p'},
//   { 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l',  0 },
//   { 'z', 'x', 'c', 'v', 'b', 'n', 'm',  0,   0,   0 };
//
// unsigned char big_keyboard[10][4] =
//     {  0,  '2', '3', '4', '5', '6', '7', '8', '9',  0 },
//     { 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P'},
//     { 'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L',  0 },
//     { 'Z', 'X', 'C', 'V', 'B', 'N', 'M',  0,   0,   0 };
//
// unsigned char punct_keyboard[10][4] =
//     { '#',  0,   0,   0,   0,   0,   0,   0,   0,   0},
//     { '%', '&', '@',  0,   0,   0,   0,   0,   0,   0},
//     {  0,   0,   0,   0,   0,   0,   0,   0,   0,   0},
//     {  0,   0,   0,   0,   0,   0,   0,   0,   0,   0};

typedef enum {SMALL, BIG, PUNCT} keyboard;

typedef struct {
  int x;
  int y;
  keyboard k;
} keyboard_location;

keyboard_location *char_to_location;

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
  unsigned int idx2;
  unsigned int idx3;
  unsigned int playeridx;
  unsigned int townidx;
	unsigned char codetype = 0;
	unsigned char townname[10] = { 33, 32,32,32,32,32,32,32,32,32 };
	unsigned char playername[10] = { 33, 32,32,32,32,32,32,32,32,32};
	unsigned char passcode[21];
	unsigned char finalcode[28];
	unsigned int itemnum;

	for( idx = 0; idx < 21; idx++ ) passcode[idx] = 0;
	for( idx = 0; idx < 28; idx++ ) finalcode[idx] = 0;

  //This will be pared down when I determine which codes the speedrun uses
  unsigned int itemnums[1300] = {
    2304, 4096, 4100, 4104, 4108, 4112, 4116, 4120, 4124, 4128, 4132, 4136, 4140, 4144, 4148, 4152, 4156, 4160, 4164, 4168, 4172, 4176, 4180, 4184, 4188, 4192, 4196, 4200, 4204, 4208, 4212, 4216, 4232, 4256, 4260, 4264, 4268, 4280, 4284, 4292, 4296, 4312, 4316, 4320, 4324, 4328, 4332, 4336, 4340, 4344, 4348, 4352, 4356, 4360, 4364, 4368, 4372, 4376, 4380, 4384, 4388, 4392, 4396, 4400, 4404, 4408, 4412, 4416, 4420, 4424, 4428, 4432, 4436, 4440, 4444, 4448, 4452, 4456, 4460, 4464, 4468, 4472, 4476, 4480, 4484, 4488, 4492, 4496, 4500, 4504, 4508, 4512, 4516, 4520, 4524, 4528, 4532, 4536, 4540, 4544, 4548, 4552, 4556, 4560, 4564, 4568, 4572, 4576, 4580, 4584, 4588, 4592, 4596, 4604, 4608, 4620, 4624, 4628, 4632, 4636, 4648, 4652, 4656, 4660, 4664, 4668, 4684, 4692, 4696, 4700, 4704, 4708, 4712, 4716, 4720, 4724, 4728, 4732, 4736, 4740, 4744, 4748, 4752, 4756, 4760, 4764, 4768, 4772, 4776, 4780, 4784, 4788, 4792, 4796, 4800, 4804, 4808, 4812, 4816, 4820, 4824, 4828, 4832, 4836, 4840, 4844, 4852, 4856, 4860, 4864, 4868, 4872, 4876, 4880, 4888, 4892, 4896, 4900, 4904, 4908, 4912, 4916, 4920, 4924, 4928, 4936, 4940, 4944, 4948, 4952, 4956, 4960, 4964, 4968, 4972, 4976, 4980, 4984, 4988, 4992, 4996, 5000, 5004, 5008, 5012, 5016, 5020, 5024, 5028, 5032, 5036, 5040, 5044, 5048, 5052, 5056, 5060, 5064, 5068, 5072, 5076, 5080, 5084, 5088, 5092, 5096, 5100, 5104, 5108, 5124, 5128, 5132, 5136, 5140, 5148, 5156, 5160, 5164, 5184, 5188, 5192, 5200, 5212, 5216, 5224, 5228, 5232, 5240, 5244, 5248, 5252, 5256, 5260, 5268, 5276, 5284, 5288, 5292, 5312, 5316, 5320, 5328, 5332, 5336, 5340, 5344, 5348, 5352, 5356, 5360, 5364, 5368, 5372, 5376, 5380, 5384, 5388, 5392, 5396, 5400, 5404, 5412, 5424, 5428, 5432, 5436, 5440, 5444, 5448, 5460, 5464, 5468, 5472, 5480, 5484, 5488, 5496, 5500, 5504, 5508, 5512, 5516, 5520, 5532, 5536, 5540, 5544, 5548, 5694, 5719, 5917, 7592, 7596, 7600, 7604, 7608, 7612, 7616, 7620, 7624, 7628, 7632, 7636, 7640, 7644, 7648, 7652, 7656, 7660, 7664, 7668, 7672, 7676, 7680, 7684, 7688, 7692, 7696, 7700, 7704, 7708, 7712, 7716, 7720, 7724, 7728, 7732, 7736, 7740, 7744, 7748, 7752, 7756, 7760, 7764, 7768, 7772, 7776, 7780, 7784, 7788, 7792, 7804, 7816, 7820, 7824, 7828, 7832, 7836, 7840, 7844, 7848, 7852, 7856, 7860, 7864, 7868, 7872, 7876, 7880, 7884, 7888, 7892, 7896, 7900, 7904, 7908, 7912, 7916, 7920, 7924, 7928, 7932, 7936, 7940, 7944, 7948, 7952, 7956, 7960, 7964, 7968, 7972, 7976, 7980, 7984, 7988, 7992, 7996, 8000, 8004, 8008, 8012, 8016, 8020, 8024, 8028, 8032, 8036, 8040, 8044, 8048, 8052, 8056, 8092, 8096, 8100, 8104, 8108, 8112, 8116, 8120, 8128, 8132, 8136, 8140, 8144, 8148, 8152, 8156, 8160, 8164, 8168, 8172, 8176, 8180, 8184, 8188, 8192, 8196, 8200, 8204, 8208, 8212, 8216, 8220, 8224, 8228, 8232, 8236, 8240, 8244, 8248, 8252, 8256, 8260, 8264, 8268, 8272, 8276, 8280, 8284, 8288, 8292, 8296, 8300, 8304, 8308, 8312, 8316, 8320, 8324, 8328, 8332, 8336, 8340, 8344, 8348, 8352, 8356, 8360, 8364, 8368, 8372, 8376, 8380, 8384, 8388, 8392, 8396, 8400, 8404, 8408, 8412, 8416, 8420, 8424, 8428, 8432, 8436, 8440, 8444, 8448, 8449, 8450, 8451, 8704, 8705, 8706, 8707, 8708, 8709, 8710, 8711, 8712, 8713, 8714, 8715, 8716, 8717, 8718, 8719, 8720, 8721, 8722, 8723, 8724, 8725, 8726, 8727, 8728, 8729, 8730, 8731, 8732, 8733, 8734, 8735, 8736, 8737, 8738, 8739, 8740, 8772, 8773, 8774, 8775, 8776, 8777, 8778, 8779, 8780, 8781, 8782, 8783, 8784, 8785, 8786, 8787, 8788, 8789, 8790, 8791, 8792, 8793, 8794, 8795, 9216, 9217, 9218, 9219, 9220, 9221, 9222, 9223, 9224, 9225, 9226, 9227, 9228, 9229, 9230, 9231, 9232, 9233, 9234, 9235, 9236, 9237, 9238, 9239, 9240, 9241, 9242, 9243, 9244, 9245, 9246, 9247, 9248, 9249, 9250, 9251, 9252, 9253, 9254, 9255, 9256, 9257, 9258, 9259, 9260, 9261, 9262, 9263, 9264, 9265, 9266, 9267, 9268, 9269, 9270, 9271, 9272, 9273, 9274, 9275, 9276, 9277, 9278, 9279, 9280, 9281, 9282, 9283, 9284, 9285, 9286, 9287, 9288, 9289, 9290, 9291, 9292, 9293, 9294, 9295, 9296, 9297, 9298, 9299, 9300, 9301, 9302, 9303, 9304, 9305, 9306, 9307, 9308, 9309, 9310, 9311, 9312, 9313, 9314, 9315, 9316, 9317, 9318, 9319, 9320, 9321, 9322, 9323, 9324, 9325, 9326, 9327, 9328, 9329, 9330, 9331, 9332, 9333, 9334, 9335, 9336, 9337, 9338, 9339, 9340, 9341, 9342, 9343, 9344, 9345, 9346, 9347, 9348, 9349, 9350, 9351, 9352, 9353, 9354, 9355, 9356, 9357, 9358, 9359, 9360, 9361, 9362, 9363, 9364, 9365, 9366, 9367, 9368, 9369, 9370, 9371, 9372, 9373, 9374, 9375, 9376, 9377, 9378, 9379, 9380, 9381, 9382, 9383, 9384, 9385, 9386, 9387, 9388, 9389, 9390, 9391, 9392, 9393, 9394, 9395, 9396, 9397, 9398, 9399, 9400, 9401, 9402, 9403, 9404, 9405, 9406, 9407, 9408, 9409, 9410, 9411, 9412, 9413, 9414, 9415, 9416, 9417, 9418, 9419, 9420, 9421, 9422, 9423, 9424, 9425, 9426, 9427, 9428, 9429, 9430, 9431, 9432, 9433, 9434, 9435, 9436, 9437, 9438, 9439, 9440, 9441, 9442, 9443, 9444, 9445, 9446, 9447, 9448, 9449, 9450, 9451, 9452, 9453, 9454, 9455, 9456, 9457, 9458, 9459, 9460, 9461, 9462, 9463, 9464, 9465, 9466, 9467, 9468, 9469, 9470, 9484, 9485, 9486, 9487, 9488, 9489, 9490, 9491, 9517, 9728, 9729, 9730, 9731, 9732, 9733, 9734, 9735, 9736, 9737, 9738, 9739, 9740, 9741, 9742, 9743, 9744, 9745, 9746, 9747, 9748, 9749, 9750, 9751, 9752, 9753, 9754, 9755, 9756, 9757, 9758, 9759, 9760, 9761, 9762, 9763, 9764, 9765, 9766, 9767, 9768, 9769, 9770, 9771, 9772, 9773, 9774, 9775, 9776, 9777, 9778, 9779, 9780, 9781, 9782, 9783, 9784, 9785, 9786, 9787, 9788, 9789, 9790, 9791, 9792, 9793, 9794, 9984, 9985, 9986, 9987, 9988, 9989, 9990, 9991, 9992, 9993, 9994, 9995, 9996, 9997, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10008, 10009, 10010, 10011, 10012, 10013, 10014, 10015, 10016, 10017, 10018, 10019, 10020, 10021, 10022, 10023, 10024, 10025, 10026, 10027, 10028, 10029, 10030, 10031, 10032, 10033, 10034, 10034, 10036, 10037, 10038, 10039, 10040, 10041, 10042, 10043, 10044, 10045, 10046, 10047, 10048, 10049, 10050, 10240, 10241, 10242, 10243, 10244, 10245, 10246, 10247, 10496, 10497, 10498, 10499, 10500, 10501, 10502, 10503, 10504, 10505, 10506, 10752, 10753, 10754, 10755, 10756, 10757, 10758, 10759, 10760, 10761, 10762, 10763, 10764, 10765, 10766, 10767, 10768, 10769, 10770, 10771, 10772, 10773, 10774, 10775, 10776, 10777, 10778, 10779, 10780, 10781, 10782, 10783, 10784, 10785, 10786, 10787, 10788, 10789, 10790, 10791, 10792, 10793, 10794, 10795, 10796, 10797, 10798, 10799, 10800, 10801, 10802, 10803, 10804, 10805, 10806, 11008, 11009, 11010, 11011, 11012, 11013, 11014, 11015, 11016, 11017, 11018, 11019, 11020, 11021, 11022, 11023, 11264, 11776, 11777, 12032, 12033, 12034, 12035, 12288, 12292, 12296, 12300, 12304, 12308, 12312, 12316, 12320, 12324, 12328, 12332, 12336, 12340, 12356, 12360, 12364, 12368, 12372, 12384, 12388, 12400, 12404, 12408, 12412, 12416, 12420, 12424, 12432, 12436, 12444, 12448, 12452, 12456, 12460, 12464, 12468, 12472, 12476, 12480, 12484, 12488, 12492, 12496, 12500, 12504, 12508, 12512, 12516, 12520, 12524, 12528, 12532, 12536, 12540, 12544, 12548, 12552, 12556, 12560, 12564, 12568, 12572, 12576, 12580, 12584, 12588, 12592, 12596, 12600, 12604, 12608, 12612, 12616, 12620, 12624, 12628, 12632, 12636, 12640, 12644, 12648, 12652, 12656, 12660, 12664, 12668, 12672, 12676, 12680, 12684, 12688, 12692, 12696, 12700, 12704, 12708, 12712, 12716, 12720, 12724, 12728, 12732, 12736, 12740, 12744, 12748, 12752, 12756, 12768, 12772, 12776, 12780, 12784, 12788, 12792, 12796, 12800, 12804, 12808, 12812, 12816, 12820, 12824, 12832, 12836, 12844, 12852, 12856, 12860, 12864, 12868, 12872, 12876, 12880, 12884, 12888, 12892, 12896, 12900, 12904, 12908, 12912, 12916, 12920, 12924, 12928, 12932, 12936, 12940, 12944, 12948, 12952, 12956, 12960, 12964, 12968, 12972, 12976, 12980, 12984, 12988, 12992, 12996, 13000, 13004, 13008, 13012, 13016, 13020, 13024, 13028, 13032, 13036, 13040, 13044, 13048, 13052, 13056, 13060, 13064, 13068, 13072, 13076, 13080, 13084, 13088, 13092, 13094, 13096, 13100, 13104, 13108, 13112, 13116, 13120, 13124, 13128, 13132, 13136, 13140, 13144, 13148, 13152, 13156, 13160, 13164, 13168, 13172, 13176, 13180, 13184, 13188, 13192, 13196, 13200, 13204, 13208, 13212, 13216, 13220, 13224, 13228, 13232, 13236, 13240, 13244, 13248
  };

  init_char_to_location();

  unsigned int minCodeCost = UINT_MAX;
  unsigned int maxCodeCost = 0;
  unsigned int minCost = UINT_MAX;
  unsigned int maxCost = 0;
	unsigned int itemCost = 0;
  unsigned int playerTownComboCost = 0;
	unsigned char minCode[28];
	unsigned char maxCode[28];

  unsigned char minPlayerName = 0;
  unsigned char minTownName = 0;
  unsigned char maxPlayerName = 0;
  unsigned char maxTownName = 0;

  //0 to 222 for all
  for(playeridx = 0; playeridx <= 222; playeridx++) {
    playername[0] = playeridx;
    printf("player name: %c, town name: %c\n", playername[0], townname[0]);

    for(townidx = 0; townidx <= 222; townidx++) {
      townname[0] = townidx;

      //< 1300 for all
      for(idx2 = 0; idx2 < 1300; idx2++) {
        for( idx = 0; idx < 21; idx++ ) passcode[idx] = 0;
      	for( idx = 0; idx < 28; idx++ ) finalcode[idx] = 0;

        itemnum = itemnums[idx2];

        mMpswd_make_passcode( passcode, 4, 1, playername, townname, itemnum, 0, codetype );
        mMpswd_substitution_cipher( passcode );
        mMpswd_transposition_cipher( passcode, 1, 0 );
        mMpswd_bit_shuffle( passcode, 0 );
        mMpswd_chg_RSA_cipher( passcode );
        mMpswd_bit_mix_code( passcode );
        mMpswd_bit_shuffle( passcode, 1 );
        mMpswd_transposition_cipher( passcode, 0, 1 );
        mMpswd_chg_6bits_code( finalcode, passcode );
        mMpswd_chg_common_font_code( finalcode );

        itemCost = calculate_item_cost(finalcode);
        playerTownComboCost += itemCost;
        if(itemCost < minCodeCost) {
          minCodeCost = itemCost;
          strcpy(minCode, finalcode);
        }
        if(itemCost > maxCodeCost) {
          maxCodeCost = itemCost;
          strcpy(maxCode, finalcode);
        }
      }
    }

    if(playerTownComboCost < minCost) {
      minCost = playerTownComboCost;
      minPlayerName = playername[0];
      minTownName = townname[0];
    }
    if(playerTownComboCost > maxCost) {
      maxCost = playerTownComboCost;
      maxPlayerName = playername[0];
      maxTownName = townname[0];
    }

    playerTownComboCost = 0;
  }

  printf("\n");

  printf("Min player name: %c, int: %d, cost: %d\n", minPlayerName, minPlayerName, minCost);
  printf("Min town name: %c, int: %d, cost: %d\n\n", minTownName, minTownName, minCost);

  printf("Max player name: %c, int: %d, cost: %d\n", maxPlayerName, maxPlayerName, maxCost);
  printf("Max town name: %c, int: %d, cost: %d\n", maxTownName, maxTownName, maxCost);

  printf("\n");

  //TODO: Track these player and town names as well, just for fun - not necessary if I write to CSV, I guess it depends how much I write
  printf("Min code cost: %i\n", minCodeCost);
  for( idx = 0; idx < 14; idx++ )
  {
    printf( "%c", minCode[idx] );
  }
  printf( "\n" );
  for( idx = 14; idx < 28; idx++ )
  {
    printf( "%c", minCode[idx] );
  }

  printf( "\n\n" );

  printf("Max code cost: %i\n", maxCodeCost);
  for( idx = 0; idx < 14; idx++ )
  {
    printf( "%c", maxCode[idx] );
  }
  printf( "\n" );
  for( idx = 14; idx < 28; idx++ )
  {
    printf( "%c", maxCode[idx] );
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
    // printf( "switchbyte = %d\n", switchbyte );
    switch( switchbyte )
    {
    case 13:
    case 14:
    case 15:
        mMpswd_bit_arrange_reverse( passcode );
        // DisplayCode( passcode, 21 );
        mMpswd_bit_reverse( passcode );
        // DisplayCode( passcode, 21 );
        mMpswd_bit_shift( passcode, switchbyte * 3 );
        // DisplayCode( passcode, 21 );
        break;
    case 9:
    case 10:
    case 11:
    case 12:
        mMpswd_bit_arrange_reverse( passcode );
        // DisplayCode( passcode, 21 );
        mMpswd_bit_shift( passcode, ( 0 - switchbyte ) * 5 );
        // DisplayCode( passcode, 21 );
        break;
    case 5:
    case 6:
    case 7:
    case 8:
        mMpswd_bit_shift( passcode, ( 0 - switchbyte ) * 5 );
        // DisplayCode( passcode, 21 );
        mMpswd_bit_reverse( passcode );
        // DisplayCode( passcode, 21 );
        break;
    case 0:
    case 1:
    case 2:
    case 3:
    case 4:
        mMpswd_bit_shift( passcode, switchbyte * 3 );
        // DisplayCode( passcode, 21 );
        mMpswd_bit_arrange_reverse( passcode );
        // DisplayCode( passcode, 21 );
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

/**
 * Initializes the char_to_location array. This array indexes with passcode characters and returns their keyboard location
 * It a'int pretty, but it'll do
 */
void init_char_to_location()
{
  char_to_location = malloc(123 * (sizeof (keyboard_location)));

  keyboard_location small_q = { .x = 0, .y = 1, .k = SMALL};
  keyboard_location small_w = { .x = 1, .y = 1, .k = SMALL};
  keyboard_location small_e = { .x = 2, .y = 1, .k = SMALL};
  keyboard_location small_r = { .x = 3, .y = 1, .k = SMALL};
  keyboard_location small_tee = { .x = 4, .y = 1, .k = SMALL};
  keyboard_location small_y = { .x = 5, .y = 1, .k = SMALL};
  keyboard_location small_u = { .x = 6, .y = 1, .k = SMALL};
  keyboard_location small_i = { .x = 7, .y = 1, .k = SMALL};
  keyboard_location small_o = { .x = 8, .y = 1, .k = SMALL};
  keyboard_location small_p = { .x = 9, .y = 1, .k = SMALL};
  keyboard_location small_a = { .x = 0, .y = 2, .k = SMALL};
  keyboard_location small_s = { .x = 1, .y = 2, .k = SMALL};
  keyboard_location small_d = { .x = 2, .y = 2, .k = SMALL};
  keyboard_location small_f = { .x = 3, .y = 2, .k = SMALL};
  keyboard_location small_g = { .x = 4, .y = 2, .k = SMALL};
  keyboard_location small_h = { .x = 5, .y = 2, .k = SMALL};
  keyboard_location small_j = { .x = 6, .y = 2, .k = SMALL};
  keyboard_location small_k = { .x = 7, .y = 2, .k = SMALL};
  keyboard_location small_l = { .x = 8, .y = 2, .k = SMALL};
  keyboard_location small_z = { .x = 0, .y = 3, .k = SMALL};
  keyboard_location small_x = { .x = 1, .y = 3, .k = SMALL};
  keyboard_location small_c = { .x = 2, .y = 3, .k = SMALL};
  keyboard_location small_v = { .x = 3, .y = 3, .k = SMALL};
  keyboard_location small_b = { .x = 4, .y = 3, .k = SMALL};
  keyboard_location small_n = { .x = 5, .y = 3, .k = SMALL};
  keyboard_location small_m = { .x = 6, .y = 3, .k = SMALL};

  keyboard_location big_2 = { .x = 1, .y = 0, .k = BIG};
  keyboard_location big_3 = { .x = 2, .y = 0, .k = BIG};
  keyboard_location big_4 = { .x = 3, .y = 0, .k = BIG};
  keyboard_location big_5 = { .x = 4, .y = 0, .k = BIG};
  keyboard_location big_6 = { .x = 5, .y = 0, .k = BIG};
  keyboard_location big_7 = { .x = 6, .y = 0, .k = BIG};
  keyboard_location big_8 = { .x = 7, .y = 0, .k = BIG};
  keyboard_location big_9 = { .x = 8, .y = 0, .k = BIG};
  keyboard_location big_q = { .x = 0, .y = 1, .k = BIG};
  keyboard_location big_w = { .x = 1, .y = 1, .k = BIG};
  keyboard_location big_e = { .x = 2, .y = 1, .k = BIG};
  keyboard_location big_r = { .x = 3, .y = 1, .k = BIG};
  keyboard_location big_tee = { .x = 4, .y = 1, .k = BIG};
  keyboard_location big_y = { .x = 5, .y = 1, .k = BIG};
  keyboard_location big_u = { .x = 6, .y = 1, .k = BIG};
  keyboard_location big_i = { .x = 7, .y = 1, .k = BIG};
  keyboard_location big_o = { .x = 8, .y = 1, .k = BIG};
  keyboard_location big_p = { .x = 9, .y = 1, .k = BIG};
  keyboard_location big_a = { .x = 0, .y = 2, .k = BIG};
  keyboard_location big_s = { .x = 1, .y = 2, .k = BIG};
  keyboard_location big_d = { .x = 2, .y = 2, .k = BIG};
  keyboard_location big_f = { .x = 3, .y = 2, .k = BIG};
  keyboard_location big_g = { .x = 4, .y = 2, .k = BIG};
  keyboard_location big_h = { .x = 5, .y = 2, .k = BIG};
  keyboard_location big_j = { .x = 6, .y = 2, .k = BIG};
  keyboard_location big_k = { .x = 7, .y = 2, .k = BIG};
  keyboard_location big_l = { .x = 8, .y = 2, .k = BIG};
  keyboard_location big_z = { .x = 0, .y = 3, .k = BIG};
  keyboard_location big_x = { .x = 1, .y = 3, .k = BIG};
  keyboard_location big_c = { .x = 2, .y = 3, .k = BIG};
  keyboard_location big_v = { .x = 3, .y = 3, .k = BIG};
  keyboard_location big_b = { .x = 4, .y = 3, .k = BIG};
  keyboard_location big_n = { .x = 5, .y = 3, .k = BIG};
  keyboard_location big_m = { .x = 6, .y = 3, .k = BIG};

  keyboard_location punct_pound =   { .x = 0, .y = 0, .k = PUNCT};
  keyboard_location punct_percent = { .x = 0, .y = 1, .k = PUNCT};
  keyboard_location punct_and =     { .x = 1, .y = 1, .k = PUNCT};
  keyboard_location punct_at =      { .x = 2, .y = 1, .k = PUNCT};

  char_to_location['q'] = small_q;
  char_to_location['w'] = small_w;
  char_to_location['e'] = small_e;
  char_to_location['r'] = small_r;
  char_to_location['t'] = small_tee;
  char_to_location['y'] = small_y;
  char_to_location['u'] = small_u;
  char_to_location['i'] = small_i;
  char_to_location['o'] = small_o;
  char_to_location['p'] = small_p;
  char_to_location['a'] = small_a;
  char_to_location['s'] = small_s;
  char_to_location['d'] = small_d;
  char_to_location['f'] = small_f;
  char_to_location['g'] = small_g;
  char_to_location['h'] = small_h;
  char_to_location['j'] = small_j;
  char_to_location['k'] = small_k;
  char_to_location['l'] = small_l;
  char_to_location['z'] = small_z;
  char_to_location['x'] = small_x;
  char_to_location['c'] = small_c;
  char_to_location['v'] = small_v;
  char_to_location['b'] = small_b;
  char_to_location['n'] = small_n;
  char_to_location['m'] = small_m;

  char_to_location['2'] = big_2;
  char_to_location['3'] = big_3;
  char_to_location['4'] = big_4;
  char_to_location['5'] = big_5;
  char_to_location['6'] = big_6;
  char_to_location['7'] = big_7;
  char_to_location['8'] = big_8;
  char_to_location['9'] = big_9;
  char_to_location['Q'] = big_q;
  char_to_location['W'] = big_w;
  char_to_location['E'] = big_e;
  char_to_location['R'] = big_r;
  char_to_location['T'] = big_tee;
  char_to_location['Y'] = big_y;
  char_to_location['U'] = big_u;
  char_to_location['I'] = big_i;
  char_to_location['O'] = big_o;
  char_to_location['P'] = big_p;
  char_to_location['A'] = big_a;
  char_to_location['S'] = big_s;
  char_to_location['D'] = big_d;
  char_to_location['F'] = big_f;
  char_to_location['G'] = big_g;
  char_to_location['H'] = big_h;
  char_to_location['J'] = big_j;
  char_to_location['K'] = big_k;
  char_to_location['L'] = big_l;
  char_to_location['Z'] = big_z;
  char_to_location['X'] = big_x;
  char_to_location['C'] = big_c;
  char_to_location['V'] = big_v;
  char_to_location['B'] = big_b;
  char_to_location['N'] = big_n;
  char_to_location['M'] = big_m;

  char_to_location['#'] = punct_pound;
  char_to_location['%'] = punct_percent;
  char_to_location['&'] = punct_and;
  char_to_location['@'] = punct_at;
}

/**
 * Calculates how many button inputs are necessary to input the given code.
 * Assumes moving the cursor is just as time consuming as swapping keyboards, which may not be true and may be changed later after some experimentation.
 */
unsigned int calculate_item_cost( unsigned char* finalcode)
{
  unsigned int cost = 0;
  unsigned int i = 0;
  keyboard_location curr_location = { .x = 0, .y = 0, .k = SMALL };

  for(i = 0; i < 28; i++) {
    keyboard_location destination = char_to_location[finalcode[i]];
    // printf("curr location: %i, %i, %i\n", curr_location.x, curr_location.y, curr_location.k);
    // printf("destination: %i, %i, %i\n", destination.x, destination.y, destination.k);

    cost += abs(destination.x - curr_location.x);
    cost += abs(destination.y - curr_location.y);

    //TODO: This can be compressed
    if(destination.k != curr_location.k) {
      switch(curr_location.k) {
        case SMALL:
          switch(destination.k) {
            case BIG:
            case PUNCT:
              cost += 1;
              break;
          }
          break;
        case BIG:
          switch(destination.k) {
            case SMALL:
            case PUNCT:
              cost += 1;
              break;
          }
          break;
        case PUNCT:
          switch(destination.k) {
            case SMALL:
            case BIG:
              cost += 2;
              break;
          }
          break;
      }
    }

    curr_location = char_to_location[finalcode[i]];
  }

  return cost;
}
