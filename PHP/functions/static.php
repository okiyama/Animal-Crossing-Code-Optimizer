<?php
//////////////////////////////////////////////////////
// static.php                                       //
//////////////////////////////////////////////////////
// Static values to be loaded in the code generator //
//////////////////////////////////////////////////////

//////////////////////////////////////////////////////
// Constants
//
// Various constants used in certain functions.
//////////////////////////////////////////////////////
define("ACUC_DIRECTION_FORWARD", 1);
define("ACUC_DIRECTION_BACKWARD", -1);

//
//
//
$acucTypes = array(0 => "Player-to-Player (P)", 1 => "NES Contest (N)", 2 => "Universal (U)", 3 => "Villager Code (V - NTSC only)", 4 => "Contest (C)");

$acucCodeTypes = array();

$acucCodeTypes[0x02] = 1;
$acucCodeTypes[0x03] = 1;
$acucCodeTypes[0x40] = 4;
$acucCodeTypes[0x46] = 3;
$acucCodeTypes[0x61] = 2;
$acucCodeTypes[0x62] = 2;
$acucCodeTypes[0x82] = 0;
$acucCodeTypes[0xa2] = 4;
$acucCodeTypes[0xa3] = 4;

//////////////////////////////////////////////////////
// $acucUsableChars
//
// An array to translate usable (code) characters
// to their corresponding value for decoding.
//////////////////////////////////////////////////////
$acucUsableChars = Array(
	0x62, 0x4b, 0x7a, 0x35, 0x63, 0x71, 0x59, 0x5a, 0x4f, 0x64, 0x74, 0x36, 0x6e, 0x6c, 0x42, 0x79,
	0x6f, 0x38, 0x34, 0x4c, 0x6b, 0x25, 0x41, 0x51, 0x6d, 0x44, 0x50, 0x49, 0x37, 0x26, 0x52, 0x73,
	0x77, 0x55, 0x23, 0x72, 0x33, 0x45, 0x78, 0x4d, 0x43, 0x40, 0x65, 0x39, 0x67, 0x76, 0x56, 0x47,
	0x75, 0x4e, 0x69, 0x58, 0x57, 0x66, 0x54, 0x4a, 0x46, 0x53, 0x48, 0x70, 0x32, 0x61, 0x6a, 0x68);


//////////////////////////////////////////////////////
// $acucSelectIndexTable
//
// An array of values used as modifiers for certain
// functions.
//////////////////////////////////////////////////////
$acucSelectIndexTable = Array();

$acucSelectIndexTable[0] = Array( 0x11, 0x0b, 0x00, 0x0a, 0x0c, 0x06, 0x08, 0x04 );
$acucSelectIndexTable[1] = Array( 0x03, 0x08, 0x0b, 0x10, 0x04, 0x06, 0x09, 0x13 );
$acucSelectIndexTable[2] = Array( 0x09, 0x0e, 0x11, 0x12, 0x0b, 0x0a, 0x0c, 0x02 );
$acucSelectIndexTable[3] = Array( 0x00, 0x02, 0x01, 0x04, 0x12, 0x0a, 0x0c, 0x08 );
$acucSelectIndexTable[4] = Array( 0x11, 0x13, 0x10, 0x07, 0x0c, 0x08, 0x02, 0x09 );
$acucSelectIndexTable[5] = Array( 0x10, 0x03, 0x01, 0x08, 0x12, 0x04, 0x07, 0x06 );
$acucSelectIndexTable[6] = Array( 0x13, 0x06, 0x0a, 0x11, 0x03, 0x10, 0x08, 0x09 );
$acucSelectIndexTable[7] = Array( 0x11, 0x07, 0x12, 0x10, 0x0c, 0x02, 0x0b, 0x00 );
$acucSelectIndexTable[8] = Array( 0x06, 0x02, 0x0c, 0x01, 0x08, 0x0e, 0x00, 0x10 );
$acucSelectIndexTable[9] = Array( 0x13, 0x10, 0x0b, 0x08, 0x11, 0x03, 0x06, 0x0e );
$acucSelectIndexTable[10] = Array( 0x12, 0x0c, 0x02, 0x07, 0x0a, 0x0b, 0x01, 0x0e );
$acucSelectIndexTable[11] = Array( 0x08, 0x00, 0x0e, 0x02, 0x07, 0x0b, 0x0c, 0x11 );
$acucSelectIndexTable[12] = Array( 0x09, 0x03, 0x02, 0x00, 0x0b, 0x08, 0x0e, 0x0a );
$acucSelectIndexTable[13] = Array( 0x0a, 0x0b, 0x0c, 0x10, 0x13, 0x07, 0x11, 0x08 );
$acucSelectIndexTable[14] = Array( 0x13, 0x08, 0x06, 0x01, 0x11, 0x09, 0x0e, 0x0a );
$acucSelectIndexTable[15] = Array( 0x09, 0x07, 0x11, 0x0c, 0x13, 0x0a, 0x01, 0x0b );

//////////////////////////////////////////////////////
// $acucPrimes
//
// An array with prime numbers, from 11 to 1667.
//////////////////////////////////////////////////////
$acucPrimes = Array(
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
	0x064d, 0x0653, 0x0655, 0x065b, 0x0665, 0x0679, 0x067f, 0x0683 );

//////////////////////////////////////////////////////
// $acucCodeChangeTable
//
// An array with values to substitute characters
// with another character, as a way to encrypt
// the code.
//////////////////////////////////////////////////////
$acucCodeChangeTable = Array(
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
    0x6b, 0x30, 0xec, 0x4b, 0x48, 0x1c, 0xad, 0xe2, 0x21, 0x1e, 0xa2, 0xbd, 0x5a, 0xd8, 0x43, 0x7a );

//////////////////////////////////////////////////////
// $acucStringModifier
//
// An array with strings that act as modifiers.
//////////////////////////////////////////////////////
$acucStringModifier = Array(
	"NiiMasaru",
	"KomatsuKunihiro",
	"TakakiGentarou",
	"MiyakeHiromichi",
	"HayakawaKenzo",
	"KasamatsuShigehiro",
	"SumiyoshiNobuhiro",
	"NomaTakafumi",
	"EguchiKatsuya",
	"NogamiHisashi",
	"IidaToki",
	"IkegawaNoriko",
	"KawaseTomohiro",
	"BandoTaro",
	"TotakaKazuo",
	"WatanabeKunio",
	"RichAmtower",
	"KyleHudson",
	"MichaelKelbaugh",
	"RaycholeLAneff",
	"LeslieSwan",
	"YoshinobuMantani",
	"KirkBuchanan",
	"TimOLeary",
	"BillTrinen",
	"nAkAyOsInoNyuuSankin",
	"zendamaKINAKUDAMAkin",
	"OishikutetUYOKUNARU",
	"AsetoAminofen",
	"fcSFCn64GCgbCGBagbVB",
	"YossyIsland",
	"KedamonoNoMori" );

//////////////////////////////////////////////////////
// $acucKeyIndex
//
// A small array determining which value of the
// current set of data should act as the modifier.
//////////////////////////////////////////////////////
$acucKeyIndex = Array(0x00000012, 0x00000009);

?>