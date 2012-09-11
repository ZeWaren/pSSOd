#!/usr/local/bin/perl

# Provides functions to extract the binary version of the keytable
# of the DES algorithm, used by pSSOD.
#
# ZeWaren / Erwan Martin <public@fzwte.net>, http://zewaren.net
# License: MIT
#
# Most of this code comes from Crypt::TripleDES (PPDES.pm), created by:
# Vipul Ved Prakash, mail@vipul.net
# Eric Young, eay@psych.psy.uq.oz.au
# Jonathan Mayer <jmayer@cobaltnet.com>

@skb0=(
# for C bits (numbered as per FIPS 46) 1 2 3 4 5 6 
0x00000000,0x00000010,0x20000000,0x20000010,
0x00010000,0x00010010,0x20010000,0x20010010,
0x00000800,0x00000810,0x20000800,0x20000810,
0x00010800,0x00010810,0x20010800,0x20010810,
0x00000020,0x00000030,0x20000020,0x20000030,
0x00010020,0x00010030,0x20010020,0x20010030,
0x00000820,0x00000830,0x20000820,0x20000830,
0x00010820,0x00010830,0x20010820,0x20010830,
0x00080000,0x00080010,0x20080000,0x20080010,
0x00090000,0x00090010,0x20090000,0x20090010,
0x00080800,0x00080810,0x20080800,0x20080810,
0x00090800,0x00090810,0x20090800,0x20090810,
0x00080020,0x00080030,0x20080020,0x20080030,
0x00090020,0x00090030,0x20090020,0x20090030,
0x00080820,0x00080830,0x20080820,0x20080830,
0x00090820,0x00090830,0x20090820,0x20090830,
);
@skb1=(
# for C bits (numbered as per FIPS 46) 7 8 10 11 12 13 
0x00000000,0x02000000,0x00002000,0x02002000,
0x00200000,0x02200000,0x00202000,0x02202000,
0x00000004,0x02000004,0x00002004,0x02002004,
0x00200004,0x02200004,0x00202004,0x02202004,
0x00000400,0x02000400,0x00002400,0x02002400,
0x00200400,0x02200400,0x00202400,0x02202400,
0x00000404,0x02000404,0x00002404,0x02002404,
0x00200404,0x02200404,0x00202404,0x02202404,
0x10000000,0x12000000,0x10002000,0x12002000,
0x10200000,0x12200000,0x10202000,0x12202000,
0x10000004,0x12000004,0x10002004,0x12002004,
0x10200004,0x12200004,0x10202004,0x12202004,
0x10000400,0x12000400,0x10002400,0x12002400,
0x10200400,0x12200400,0x10202400,0x12202400,
0x10000404,0x12000404,0x10002404,0x12002404,
0x10200404,0x12200404,0x10202404,0x12202404,
);
@skb2=(
# for C bits (numbered as per FIPS 46) 14 15 16 17 19 20 
0x00000000,0x00000001,0x00040000,0x00040001,
0x01000000,0x01000001,0x01040000,0x01040001,
0x00000002,0x00000003,0x00040002,0x00040003,
0x01000002,0x01000003,0x01040002,0x01040003,
0x00000200,0x00000201,0x00040200,0x00040201,
0x01000200,0x01000201,0x01040200,0x01040201,
0x00000202,0x00000203,0x00040202,0x00040203,
0x01000202,0x01000203,0x01040202,0x01040203,
0x08000000,0x08000001,0x08040000,0x08040001,
0x09000000,0x09000001,0x09040000,0x09040001,
0x08000002,0x08000003,0x08040002,0x08040003,
0x09000002,0x09000003,0x09040002,0x09040003,
0x08000200,0x08000201,0x08040200,0x08040201,
0x09000200,0x09000201,0x09040200,0x09040201,
0x08000202,0x08000203,0x08040202,0x08040203,
0x09000202,0x09000203,0x09040202,0x09040203,
);
@skb3=(
# for C bits (numbered as per FIPS 46) 21 23 24 26 27 28 
0x00000000,0x00100000,0x00000100,0x00100100,
0x00000008,0x00100008,0x00000108,0x00100108,
0x00001000,0x00101000,0x00001100,0x00101100,
0x00001008,0x00101008,0x00001108,0x00101108,
0x04000000,0x04100000,0x04000100,0x04100100,
0x04000008,0x04100008,0x04000108,0x04100108,
0x04001000,0x04101000,0x04001100,0x04101100,
0x04001008,0x04101008,0x04001108,0x04101108,
0x00020000,0x00120000,0x00020100,0x00120100,
0x00020008,0x00120008,0x00020108,0x00120108,
0x00021000,0x00121000,0x00021100,0x00121100,
0x00021008,0x00121008,0x00021108,0x00121108,
0x04020000,0x04120000,0x04020100,0x04120100,
0x04020008,0x04120008,0x04020108,0x04120108,
0x04021000,0x04121000,0x04021100,0x04121100,
0x04021008,0x04121008,0x04021108,0x04121108,
);
@skb4=(
# for D bits (numbered as per FIPS 46) 1 2 3 4 5 6 
0x00000000,0x10000000,0x00010000,0x10010000,
0x00000004,0x10000004,0x00010004,0x10010004,
0x20000000,0x30000000,0x20010000,0x30010000,
0x20000004,0x30000004,0x20010004,0x30010004,
0x00100000,0x10100000,0x00110000,0x10110000,
0x00100004,0x10100004,0x00110004,0x10110004,
0x20100000,0x30100000,0x20110000,0x30110000,
0x20100004,0x30100004,0x20110004,0x30110004,
0x00001000,0x10001000,0x00011000,0x10011000,
0x00001004,0x10001004,0x00011004,0x10011004,
0x20001000,0x30001000,0x20011000,0x30011000,
0x20001004,0x30001004,0x20011004,0x30011004,
0x00101000,0x10101000,0x00111000,0x10111000,
0x00101004,0x10101004,0x00111004,0x10111004,
0x20101000,0x30101000,0x20111000,0x30111000,
0x20101004,0x30101004,0x20111004,0x30111004,
);
@skb5=(
# for D bits (numbered as per FIPS 46) 8 9 11 12 13 14 
0x00000000,0x08000000,0x00000008,0x08000008,
0x00000400,0x08000400,0x00000408,0x08000408,
0x00020000,0x08020000,0x00020008,0x08020008,
0x00020400,0x08020400,0x00020408,0x08020408,
0x00000001,0x08000001,0x00000009,0x08000009,
0x00000401,0x08000401,0x00000409,0x08000409,
0x00020001,0x08020001,0x00020009,0x08020009,
0x00020401,0x08020401,0x00020409,0x08020409,
0x02000000,0x0A000000,0x02000008,0x0A000008,
0x02000400,0x0A000400,0x02000408,0x0A000408,
0x02020000,0x0A020000,0x02020008,0x0A020008,
0x02020400,0x0A020400,0x02020408,0x0A020408,
0x02000001,0x0A000001,0x02000009,0x0A000009,
0x02000401,0x0A000401,0x02000409,0x0A000409,
0x02020001,0x0A020001,0x02020009,0x0A020009,
0x02020401,0x0A020401,0x02020409,0x0A020409,
);
@skb6=(
# for D bits (numbered as per FIPS 46) 16 17 18 19 20 21 
0x00000000,0x00000100,0x00080000,0x00080100,
0x01000000,0x01000100,0x01080000,0x01080100,
0x00000010,0x00000110,0x00080010,0x00080110,
0x01000010,0x01000110,0x01080010,0x01080110,
0x00200000,0x00200100,0x00280000,0x00280100,
0x01200000,0x01200100,0x01280000,0x01280100,
0x00200010,0x00200110,0x00280010,0x00280110,
0x01200010,0x01200110,0x01280010,0x01280110,
0x00000200,0x00000300,0x00080200,0x00080300,
0x01000200,0x01000300,0x01080200,0x01080300,
0x00000210,0x00000310,0x00080210,0x00080310,
0x01000210,0x01000310,0x01080210,0x01080310,
0x00200200,0x00200300,0x00280200,0x00280300,
0x01200200,0x01200300,0x01280200,0x01280300,
0x00200210,0x00200310,0x00280210,0x00280310,
0x01200210,0x01200310,0x01280210,0x01280310,
);
@skb7=(
# for D bits (numbered as per FIPS 46) 22 23 24 25 27 28 
0x00000000,0x04000000,0x00040000,0x04040000,
0x00000002,0x04000002,0x00040002,0x04040002,
0x00002000,0x04002000,0x00042000,0x04042000,
0x00002002,0x04002002,0x00042002,0x04042002,
0x00000020,0x04000020,0x00040020,0x04040020,
0x00000022,0x04000022,0x00040022,0x04040022,
0x00002020,0x04002020,0x00042020,0x04042020,
0x00002022,0x04002022,0x00042022,0x04042022,
0x00000800,0x04000800,0x00040800,0x04040800,
0x00000802,0x04000802,0x00040802,0x04040802,
0x00002800,0x04002800,0x00042800,0x04042800,
0x00002802,0x04002802,0x00042802,0x04042802,
0x00000820,0x04000820,0x00040820,0x04040820,
0x00000822,0x04000822,0x00040822,0x04040822,
0x00002820,0x04002820,0x00042820,0x04042820,
0x00002822,0x04002822,0x00042822,0x04042822,
);

@shifts2=(0,0,1,1,1,1,1,1,0,1,1,1,1,1,1,0);

# used in ecb_encrypt
@SP0=(
0x00410100, 0x00010000, 0x40400000, 0x40410100,
0x00400000, 0x40010100, 0x40010000, 0x40400000,
0x40010100, 0x00410100, 0x00410000, 0x40000100,
0x40400100, 0x00400000, 0x00000000, 0x40010000,
0x00010000, 0x40000000, 0x00400100, 0x00010100,
0x40410100, 0x00410000, 0x40000100, 0x00400100,
0x40000000, 0x00000100, 0x00010100, 0x40410000,
0x00000100, 0x40400100, 0x40410000, 0x00000000,
0x00000000, 0x40410100, 0x00400100, 0x40010000,
0x00410100, 0x00010000, 0x40000100, 0x00400100,
0x40410000, 0x00000100, 0x00010100, 0x40400000,
0x40010100, 0x40000000, 0x40400000, 0x00410000,
0x40410100, 0x00010100, 0x00410000, 0x40400100,
0x00400000, 0x40000100, 0x40010000, 0x00000000,
0x00010000, 0x00400000, 0x40400100, 0x00410100,
0x40000000, 0x40410000, 0x00000100, 0x40010100,
);
@SP1=(
0x08021002, 0x00000000, 0x00021000, 0x08020000,
0x08000002, 0x00001002, 0x08001000, 0x00021000,
0x00001000, 0x08020002, 0x00000002, 0x08001000,
0x00020002, 0x08021000, 0x08020000, 0x00000002,
0x00020000, 0x08001002, 0x08020002, 0x00001000,
0x00021002, 0x08000000, 0x00000000, 0x00020002,
0x08001002, 0x00021002, 0x08021000, 0x08000002,
0x08000000, 0x00020000, 0x00001002, 0x08021002,
0x00020002, 0x08021000, 0x08001000, 0x00021002,
0x08021002, 0x00020002, 0x08000002, 0x00000000,
0x08000000, 0x00001002, 0x00020000, 0x08020002,
0x00001000, 0x08000000, 0x00021002, 0x08001002,
0x08021000, 0x00001000, 0x00000000, 0x08000002,
0x00000002, 0x08021002, 0x00021000, 0x08020000,
0x08020002, 0x00020000, 0x00001002, 0x08001000,
0x08001002, 0x00000002, 0x08020000, 0x00021000,
);
@SP2=(
0x20800000, 0x00808020, 0x00000020, 0x20800020,
0x20008000, 0x00800000, 0x20800020, 0x00008020,
0x00800020, 0x00008000, 0x00808000, 0x20000000,
0x20808020, 0x20000020, 0x20000000, 0x20808000,
0x00000000, 0x20008000, 0x00808020, 0x00000020,
0x20000020, 0x20808020, 0x00008000, 0x20800000,
0x20808000, 0x00800020, 0x20008020, 0x00808000,
0x00008020, 0x00000000, 0x00800000, 0x20008020,
0x00808020, 0x00000020, 0x20000000, 0x00008000,
0x20000020, 0x20008000, 0x00808000, 0x20800020,
0x00000000, 0x00808020, 0x00008020, 0x20808000,
0x20008000, 0x00800000, 0x20808020, 0x20000000,
0x20008020, 0x20800000, 0x00800000, 0x20808020,
0x00008000, 0x00800020, 0x20800020, 0x00008020,
0x00800020, 0x00000000, 0x20808000, 0x20000020,
0x20800000, 0x20008020, 0x00000020, 0x00808000,
);
@SP3=(
0x00080201, 0x02000200, 0x00000001, 0x02080201,
0x00000000, 0x02080000, 0x02000201, 0x00080001,
0x02080200, 0x02000001, 0x02000000, 0x00000201,
0x02000001, 0x00080201, 0x00080000, 0x02000000,
0x02080001, 0x00080200, 0x00000200, 0x00000001,
0x00080200, 0x02000201, 0x02080000, 0x00000200,
0x00000201, 0x00000000, 0x00080001, 0x02080200,
0x02000200, 0x02080001, 0x02080201, 0x00080000,
0x02080001, 0x00000201, 0x00080000, 0x02000001,
0x00080200, 0x02000200, 0x00000001, 0x02080000,
0x02000201, 0x00000000, 0x00000200, 0x00080001,
0x00000000, 0x02080001, 0x02080200, 0x00000200,
0x02000000, 0x02080201, 0x00080201, 0x00080000,
0x02080201, 0x00000001, 0x02000200, 0x00080201,
0x00080001, 0x00080200, 0x02080000, 0x02000201,
0x00000201, 0x02000000, 0x02000001, 0x02080200,
);
@SP4=(
0x01000000, 0x00002000, 0x00000080, 0x01002084,
0x01002004, 0x01000080, 0x00002084, 0x01002000,
0x00002000, 0x00000004, 0x01000004, 0x00002080,
0x01000084, 0x01002004, 0x01002080, 0x00000000,
0x00002080, 0x01000000, 0x00002004, 0x00000084,
0x01000080, 0x00002084, 0x00000000, 0x01000004,
0x00000004, 0x01000084, 0x01002084, 0x00002004,
0x01002000, 0x00000080, 0x00000084, 0x01002080,
0x01002080, 0x01000084, 0x00002004, 0x01002000,
0x00002000, 0x00000004, 0x01000004, 0x01000080,
0x01000000, 0x00002080, 0x01002084, 0x00000000,
0x00002084, 0x01000000, 0x00000080, 0x00002004,
0x01000084, 0x00000080, 0x00000000, 0x01002084,
0x01002004, 0x01002080, 0x00000084, 0x00002000,
0x00002080, 0x01002004, 0x01000080, 0x00000084,
0x00000004, 0x00002084, 0x01002000, 0x01000004,
);
@SP5=(
0x10000008, 0x00040008, 0x00000000, 0x10040400,
0x00040008, 0x00000400, 0x10000408, 0x00040000,
0x00000408, 0x10040408, 0x00040400, 0x10000000,
0x10000400, 0x10000008, 0x10040000, 0x00040408,
0x00040000, 0x10000408, 0x10040008, 0x00000000,
0x00000400, 0x00000008, 0x10040400, 0x10040008,
0x10040408, 0x10040000, 0x10000000, 0x00000408,
0x00000008, 0x00040400, 0x00040408, 0x10000400,
0x00000408, 0x10000000, 0x10000400, 0x00040408,
0x10040400, 0x00040008, 0x00000000, 0x10000400,
0x10000000, 0x00000400, 0x10040008, 0x00040000,
0x00040008, 0x10040408, 0x00040400, 0x00000008,
0x10040408, 0x00040400, 0x00040000, 0x10000408,
0x10000008, 0x10040000, 0x00040408, 0x00000000,
0x00000400, 0x10000008, 0x10000408, 0x10040400,
0x10040000, 0x00000408, 0x00000008, 0x10040008,
);
@SP6=(
0x00000800, 0x00000040, 0x00200040, 0x80200000,
0x80200840, 0x80000800, 0x00000840, 0x00000000,
0x00200000, 0x80200040, 0x80000040, 0x00200800,
0x80000000, 0x00200840, 0x00200800, 0x80000040,
0x80200040, 0x00000800, 0x80000800, 0x80200840,
0x00000000, 0x00200040, 0x80200000, 0x00000840,
0x80200800, 0x80000840, 0x00200840, 0x80000000,
0x80000840, 0x80200800, 0x00000040, 0x00200000,
0x80000840, 0x00200800, 0x80200800, 0x80000040,
0x00000800, 0x00000040, 0x00200000, 0x80200800,
0x80200040, 0x80000840, 0x00000840, 0x00000000,
0x00000040, 0x80200000, 0x80000000, 0x00200040,
0x00000000, 0x80200040, 0x00200040, 0x00000840,
0x80000040, 0x00000800, 0x80200840, 0x00200000,
0x00200840, 0x80000000, 0x80000800, 0x80200840,
0x80200000, 0x00200840, 0x00200800, 0x80000800,
);
@SP7=(
0x04100010, 0x04104000, 0x00004010, 0x00000000,
0x04004000, 0x00100010, 0x04100000, 0x04104010,
0x00000010, 0x04000000, 0x00104000, 0x00004010,
0x00104010, 0x04004010, 0x04000010, 0x04100000,
0x00004000, 0x00104010, 0x00100010, 0x04004000,
0x04104010, 0x04000010, 0x00000000, 0x00104000,
0x04000000, 0x00100000, 0x04004010, 0x04100010,
0x00100000, 0x00004000, 0x04104000, 0x00000010,
0x00100000, 0x00004000, 0x04000010, 0x04104010,
0x00004010, 0x04000000, 0x00000000, 0x00104000,
0x04100010, 0x04004010, 0x04004000, 0x00100010,
0x04104000, 0x00000010, 0x00100010, 0x04004000,
0x04104010, 0x00100000, 0x04100000, 0x04000010,
0x00104000, 0x00004010, 0x04004010, 0x04100000,
0x00000010, 0x04104000, 0x00104010, 0x00000000,
0x04000000, 0x04100010, 0x00004000, 0x00104010,
);

sub doPC1 {
	local(*a,*b)=@_;
	local($t);

	$t=(($b>>4)^$a)&0x0f0f0f0f;
	$b^=($t<<4); $a^=$t;
	# do $a first 
	$t=(($a<<18)^$a)&0xcccc0000;
	$a=$a^$t^($t>>18);
	$t=(($a<<17)^$a)&0xaaaa0000;
	$a=$a^$t^($t>>17);
	$t=(($a<< 8)^$a)&0x00ff0000;
	$a=$a^$t^($t>> 8);
	$t=(($a<<17)^$a)&0xaaaa0000;
	$a=$a^$t^($t>>17);

	# now do $b
	$t=(($b<<24)^$b)&0xff000000;
	$b=$b^$t^($t>>24);
	$t=(($b<< 8)^$b)&0x00ff0000;
	$b=$b^$t^($t>> 8);
	$t=(($b<<14)^$b)&0x33330000;
	$b=$b^$t^($t>>14);
	$b=(($b&0x00aa00aa)<<7)|(($b&0x55005500)>>7)|($b&0xaa55aa55);
	$b=($b>>8)|(($a&0xf0000000)>>4);
	$a&=0x0fffffff;
}

sub des_get_key_table {
	local($param)=@_;
	local(@key);
	local($c,$d,$i,$s,$t);
	local(@ks)=();

	# Get the bytes in the order we want.
	@key=unpack("C8",$param);
 	push (@key, 0,0,0,0,0,0,0,0); 

	$c=	($key[0]    )|
		($key[1]<< 8)|
		($key[2]<<16)|
		($key[3]<<24);
	$d=	($key[4]    )|
		($key[5]<< 8)|
		($key[6]<<16)|
		($key[7]<<24);

	&doPC1(*c,*d);

	for $i (@shifts2) {
		if ($i) {
			$c=($c>>2)|($c<<26);
			$d=($d>>2)|($d<<26);
		}
		else {
			$c=($c>>1)|($c<<27);
			$d=($d>>1)|($d<<27);
		}
		$c&=0x0fffffff;
		$d&=0x0fffffff;
		$s=	$skb0[ ($c    )&0x3f                 ]|
			$skb1[(($c>> 6)&0x03)|(($c>> 7)&0x3c)]|
			$skb2[(($c>>13)&0x0f)|(($c>>14)&0x30)]|
			$skb3[(($c>>20)&0x01)|(($c>>21)&0x06) |
			(($c>>22)&0x38)];
		$t= $skb4[ ($d    )&0x3f                 ]|
			$skb5[(($d>> 7)&0x03)|(($d>> 8)&0x3c)]|
			$skb6[ ($d>>15)&0x3f                 ]|
			$skb7[(($d>>21)&0x0f)|(($d>>22)&0x30)];

		#This part is different from the original:
        $temp = (($t << 16) | ($s & 0x0000ffff)) & 0xffffffff;
        push(@ks, (($temp << 2)&0xffffffff)|($temp >> (32 - 2)));

        $temp = (($s >> 16) | ($t & 0xffff0000))  & 0xffffffff;
        push(@ks, (($temp << 6)&0xffffffff)|($temp >> (32 - 6)));
	}
	@ks;
}

1;
