unit PasOpenSSL;

interface

uses
 System.SysUtils, System.Variants, System.Classes, Winapi.Windows, IdSSLOpenSSLHeaders, IdSSL, IdSSLOpenSSL;



type
  TSupportCipherList = record
    Alog: string;
    Mode: string;
  end;
  PPBIGNUM = ^PBIGNUM;

type {$Z4} Tpoint_conversion_form = (POINT_CONVERSION_COMPRESSED=2, POINT_CONVERSION_UNCOMPRESSED=4, POINT_CONVERSION_HYBRID=6);


const NID_sm2 = 1172;
const EVP_PKEY_SM2 = NID_sm2;

const EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID = (EVP_PKEY_ALG_CTRL + 1);
const EVP_PKEY_CTRL_EC_PARAM_ENC          = (EVP_PKEY_ALG_CTRL + 2);
const EVP_PKEY_CTRL_EC_ECDH_COFACTOR      = (EVP_PKEY_ALG_CTRL + 3);
const EVP_PKEY_CTRL_EC_KDF_TYPE           = (EVP_PKEY_ALG_CTRL + 4);
const EVP_PKEY_CTRL_EC_KDF_MD             = (EVP_PKEY_ALG_CTRL + 5);
const EVP_PKEY_CTRL_GET_EC_KDF_MD         = (EVP_PKEY_ALG_CTRL + 6);
const EVP_PKEY_CTRL_EC_KDF_OUTLEN         = (EVP_PKEY_ALG_CTRL + 7);
const EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN     = (EVP_PKEY_ALG_CTRL + 8);
const EVP_PKEY_CTRL_EC_KDF_UKM            = (EVP_PKEY_ALG_CTRL + 9);
const EVP_PKEY_CTRL_GET_EC_KDF_UKM        = (EVP_PKEY_ALG_CTRL + 10);
const EVP_PKEY_CTRL_SET1_ID               = (EVP_PKEY_ALG_CTRL + 11);
const EVP_PKEY_CTRL_GET1_ID               = (EVP_PKEY_ALG_CTRL + 12);
const EVP_PKEY_CTRL_GET1_ID_LEN           = (EVP_PKEY_ALG_CTRL + 13);

const SupportCipherCount = 37;
const SupportCipherList : array [0..SupportCipherCount-1] of TSupportCipherList = (
  (Alog: 'sm4';         Mode: 'ecb'),
  (Alog: 'sm4';         Mode: 'cbc'),
  (Alog: 'sm4';         Mode: 'cfb'),
  (Alog: 'sm4';         Mode: 'ofb'),
  (Alog: 'sm4';         Mode: 'ctr'),

  (Alog: 'aes-128';     Mode: 'ecb'),
  (Alog: 'aes-128';     Mode: 'cbc'),

  (Alog: 'aes-192';     Mode: 'ecb'),
  (Alog: 'aes-192';     Mode: 'cbc'),

  (Alog: 'aes-256';     Mode: 'ecb'),
  (Alog: 'aes-256';     Mode: 'cbc'),

  (Alog: 'aria-128';    Mode: 'ecb'),
  (Alog: 'aria-128';    Mode: 'cbc'),
  (Alog: 'aria-128';    Mode: 'cfb'),
  (Alog: 'aria-128';    Mode: 'cfb1'),
  (Alog: 'aria-128';    Mode: 'cfb8'),
  (Alog: 'aria-128';    Mode: 'ctr'),
  (Alog: 'aria-128';    Mode: 'ofb'),

  (Alog: 'aria-192';    Mode: 'ecb'),
  (Alog: 'aria-192';    Mode: 'cbc'),
  (Alog: 'aria-192';    Mode: 'cfb'),
  (Alog: 'aria-192';    Mode: 'cfb1'),
  (Alog: 'aria-192';    Mode: 'cfb8'),
  (Alog: 'aria-192';    Mode: 'ctr'),
  (Alog: 'aria-192';    Mode: 'ofb'),

  (Alog: 'aria-256';    Mode: 'ecb'),
  (Alog: 'aria-256';    Mode: 'cbc'),
  (Alog: 'aria-256';    Mode: 'cfb'),
  (Alog: 'aria-256';    Mode: 'cfb1'),
  (Alog: 'aria-256';    Mode: 'cfb8'),
  (Alog: 'aria-256';    Mode: 'ctr'),
  (Alog: 'aria-256';    Mode: 'ofb'),

  (Alog: 'bf';          Mode: ''),
  (Alog: 'bf';          Mode: 'ecb'),
  (Alog: 'bf';          Mode: 'cbc'),
  (Alog: 'bf';          Mode: 'cfb'),
  (Alog: 'bf';          Mode: 'ofb')
 );


const libcrypto = 'libcrypto-3.dll';

//Crypto Base functions
function CRYPTO_malloc(num: SIZE_T; const _file: PAnsiChar; line: Integer): Pointer; external libcrypto;
function CRYPTO_zalloc(num: SIZE_T; const _file: PAnsiChar; line: Integer): Pointer; external libcrypto;
function CRYPTO_realloc(str: Pointer; num: SIZE_T; const _file: PAnsiChar; line: Integer): Pointer; external libcrypto;
function CRYPTO_clear_realloc(str: Pointer; old_len: SIZE_T; num: SIZE_T; const _file: PAnsiChar; line: Integer): Pointer; external libcrypto;
procedure CRYPTO_free(str: Pointer; const _file: PAnsiChar; line: Integer); external libcrypto;
procedure CRYPTO_clear_free(str: Pointer; num: SIZE_T; const _file: PAnsiChar; line: Integer); external libcrypto;
function ERR_get_error: ULONG; stdcall; external libcrypto;
//BigNumber functions
function BN_new: PBIGNUM; stdcall; external libcrypto;
procedure BN_free(a: PBIGNUM); stdcall; external libcrypto;
function BN_bn2hex(const a: PBIGNUM): PAnsiChar; stdcall; external libcrypto;
function BN_bn2dec(const a: PBIGNUM): PAnsiChar; stdcall; external libcrypto;
function BN_hex2bn(var bn: PBIGNUM; const a: PAnsiChar): Integer; stdcall; external libcrypto;  //BIGNUM **bn
function BN_dec2bn(var bn: PBIGNUM; const a: PAnsiChar): Integer; stdcall; external libcrypto;  //BIGNUM **bn
function BN_asc2bn(var bn: PBIGNUM; const a: PAnsiChar): Integer; stdcall; external libcrypto;  //BIGNUM **bn
function BN_bin2bn(const s: PByte; len: Integer; ret: PBIGNUM): PBIGNUM; stdcall; external libcrypto;
//EC Point functions
function EC_POINT_point2oct(const group: PEC_GROUP; const point: PEC_POINT; form: Tpoint_conversion_form; buf: PByte; len: SIZE_T; ctx: PBN_CTX): SIZE_T; stdcall; external libcrypto;
function EC_POINT_oct2point(const group: PEC_GROUP; point: PEC_POINT; const buf: PByte; len: SIZE_T; ctx: PBN_CTX): Integer; stdcall; external libcrypto;
function EC_POINT_point2buf(const group: PEC_GROUP; const Pointer: PEC_POINT; form: Tpoint_conversion_form; var pbuf: PByte; ctx: PBN_CTX): SIZE_T; stdcall; external libcrypto;
function EC_POINT_point2bn(const group: PEC_GROUP; const point: PEC_POINT; form: Tpoint_conversion_form; ret: PBIGNUM; ctx: PBN_CTX): PBIGNUM; stdcall; external libcrypto;
function EC_POINT_bn2point(const group: PEC_GROUP; const bn: PBIGNUM; point: PEC_POINT; ctx: PBN_CTX): PEC_POINT; stdcall; external libcrypto;
function EC_POINT_point2hex(const group: PEC_GROUP; const point: PEC_POINT; form: Tpoint_conversion_form; ctx: PBN_CTX): PAnsiChar; stdcall; external libcrypto;
function EC_POINT_hex2point(const group: PEC_GROUP; const buf: PAnsiChar; point: PEC_POINT; ctx: PBN_CTX): PEC_POINT; stdcall; external libcrypto;
//EVP Cipher functions
function EVP_CIPHER_CTX_new: PEVP_CIPHER_CTX; stdcall; external libcrypto;
function EVP_CipherInit_ex(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; impl: PENGINE; key: PAnsiChar; iv: PAnsiChar; enc: Integer): Integer; stdcall; external libcrypto;
function EVP_CipherUpdate(ctx: PEVP_CIPHER_CTX; _out : PAnsiChar; var outl: Integer; _in: PAnsiChar; inl: Integer): Integer; stdcall; external libcrypto;
function EVP_CipherFinal_ex(ctx: PEVP_CIPHER_CTX; outm: PAnsiChar; var outl: Integer): Integer; stdcall; external libcrypto;
procedure EVP_CIPHER_CTX_free(a: PEVP_CIPHER_CTX); stdcall; external libcrypto;
function EVP_get_cipherbyname(const name: PAnsiChar): PEVP_CIPHER; stdcall; external libcrypto;
function EVP_CIPHER_CTX_set_padding(c: PEVP_CIPHER_CTX; pad: Integer): Integer; stdcall; external libcrypto;
//EVP Message Digest functions
function EVP_MD_CTX_new:PEVP_MD_CTX; stdcall; external libcrypto;
procedure EVP_MD_CTX_set_pkey_ctx(ctx: PEVP_MD_CTX; pctx: PEVP_PKEY_CTX); stdcall; external libcrypto;
function EVP_DigestInit_ex(ctx: PEVP_MD_CTX; const AType: PEVP_MD; impl: PENGINE): Integer; stdcall; external libcrypto;
function EVP_DigestUpdate(ctx: PEVP_MD_CTX; d: Pointer; cnt: SIZE_T): Integer; stdcall; external libcrypto;
function EVP_DigestFinal(ctx: PEVP_MD_CTX; md: PByte; size: PUINT): Integer; stdcall; external libcrypto;
function EVP_DigestFinal_ex(ctx: PEVP_MD_CTX; md: PAnsiChar; var s: UINT): Integer; stdcall; external libcrypto;
procedure EVP_MD_CTX_free(ctx: PEVP_MD_CTX); stdcall; external libcrypto;
function EVP_get_digestbyname(const name: PAnsiChar): PEVP_MD; stdcall; external libcrypto;
//EVP PKEY functions
function EVP_PKEY_new: PEVP_PKEY; stdcall; external libcrypto;
function EVP_PKEY_new_raw_public_key(_type: Integer; e: PENGINE; const public: PByte; len: SIZE_T): PEVP_PKEY; stdcall; external libcrypto;
function EVP_PKEY_assign(pkey: PEVP_PKEY; _type: Integer; key: Pointer): Integer; stdcall; external libcrypto;
function EVP_PKEY_CTX_new(pkey: PEVP_PKEY; e: PENGINE): PEVP_PKEY_CTX; stdcall; external libcrypto;
procedure EVP_PKEY_CTX_free(ctx: PEVP_PKEY_CTX); stdcall; external libcrypto;
function EVP_PKEY_CTX_ctrl(ctx: PEVP_PKEY_CTX; keytype: Integer; optype: Integer; cmd: Integer; p1: Integer; p2: Pointer): Integer; stdcall; external libcrypto;
function EVP_PKEY_set_type(pkey: PEVP_PKEY; _type: Integer): Integer; stdcall; external libcrypto;
function EVP_PKEY_set_alias_type(pkey: PEVP_PKEY; _type: Integer): Integer; stdcall; external libcrypto;
function EVP_PKEY_encrypt_init(ctx: PEVP_PKEY_CTX): Integer; stdcall; external libcrypto;
function EVP_PKEY_encrypt(ctx: PEVP_PKEY_CTX; out: PByte; var outlen: SIZE_T; const _in: PByte; inlen: SIZE_T): Integer; stdcall; external libcrypto;
function EVP_PKEY_decrypt_init(ctx: PEVP_PKEY_CTX): Integer; stdcall; external libcrypto;
function EVP_PKEY_decrypt(ctx: PEVP_PKEY_CTX; out: PByte; var outlen: SIZE_T; const _in: PByte; inlen: SIZE_T): Integer; stdcall; external libcrypto;
//EVP m_sigver.c
function EVP_DigestSignInit(ctx: PEVP_MD_CTX; PCTX: PPEVP_PKEY_CTX; const _type: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): Integer; stdcall; external libcrypto;
function EVP_DigestVerifyInit(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; const _type: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): Integer; stdcall; external libcrypto;
function EVP_DigestSignFinal(ctx: PEVP_MD_CTX; sigret: PByte; siglen: PSIZE_T): Integer; stdcall; external libcrypto;
function EVP_DigestSign(ctx: PEVP_MD_CTX; sigret: PByte; siglen: PSIZE_T; const tbs: PByte; tbslen: SIZE_T): Integer; stdcall; external libcrypto;
function EVP_DigestVerifyFinal(ctx: PEVP_MD_CTX; const sig: PByte; siglen: SIZE_T): Integer; stdcall; external libcrypto;
function EVP_DigestVerify(ctx: PEVP_MD_CTX; const sigret: PByte; siglen: SIZE_T; const tbs: PByte; tbslen: SIZE_T): Integer; stdcall; external libcrypto;
function EVP_DigestInit(ctx: PEVP_MD_CTX; const _type: PEVP_MD): Integer; stdcall; external libcrypto;
//function EVP_DigestInit_ex(ctx: PEVP_MD_CTX; const _type: PEVP_MD; impl: PENGINE): Integer; stdcall; external libcrypto;
//function EVP_DigestUpdate(ctx: PEVP_MD_CTX; const data: Pointer; count: SIZE_T): Integer; stdcall; external libcrypto;
//function EVP_DigestFinal(ctx: PEVP_MD_CTX; md: PByte; size: PUINT): Integer; stdcall; external libcrypto;
//function EVP_DigestFinal_ex(ctx: PEVP_MD_CTX; md: PByte; size: PUINT): Integer; stdcall; external libcrypto;
//
function EVP_EncryptUpdate(ctx: PEVP_CIPHER_CTX; _out: PByte; outl: PINT; const _in: PByte; inl: Integer): Integer; stdcall; external libcrypto;
function EVP_DecryptUpdate(ctx: PEVP_CIPHER_CTX; _out: PByte; outl: PINT; const _in: PByte; inl: Integer): Integer; stdcall; external libcrypto;

//EC Group functions
function EC_GROUP_new(const meth: PEC_METHOD): PEC_GROUP; stdcall; external libcrypto;
procedure EC_pre_comp_free(group: PEC_GROUP); stdcall; external libcrypto;
procedure EC_GROUP_free(group: PEC_GROUP); stdcall; external libcrypto;
procedure EC_GROUP_clear_free(group: PEC_GROUP); stdcall; external libcrypto;
function EC_GROUP_copy(dest: PEC_GROUP; const src: PEC_GROUP): Integer; stdcall; external libcrypto;
function EC_GROUP_dup(const a: PEC_GROUP): PEC_GROUP; stdcall; external libcrypto;
function EC_GROUP_method_of(const group: PEC_GROUP): PEC_METHOD; stdcall; external libcrypto;   //const return value
function EC_METHOD_get_field_type(const meth: PEC_METHOD): Integer; stdcall; external libcrypto;
function EC_GROUP_set_generator(group: PEC_GROUP; const generator: PEC_POINT; const order: PBIGNUM; const cofactor: PBIGNUM): Integer; stdcall; external libcrypto;
function EC_GROUP_get0_generator(const group: PEC_GROUP): PEC_POINT; stdcall; external libcrypto;   //const return value
function EC_GROUP_get_mont_data(const group: PEC_GROUP): PBN_MONT_CTX; stdcall; external libcrypto;
function EC_GROUP_get_order(const group: PEC_GROUP; order: PBIGNUM; ctx: PBN_CTX): Integer; stdcall; external libcrypto;
function EC_GROUP_get0_order(const group: PEC_GROUP): PBIGNUM; stdcall; external libcrypto;   //const return value
function EC_GROUP_order_bits(const group: PEC_GROUP): Integer; stdcall; external libcrypto;
function EC_GROUP_get_cofactor(const group: PEC_GROUP; cofactor: PBIGNUM; ctx: PBN_CTX): Integer; stdcall; external libcrypto;
function EC_GROUP_get0_cofactor(const group: PEC_GROUP): PBIGNUM; stdcall; external libcrypto;    //const return value
procedure EC_GROUP_set_curve_name(group: PEC_GROUP; nid: Integer); stdcall; external libcrypto;
function EC_GROUP_get_curve_name(const group: PEC_GROUP): Integer; stdcall; external libcrypto;
procedure EC_GROUP_set_asn1_flag(group: PEC_GROUP; flag: Integer); stdcall; external libcrypto;
function EC_GROUP_get_asn1_flag(const group: PEC_GROUP): Integer; stdcall; external libcrypto;
procedure EC_GROUP_set_point_conversion_form(group: PEC_GROUP; form: Tpoint_conversion_form); stdcall; external libcrypto;
function EC_GROUP_get_point_conversion_form(const group: PEC_GROUP): Tpoint_conversion_form; stdcall; external libcrypto;
function EC_GROUP_new_by_curve_name(nid: Integer): PEC_GROUP; stdcall; external libcrypto;
function EC_GROUP_set_seed(group: PEC_GROUP; const p: PByte; len: SIZE_T): SIZE_T; stdcall; external libcrypto;
function EC_GROUP_get0_seed(const group: PEC_GROUP): PByte; stdcall; external libcrypto;
function EC_GROUP_get_seed_len(const group: PEC_GROUP): SIZE_T; stdcall; external libcrypto;
function EC_GROUP_set_curve(group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): Integer; stdcall; external libcrypto;
function EC_GROUP_get_curve(const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): Integer; stdcall; external libcrypto;
function EC_GROUP_get_degree(const group: PEC_GROUP): Integer; stdcall; external libcrypto;
function EC_GROUP_check_discriminant(const group: PEC_GROUP; ctx: PBN_CTX): Integer; stdcall; external libcrypto;
function EC_GROUP_cmp(const a: PEC_GROUP; const b: PEC_GROUP; ctx: PBN_CTX): Integer; stdcall; external libcrypto;
function EC_GROUP_new_curve_GFp(const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; stdcall; external libcrypto;
function EC_GROUP_set_curve_GFp(group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): Integer; external libcrypto;
function EC_GROUP_get_curve_GFp(const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): Integer; external libcrypto;
//EC Point functions
function EC_POINT_new(const group: PEC_GROUP): PEC_POINT; stdcall; external libcrypto;
procedure EC_POINT_free(point: PEC_POINT); stdcall; external libcrypto;
procedure EC_POINT_clear_free(point: PEC_POINT); stdcall; external libcrypto;
function EC_POINT_copy(dst: PEC_POINT; const src: PEC_POINT): Integer; stdcall; external libcrypto;
function EC_POINT_dup(const src: PEC_POINT; const group: PEC_GROUP): PEC_POINT; stdcall; external libcrypto;
function EC_POINT_add(const group: PEC_GROUP; r: PEC_POINT; const a: PEC_POINT; const b: PEC_POINT; ctx: PBN_CTX): Integer; stdcall; external libcrypto;
function EC_POINT_dbl(const group: PEC_GROUP; r: PEC_POINT; const a: PEC_POINT; ctx: PBN_CTX): Integer; stdcall; external libcrypto;
function EC_POINT_invert(const group: PEC_GROUP; a: PEC_POINT; ctx: PBN_CTX): Integer; stdcall; external libcrypto;
function EC_POINT_is_at_infinity(const group: PEC_GROUP; const p: PEC_POINT): Integer; stdcall; external libcrypto;
function EC_POINT_is_on_curve(const group: PEC_GROUP; const point: PEC_POINT; ctx: PBN_CTX): Integer; stdcall; external libcrypto;
function EC_POINT_cmp(const group: PEC_GROUP; const a: PEC_POINT; const b: PEC_POINT; ctx: PBN_CTX): Integer; stdcall; external libcrypto;
function EC_POINT_mul(const group: PEC_GROUP; r: PEC_POINT; const g_scalar: PBIGNUM; const point: PEC_POINT; const p_scaler: PBIGNUM; ctx: PBN_CTX): Integer; stdcall; external libcrypto;
function EC_POINT_get_Jprojective_corrdinates_GFp(const group: PEC_GROUP; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): Integer; stdcall; external libcrypto;
function EC_POINT_set_affine_coordinates_GFp(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): Integer; stdcall; external libcrypto;
function EC_POINT_get_affine_coordinates_GFp(const group: PEC_GROUP; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): Integer; stdcall; external libcrypto;
function EC_POINT_set_compressed_coordinates_GFp(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; y_bit: Integer; ctx: PBN_CTX): Integer; stdcall; external libcrypto;
//EC Key functions
function EC_KEY_new: PEC_KEY; stdcall; external libcrypto;
function EC_KEY_new_by_curve_name(nid: Integer): PEC_KEY; stdcall; external libcrypto;
procedure EC_KEY_free(r: PEC_KEY); stdcall; external libcrypto;
function EC_KEY_copy(dest: PEC_KEY; const src: PEC_KEY): PEC_KEY; stdcall; external libcrypto;
function EC_KEY_dup(const ec_key: PEC_KEY): PEC_KEY; stdcall; external libcrypto;
function EC_KEY_up_ref(r: PEC_KEY): Integer; stdcall; external libcrypto;
function EC_KEY_get0_engine(const eckey: PEC_KEY): PENGINE; stdcall; external libcrypto;
function EC_KEY_generate_key(eckey: PEC_KEY): Integer; stdcall; external libcrypto;
function ec_key_simple_generate_key(eckey: PEC_KEY): Integer; stdcall; external libcrypto;
function ec_key_simple_generate_public_key(eckey:PEC_KEY): Integer; stdcall; external libcrypto;
function EC_KEY_check_key(const eckey: PEC_KEY): Integer; stdcall; external libcrypto;
function ec_key_simple_check_key(const eckey: PEC_KEY): Integer; stdcall; external libcrypto;
function EC_KEY_set_public_key_affine_coordinates(key: PEC_KEY; x: PBIGNUM; y: PBIGNUM): Integer; stdcall; external libcrypto;
function EC_KEY_get0_group(const key: PEC_KEY): PEC_GROUP; stdcall; external libcrypto;   //return const
function EC_KEY_set_group(key: PEC_KEY; const group: PEC_GROUP): Integer; stdcall; external libcrypto;
function EC_KEY_get0_private_key(const key: PEC_KEY): PBIGNUM; stdcall; external libcrypto;
function EC_KEY_set_private_key(key: PEC_KEY; const priv_key: PBIGNUM): Integer; stdcall; external libcrypto;
function EC_KEY_get0_public_key(const key: PEC_KEY): PEC_POINT; stdcall; external libcrypto;
function EC_KEY_set_public_key(key: PEC_KEY; const pub_key: PEC_POINT): Integer; stdcall; external libcrypto;
function EC_KEY_get_enc_flags(const key: PEC_KEY): UINT; stdcall; external libcrypto;
procedure EC_KEY_set_enc_flags(key: PEC_KEY; flags: UINT); stdcall; external libcrypto;
function EC_KEY_get_conv_form(const key: PEC_KEY): Tpoint_conversion_form; stdcall; external libcrypto;
procedure EC_KEY_set_conv_form(key: PEC_KEY; cform: Tpoint_conversion_form); stdcall; external libcrypto;
procedure EC_KEY_set_asn1_flag(key: PEC_KEY; flag: Integer); stdcall; external libcrypto;
function EC_KEY_precompute_mult(key: PEC_KEY; ctx: PBN_CTX): Integer; stdcall; external libcrypto;
function EC_KEY_get_flags(const key: PEC_KEY): Integer; stdcall; external libcrypto;
procedure EC_KEY_set_flags(key: PEC_KEY; flags: Integer); stdcall; external libcrypto;
procedure EC_KEY_clear_flags(key: PEC_KEY; flags: Integer); stdcall; external libcrypto;
//ECDSA functions
function ECDSA_SIG_new: PECDSA_SIG; stdcall; external libcrypto;
procedure ECDSA_SIG_free(sig: PECDSA_SIG); stdcall; external libcrypto;
procedure ECDSA_SIG_get0(const sig: PECDSA_SIG; const pr: PPBIGNUM; const ps: PPBIGNUM); stdcall; external libcrypto;
function ECDSA_SIG_get0_r(const sig: PECDSA_SIG): PBIGNUM; stdcall; external libcrypto;   //const return value
function ECDSA_SIG_get0_s(const sig: PECDSA_SIG): PBIGNUM; stdcall; external libcrypto;   //const return value
function ECDSA_SIG_set0(sig: PECDSA_SIG; r: PBIGNUM; s: PBIGNUM): Integer; stdcall; external libcrypto;
//der functions
function i2d_ECDSA_SIG(const sig: PECDSA_SIG; pp: PPByte): Integer; stdcall; external libcrypto;
function d2i_ECDSA_SIG(sig: PPECDSA_SIG; const pp: PPByte; len: LONG): PECDSA_SIG; stdcall; external libcrypto;

//macro functions
function OPENSSL_malloc(num: SIZE_T):Pointer;
function OPENSSL_zalloc(num: SIZE_T):Pointer;
function OPENSSL_realloc(addr: Pointer; num: SIZE_T): Pointer;
function OPENSSL_clear_realloc(addr: Pointer; old_num: SIZE_T; num: SIZE_T): Pointer;
procedure OPENSSL_clear_free(addr: Pointer; num: SIZE_T);
procedure OPENSSL_free(obj: Pointer);
function EVP_PKEY_CTX_set1_id(ctx: PEVP_PKEY_CTX; id: Pointer; id_len: Integer): Integer;
function EVP_PKEY_CTX_get1_id(ctx: PEVP_PKEY_CTX; id: Pointer): Integer;
function EVP_PKEY_CTX_get1_id_len(ctx: PEVP_PKEY_CTX; id_len: Integer): Integer;
function EVP_SignInit_ex(ctx: PEVP_MD_CTX; const _type: PEVP_MD; impl: PENGINE): Integer;
function EVP_SignInit(ctx: PEVP_MD_CTX; const _type: PEVP_MD): Integer;
function EVP_SignUpdate(ctx: PEVP_MD_CTX; const data: Pointer; count: SIZE_T): Integer;
function EVP_VerifyInit_ex(ctx: PEVP_MD_CTX; const _type : PEVP_MD; impl: PENGINE): Integer;
function EVP_VerifyInit(ctx: PEVP_MD_CTX; const _type: PEVP_MD): Integer;
function EVP_VerifyUpdate(ctx: PEVP_MD_CTX; const data: Pointer; count: SIZE_T): Integer;
function EVP_OpenUpdate(ctx: PEVP_CIPHER_CTX; _out: PByte; outl: PINT; const _in: PByte; inl: Integer): Integer;
function EVP_SealUpdate(ctx: PEVP_CIPHER_CTX; _out: PByte; outl: PINT; const _in: PByte; inl: Integer): Integer;
function EVP_DigestSignUpdate(ctx: PEVP_MD_CTX; const data: Pointer; count: SIZE_T): Integer;
function EVP_DigestVerifyUpdate(ctx: PEVP_MD_CTX; const data: Pointer; count: SIZE_T): Integer;

////////////////////////////////////////
procedure FreePByte(pb: PByte);
function GetPByteFromHexStr(in_str: TStrings; var out_len: Integer): PByte; overload;
function GetPByteFromHexStr(in_str: string; var out_len: Integer): PByte; overload;
function GetPByteFromASCIIStrs(in_str: TStrings; var out_len: Integer): PByte; overload;
function GetPByteFromASCIIStrs(in_str: string; var out_len: Integer): PByte; overload;
function PByteToString(in_pbyte: PByte; in_len: Integer; split_str: string): string;
function PAnsiCharToString(in_pansichar: PAnsiChar; in_len: Integer; split_str: string): string;

function simple_d2i_SM2_Ciphertext(_in: PByte; inlen: Integer; _out: PByte; var outlen: Integer; C1C2C3: Boolean): Integer;
function simple_i2d_SM2_Ciphertext(_in: PByte; inlen: Integer; _out: PByte; var outlen: Integer; C1C2C3: Boolean): Integer;


////////////////////////////////////////

procedure do_md(alog_name: string;
    input: PByte; output: PByte;
   input_len: Integer; var output_len: Integer);
procedure do_cipher(alog_name: string; do_enc: Integer; padding: Integer;
    input: PByte; output: PByte; key: PByte; iv: PByte;
    input_len: Integer; var output_len: Integer; key_len: Integer; iv_len: Integer);
function do_sm2sign(group: PEC_GROUP; evp_md: PEVP_MD;
    userid: PByte; prikey: PByte; msg: PByte; k: PByte; var sig: string;
    userid_len: Integer; msg_len: Integer; var sig_len: Integer): Boolean;
function do_sm2verify(group: PEC_GROUP; evp_md: PEVP_MD;
    userid: PByte; pubkey: string; msg: PByte; k: PByte; sig: string;
    userid_len: Integer; msg_len: Integer; sig_len: Integer): Boolean;
function check_cipher(alog_name: string): Boolean;
function get_cipher_key_size(alog_name: string): Integer;
function get_cipher_iv_size(alog_name: string): Integer;
function get_cipher_block_size(alog_name: string): Integer;
function get_cipher_all_size(alog_name: string; var key_size: Integer; var iv_size: Integer; var block_size: Integer): Boolean;

function set_public_key_by_hex(key: PEC_KEY; key_hex_str: string): Boolean;
function set_private_key_by_hex(key: PEC_KEY; key_hex_str: string): Boolean;
function set_key_pare_by_hex(key: PEC_KEY; pri_key_hex_str: string; pub_key_hex_str: string = ''): Boolean;

function create_EC_group(p_hex: string; a_hex: string; b_hex: string;
    x_hex: string; y_hex: string; order_hex: string; cof_hex: string): PEC_GROUP;

implementation




function OPENSSL_malloc(num: SIZE_T):Pointer;
begin
  Result := CRYPTO_malloc(num, 'InPascal', 1);
end;

function OPENSSL_zalloc(num: SIZE_T):Pointer;
begin
  Result := CRYPTO_zalloc(num, 'InPascal', 1);
end;

function OPENSSL_realloc(addr: Pointer; num: SIZE_T): Pointer;
begin
  Result := CRYPTO_realloc(addr, num, 'InPascal', 1);
end;

function OPENSSL_clear_realloc(addr: Pointer; old_num: SIZE_T; num: SIZE_T): Pointer;
begin
  Result := CRYPTO_clear_realloc(addr, old_num, num, 'InPascal', 1);
end;

procedure OPENSSL_clear_free(addr: Pointer; num: SIZE_T);
begin
  CRYPTO_clear_free(addr, num, 'InPascal', 1);
end;

procedure OPENSSL_free(obj: Pointer);
begin
  CRYPTO_free(obj, 'InPascal', 1);
end;

function EVP_PKEY_CTX_set1_id(ctx: PEVP_PKEY_CTX; id: Pointer; id_len: Integer): Integer;
begin
  Result := EVP_PKEY_CTX_ctrl(ctx, -1, -1, EVP_PKEY_CTRL_SET1_ID, id_len, Pointer(id));
end;

function EVP_PKEY_CTX_get1_id(ctx: PEVP_PKEY_CTX; id: Pointer): Integer;
begin
  Result := EVP_PKEY_CTX_ctrl(ctx, -1, -1, EVP_PKEY_CTRL_GET1_ID, 0, Pointer(id));
end;

function EVP_PKEY_CTX_get1_id_len(ctx: PEVP_PKEY_CTX; id_len: Integer): Integer;
begin
  Result := EVP_PKEY_CTX_ctrl(ctx, -1, -1, EVP_PKEY_CTRL_GET1_ID_LEN, 0, Pointer(id_len));
end;

function EVP_SignInit_ex(ctx: PEVP_MD_CTX; const _type: PEVP_MD; impl: PENGINE): Integer;
begin
  Result := EVP_DigestInit_ex(ctx, _type, impl);
end;

function EVP_SignInit(ctx: PEVP_MD_CTX; const _type: PEVP_MD): Integer;
begin
  Result := EVP_DigestInit(ctx, _type);
end;

function EVP_SignUpdate(ctx: PEVP_MD_CTX; const data: Pointer; count: SIZE_T): Integer;
begin
  Result := EVP_DigestUpdate(ctx, data, count);
end;

function EVP_VerifyInit_ex(ctx: PEVP_MD_CTX; const _type : PEVP_MD; impl: PENGINE): Integer;
begin
  Result := EVP_DigestInit_ex(ctx, _type, impl);
end;

function EVP_VerifyInit(ctx: PEVP_MD_CTX; const _type: PEVP_MD): Integer;
begin
  Result := EVP_DigestInit(ctx, _type);
end;

function EVP_VerifyUpdate(ctx: PEVP_MD_CTX; const data: Pointer; count: SIZE_T): Integer;
begin
  Result := EVP_DigestUpdate(ctx, data, count);
end;

function EVP_OpenUpdate(ctx: PEVP_CIPHER_CTX; _out: PByte; outl: PINT; const _in: PByte; inl: Integer): Integer;
begin
  Result := EVP_DecryptUpdate(ctx, _out, outl, _in, inl);
end;

function EVP_SealUpdate(ctx: PEVP_CIPHER_CTX; _out: PByte; outl: PINT; const _in: PByte; inl: Integer): Integer;
begin
  Result := EVP_EncryptUpdate(ctx, _out, outl, _in, inl);
end;

function EVP_DigestSignUpdate(ctx: PEVP_MD_CTX; const data: Pointer; count: SIZE_T): Integer;
begin
  Result := EVP_DigestUpdate(ctx, data, count);
end;

function EVP_DigestVerifyUpdate(ctx: PEVP_MD_CTX; const data: Pointer; count: SIZE_T): Integer;
begin
  Result := EVP_DigestUpdate(ctx, data, count);
end;

/////////////////////////////////////////////////////////////////////////////////////////////


procedure FreePByte(pb: PByte);
begin
  FreeMemory(pb);
end;

function GetPByteFromHexStr(in_str: TStrings; var out_len: Integer): PByte; overload;
var
  i,j,l: Integer;
  tb: Boolean;
  th: Byte;
  ptr: PByte;
begin
  out_len := 0;
  l := 0;
  Result := nil;
  for j := 0 to in_str.Count-1 do
    Inc(l, in_str[j].Length);
  if l = 0 then
    Exit;
  Result := GetMemory(l div 2 + 1);
  ptr := Result;
  tb := True;
  for j := 0 to in_str.Count-1 do
  begin
    for i := 1 to in_str[j].Length do
    begin
      case in_str[j][i] of
        '0'..'9': th := Ord(in_str[j][i]) - Ord('0');
        'A'..'F': th := Ord(in_str[j][i]) - Ord('A') + 10;
        'a'..'f': th := Ord(in_str[j][i]) - Ord('a') + 10;
      else
        Dec(l);
        continue;
      end;
      if tb then
        ptr^ := th shl 4
      else
      begin
        ptr^ := ptr^ + th;
        Inc(ptr);
      end;
      tb := not tb;
    end;
  end;
  out_len := l div 2;
end;

function GetPByteFromHexStr(in_str: string; var out_len: Integer): PByte; overload;
var
  i,l: Integer;
  tb: Boolean;
  th: Byte;
  ptr: PByte;
begin
  out_len := 0;
  Result := nil;
  l := in_str.Length;
  if l = 0 then
    Exit;
  Result := GetMemory(l div 2 + 1);
  ptr := Result;
  tb := True;
  for i := 1 to in_str.Length do
  begin
    case in_str[i] of
      '0'..'9': th := Ord(in_str[i]) - Ord('0');
      'A'..'F': th := Ord(in_str[i]) - Ord('A') + 10;
      'a'..'f': th := Ord(in_str[i]) - Ord('a') + 10;
    else
      Dec(l);
      continue;
    end;
    if tb then
      ptr^ := th shl 4
    else
    begin
      ptr^ := ptr^ + th;
      Inc(ptr);
    end;
    tb := not tb;
  end;
  out_len := l div 2;
end;

function GetPByteFromASCIIStrs(in_str: TStrings; var out_len: Integer): PByte; overload;
var
  i,j,l: Integer;
  ptr: PByte;
begin
  out_len := 0;
  l := 0;
  Result := nil;
  for j := 0 to in_str.Count do
    Inc(l, in_str[j].Length);
  if l = 0 then
    Exit;
  Result := GetMemory(l);
  ptr := Result;
  for j := 0 to in_str.Count-1 do
  begin
    for i := 1 to in_str[j].Length do
    begin
      ptr^ := Byte(in_str[j][i]);
      Inc(ptr);
    end;
  end;
  out_len := l;
end;

function GetPByteFromASCIIStrs(in_str: string; var out_len: Integer): PByte; overload;
var
  i,l: Integer;
  ptr: PByte;
begin
  out_len := 0;
  l := Length(in_str);
  Result := nil;
  if l = 0 then
    Exit;
  Result := GetMemory(l);
  ptr := Result;
  for i := 1 to l do
  begin
    ptr^ := Byte(in_str[i]);
    Inc(ptr);
  end;
  out_len := l;
end;

function PByteToString(in_pbyte: PByte; in_len: Integer; split_str: string): string;
begin
  Result := '';
  if in_len = 0 then
    Exit;
  while in_len > 1 do
  begin
    Result := Result + split_str + IntToHex(in_pbyte^, 2);
    Inc(in_pbyte);
    Dec(in_len);
  end;
  Result := Result + IntToHex(in_pbyte^, 2);
end;

function PAnsiCharToString(in_pansichar: PAnsiChar; in_len: Integer; split_str: string): string;
begin
  Result := '';
  if in_len = 0 then
    Exit;
  while in_len > 1 do
  begin
    Result := Result + split_str + IntToHex(Ord(in_pansichar^), 2);
    Inc(in_pansichar);
    Dec(in_len);
  end;
  Result := Result + IntToHex(Ord(in_pansichar^), 2);
end;

function simple_der_get_len(ptr: PByte; pptr: PPByte): Integer;
var
  i: Integer;
begin
  Result := -1;
  if ptr^ < $80 then
    Result := ptr^                                                              // single len byte
  else if ptr^ = $80 then
  begin
    Exit;
    i := 2;
    while i <> 0 do
    begin
                                                                                // auto len, stop with "0000", not support now
    end;
  end
  else
  begin
    i := ptr^ and $7F;                                                          // get len byte count
    Result := 0;
    while i <> 0 do
    begin
      Inc(ptr);
      Result := Result * 256 + ptr^;
      Dec(i);
    end;
  end;
  if pptr <> nil then
  begin
    pptr^ := ptr + 1;                                                           // pptr return position of data
  end;
end;

function simple_der_gen_len(len: Integer; ptr: PByte): Integer;
begin
  Result := -1;
  if len <= 127 then
  begin
    if ptr <> nil then
    begin
      ptr^ := Byte(len and $7F);
    end;
    Result := 1;
  end
  else
  begin
    if len < 256 then
    begin
      if ptr <> nil then
      begin
        ptr^ := $81;
        (ptr+1)^ := len shr 0 and $FF;
      end;
      Result := 2;
    end
    else if len < 65536 then
    begin
      if ptr <> nil then
      begin
        ptr^ := $82;
        (ptr+1)^ := len shr 8 and $FF;
        (ptr+2)^ := len shr 0 and $FF;
      end;
      Result := 3;
    end
    else if len < 16777216 then
    begin
      if ptr <> nil then
      begin
        ptr^ := $83;
        (ptr+1)^ := len shr 16 and $FF;
        (ptr+2)^ := len shr 8 and $FF;
        (ptr+3)^ := len shr 0 and $FF;
      end;
      Result := 4;
    end
    else if len < 4294967296 then
    begin
      if ptr <> nil then
      begin
        ptr^ := $84;
        (ptr+1)^ := len shr 24 and $FF;
        (ptr+2)^ := len shr 16 and $FF;
        (ptr+3)^ := len shr 8 and $FF;
        (ptr+4)^ := len shr 0 and $FF;
      end;
      Result := 5;
    end;
  end;
end;

function simple_d2i_SM2_Ciphertext(_in: PByte; inlen: Integer; _out: PByte; var outlen: Integer; C1C2C3: Boolean): Integer;
var
  total_len, C1xlen, C1ylen, C2len, C3len: Integer;
  C1x, C1y, C2, C3: PByte;
  i : Integer;
begin
  Result := 0;
  if _in = nil then
    Exit;
  if _in^ <> $30 then
    Exit;
  total_len := simple_der_get_len(_in + 1, @_in);
  C1xlen := simple_der_get_len(_in + 1, @C1x);
  _in := C1x;
  Inc(_in, C1xlen);
  C1ylen := simple_der_get_len(_in + 1, @C1y);
  _in := C1y;
  Inc(_in, C1ylen);
  C3len := simple_der_get_len(_in + 1, @C3);
  _in := C3;
  Inc(_in, C3len);
  C2len := simple_der_get_len(_in + 1, @C2);
  if C1x^ = $00 then
  begin
    Inc(C1x);
    Dec(C1xlen);
  end;
  if C1y^ = $00 then
  begin
    Inc(C1y);
    Dec(C1ylen);
  end;
  if C3^ = $00 then
  begin
    Inc(C3);
    Dec(C3len);
  end;
  if C2^ = $00 then
  begin
    Inc(C2);
    Dec(C2Len);
  end;
  if C1xlen <> 32 then
    Exit;
  if C1ylen <> 32 then
    Exit;
  if C3len <> 32 then
    Exit;
  outlen := C1xlen + C1ylen + C3len + C2len + 1;
  _out^ := $04;                                                                 // output with head "04"
  Inc(_out);
  CopyMemory(_out, C1x, C1xlen);
  CopyMemory(_out + C1xlen, C1y, C1ylen);
  if C1C2C3 then
  begin
    CopyMemory(_out + C1xlen + C1ylen, C2, C2len);
    CopyMemory(_out + C1xlen + C1ylen + C2len, C3, C3len);
  end
  else
  begin
    CopyMemory(_out + C1xlen + C1ylen, C3, C3len);
    CopyMemory(_out + C1xlen + C1ylen + C3len, C2, C2len);
  end;
  Result := outlen;
end;

function simple_i2d_SM2_Ciphertext(_in: PByte; inlen: Integer; _out: PByte; var outlen: Integer; C1C2C3: Boolean): Integer;
var
  total_len, C1xlen, C1ylen, C2len, C3len: Integer;
  c : Integer;
begin
  Result := -1;
  if _in = nil then
    Exit;
  if inlen <= 97 then
    Exit;
  C1xlen := 32;
  C1ylen := 32;
  C3len := 32;
  C2len := inlen - 97;
  if _in^ <> $04 then
    Exit;
  Inc(_in);                                                                     // skip head 04
  if _in^ >= $80 then
    Inc(C1xlen);
  if (_in+32)^ >= $80 then
    Inc(C1ylen);
  total_len := C1xlen + C1ylen + C2len + C3len + 4 +
      simple_der_gen_len(C1xlen, nil) +
      simple_der_gen_len(C1ylen, nil) +
      simple_der_gen_len(C2len, nil) +
      simple_der_gen_len(C3len, nil);
  // make up
  _out^ := $30;
  Inc(_out);
  c := simple_der_gen_len(total_len, _out);
  outlen := c + total_len + 1;
  Result := outlen;
  Inc(_out, c);
  _out^ := $02;
  Inc(_out);
  c := simple_der_gen_len(C1xlen, _out);
  Inc(_out, c);
  if C1xlen > 32 then
  begin
    _out^ := $00;
    Inc(_out);
  end;
  CopyMemory(_out, _in, 32);
  Inc(_out, 32);
  _out^ := $02;
  Inc(_out);
  c := simple_der_gen_len(C1ylen, _out);
  Inc(_out, c);
  if C1ylen > 32 then
  begin
    _out^ := $00;
    Inc(_out);
  end;
  CopyMemory(_out, _in + 32, 32);
  Inc(_out, 32);
  if C1C2C3 then
  begin
    _out^ := $04;
    Inc(_out);
    c := simple_der_gen_len(C3len, _out);
    Inc(_out, c);
    CopyMemory(_out, _in+inlen-97+64, C3len);
    Inc(_out, C3len);
    _out^ := $04;
    Inc(_out);
    c := simple_der_gen_len(C2len, _out);
    Inc(_out, c);
    CopyMemory(_out, _in+64, C2len);
  end
  else
  begin
    _out^ := $04;
    Inc(_out);
    c := simple_der_gen_len(C3len, _out);
    Inc(_out, c);
    CopyMemory(_out, _in+64, C3len);
    Inc(_out, C3len);
    _out^ := $04;
    Inc(_out);
    c := simple_der_gen_len(C2len, _out);
    Inc(_out, c);
    CopyMemory(_out, _in+96, C2len);
  end;
end;



/////////////////////////////////////////////////////////////////////////////////////////////
procedure do_md(alog_name: string; input: PByte; output: PByte; input_len: Integer; var output_len: Integer);
var
  md_ctx : PEVP_MD_CTX;
  evp_md : PEVP_MD;
  r_len : UINT;
begin
  md_ctx := EVP_MD_CTX_new;
  evp_md := EVP_get_digestbyname(PAnsiChar(AnsiString(alog_name)));
  EVP_DigestInit_ex(md_ctx, evp_md, nil);
  EVP_DigestUpdate(md_ctx, input, input_len);
  EVP_DigestFinal_ex(md_ctx, PAnsiChar(output), r_len);
  evp_md_ctx_free(md_ctx);
  output_len := r_len;
end;

procedure do_cipher(alog_name: string; do_enc: Integer; padding: Integer;
    input: PByte; output: PByte; key: PByte; iv: PByte;
    input_len: Integer; var output_len: Integer; key_len: Integer; iv_len: Integer);
var
  cipher_ctx : PEVP_CIPHER_CTX;
  evp_cipher : PEVP_CIPHER;
  ret : Integer;
begin
  cipher_ctx := EVP_CIPHER_CTX_new;
  evp_cipher := EVP_get_cipherbyname(PAnsiChar(AnsiString(alog_name)));
  ret := EVP_CipherInit_ex(cipher_ctx, evp_cipher, nil, PAnsiChar(key), PAnsiChar(iv), do_enc);
  ret := EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);
  //ret := EVP_CipherInit_ex(cipher_ctx, evp_cipher, nil, nil, nil, do_enc);
  //ret := EVP_CipherInit_ex(cipher_ctx, nil, nil, PAnsiChar(key), PAnsiChar(iv), -1);                     //set key and iv
  ret := EVP_CipherUpdate(cipher_ctx, PAnsiChar(output), output_len, PAnsiChar(input), input_len);
  //ret := EVP_CipherFinal_ex(cipher_ctx, PAnsiChar(output), out2);
  if padding <> 0 then
  begin
    ret := EVP_CipherFinal_ex(cipher_ctx, PAnsiChar(output), output_len);
  end;
  EVP_CIPHER_CTX_free(cipher_ctx);
end;

function do_sm2verify(group: PEC_GROUP; evp_md: PEVP_MD;
    userid: PByte; pubkey: string; msg: PByte; k: PByte; sig: string;
    userid_len: Integer; msg_len: Integer; sig_len: Integer): Boolean;
var
  ret: Integer;
  pkey: PEVP_PKEY;
  mctx: PEVP_MD_CTX;
  pctx: PEVP_PKEY_CTX;
  key: PEC_KEY;
  sig_der: array[0..127] of Byte;
  sig_der_p: PByte;
  ecdsa_sig: PECDSA_SIG;
  sig_r, sig_s : PBIGNUM;
  s_r, s_s : PAnsiChar;
  pub_key: PEC_POINT;
begin
  Result := False;
  if Length(sig) <> 128 then
    Exit;
  pub_key := EC_POINT_new(group);
  key := EC_KEY_new;
  pkey := EVP_PKEY_new;
  mctx := EVP_MD_CTX_new;
  // key config
  EC_POINT_hex2point(group, PAnsiChar(AnsiString(pubkey)), pub_key, nil);
  if pub_key = nil then
    Exit;
  ret := EC_KEY_set_group(key, group);
  ret := EC_KEY_set_public_key(key, pub_key);
  s_r := PAnsiChar(AnsiString(Copy(sig, 1, 64)));
  s_s := PAnsiChar(AnsiString(Copy(sig, 65, 64)));
  sig_r := nil;
  sig_s := nil;
  ret := BN_hex2bn(sig_r, s_r);
  ret := BN_hex2bn(sig_s, s_s);
  // encode
  ecdsa_sig := ECDSA_SIG_new;
  ret := ECDSA_SIG_set0(ecdsa_sig, sig_r, sig_s);
  sig_der_p := @sig_der;
  sig_len := i2d_ECDSA_SIG(ecdsa_sig, @sig_der_p);
  ret := EVP_PKEY_assign(pkey, EVP_PKEY_SM2, key);
  ret := EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
  pctx := EVP_PKEY_CTX_new(pkey, nil);
  ret := EVP_PKEY_CTX_set1_id(pctx, userid, userid_len);
  EVP_MD_CTX_set_pkey_ctx(mctx, pctx);
  ret := EVP_DigestVerifyInit(mctx, nil, evp_md, nil, pkey);
  ret := EVP_DigestVerifyUpdate(mctx, msg, msg_len);
  ret := EVP_DigestVerifyFinal(mctx, @sig_der, sig_len);
  if ret = 1 then
    Result := True;
end;

function do_sm2sign(group: PEC_GROUP; evp_md: PEVP_MD;
    userid: PByte; prikey: PByte; msg: PByte; k: PByte; var sig: string;
    userid_len: Integer; msg_len: Integer; var sig_len: Integer): Boolean;
var
  ret: Integer;
  pkey: PEVP_PKEY;
  mctx: PEVP_MD_CTX;
  pctx: PEVP_PKEY_CTX;
  key: PEC_KEY;
  sig_der: array[0..127] of Byte;
  sig_der_p: PByte;
  ecdsa_sig: PECDSA_SIG;
  sig_r, sig_s, pri_key : PBIGNUM;
  s_r, s_s : PAnsiChar;
  pub_key: PEC_POINT;
begin
  Result := False;
  pri_key := BN_new;
  pub_key := EC_POINT_new(group);
  key := EC_KEY_new;
  pkey := EVP_PKEY_new;
  mctx := EVP_MD_CTX_new;
  BN_bin2bn(prikey, 32, pri_key);
  EC_POINT_mul(group, pub_key, pri_key, nil, nil, nil);
  ret := EC_KEY_set_group(key, group);
  ret := EC_KEY_set_private_key(key, pri_key);
  ret := EC_KEY_set_public_key(key, pub_key);
  ret := EVP_PKEY_assign(pkey, EVP_PKEY_SM2, key);
  ret := EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
  pctx := EVP_PKEY_CTX_new(pkey, nil);
  EVP_PKEY_CTX_set1_id(pctx, userid, userid_len);
  EVP_MD_CTX_set_pkey_ctx(mctx, pctx);
  ret := EVP_DigestSignInit(mctx, nil, evp_md, nil, pkey);
  ret := EVP_DigestSignUpdate(mctx, msg, msg_len);
  sig_len := 128;
  sig_der_p := @sig_der;
  ret := EVP_DigestSignFinal(mctx, @sig_der, @sig_len);
  //decode
  ecdsa_sig := d2i_ECDSA_SIG(nil, @sig_der_p, sig_len);
  ECDSA_SIG_get0(ecdsa_sig, @sig_r, @sig_s);
  s_r := BN_bn2hex(sig_r);
  s_s := BN_bn2hex(sig_s);
  sig := s_r;
  sig := sig + s_s;
  Result := True;
end;

function check_cipher(alog_name: string): Boolean;
var
  evp_cipher : PEVP_CIPHER;
begin
  try
    evp_cipher := EVP_get_cipherbyname(PAnsiChar(AnsiString(alog_name)));
  except
    Result := False;
    Exit;
  end;
  Result := True;
end;

function get_cipher_key_size(alog_name: string): Integer;
var
  evp_cipher : PEVP_CIPHER;
begin
  evp_cipher := EVP_get_cipherbyname(PAnsiChar(AnsiString(alog_name)));
  Result := evp_cipher.key_len;
end;

function get_cipher_iv_size(alog_name: string): Integer;
var
  evp_cipher : PEVP_CIPHER;
begin
  evp_cipher := EVP_get_cipherbyname(PAnsiChar(AnsiString(alog_name)));
  Result := evp_cipher.iv_len;
end;

function get_cipher_block_size(alog_name: string): Integer;
var
  evp_cipher : PEVP_CIPHER;
begin
  evp_cipher := EVP_get_cipherbyname(PAnsiChar(AnsiString(alog_name)));
  Result := evp_cipher.block_size;
end;

function get_cipher_all_size(alog_name: string; var key_size: Integer; var iv_size: Integer; var block_size: Integer): Boolean;
var
  evp_cipher : PEVP_CIPHER;
begin
  try
    evp_cipher := EVP_get_cipherbyname(PAnsiChar(AnsiString(alog_name)));
  except
    Result := False;
    Exit;
  end;
  key_size := evp_cipher.key_len;
  iv_size := evp_cipher.iv_len;
  block_size := evp_cipher.block_size;
  Result := True;
end;

function set_public_key_by_hex(key: PEC_KEY; key_hex_str: string): Boolean;
var
  ret : Integer;
  pub_key: PEC_POINT;
  sm2_curve : PEC_GROUP;
begin
  Result := False;
  sm2_curve := EC_GROUP_new_by_curve_name(NID_sm2);
  pub_key := EC_POINT_new(sm2_curve);
  EC_POINT_hex2point(sm2_curve, PAnsiChar(AnsiString(key_hex_str)), pub_key, nil);
  if pub_key = nil then
    Exit;
  ret := EC_KEY_set_group(key, sm2_curve);
  ret := EC_KEY_set_public_key(key, pub_key);
  if ret <= 0 then
    Exit;
  Result := True;
end;

function set_private_key_by_hex(key: PEC_KEY; key_hex_str: string): Boolean;
var
  ret : Integer;
  pri_key: PBIGNUM;
  sm2_curve : PEC_GROUP;
begin
  Result := False;
  sm2_curve := EC_GROUP_new_by_curve_name(NID_sm2);
  pri_key := BN_new;
  ret := BN_hex2bn(pri_key, PAnsiChar(AnsiString(key_hex_str)));
  if ret <= 0 then
    Exit;
  ret := EC_KEY_set_group(key, sm2_curve);
  ret := EC_KEY_set_private_key(key, pri_key);
  if ret <= 0 then
    Exit;
  Result := True;
end;

function set_key_pare_by_hex(key: PEC_KEY; pri_key_hex_str: string; pub_key_hex_str: string = ''): Boolean;
var
  ret : Integer;
  pri_key: PBIGNUM;
  pub_key: PEC_POINT;
  sm2_curve : PEC_GROUP;
begin
  Result := False;
  sm2_curve := EC_GROUP_new_by_curve_name(NID_sm2);
  pri_key := BN_new;
  pub_key := EC_POINT_new(sm2_curve);
  ret := BN_hex2bn(pri_key, PAnsiChar(AnsiString(pri_key_hex_str)));
  if pub_key_hex_str = '' then
  begin
    EC_POINT_mul(sm2_curve, pub_key, pri_key, nil, nil, nil);
  end
  else
  begin
    EC_POINT_hex2point(sm2_curve, PAnsiChar(AnsiString(pub_key_hex_str)), pub_key, nil);
  end;
  ret := EC_KEY_set_group(key, sm2_curve);
  ret := EC_KEY_set_private_key(key, pri_key);
  ret := EC_KEY_set_public_key(key, pub_key);
  if ret <= 0 then
    Exit;
  Result := True;
end;

function create_EC_group(p_hex: string; a_hex: string; b_hex: string;
    x_hex: string; y_hex: string; order_hex: string; cof_hex: string): PEC_GROUP;
var
  p, a, b, g_x, g_y, order, cof : PBIGNUM;
  generator : PEC_POINT;
  group : PEC_GROUP;
  ok : Boolean;
  ret : Integer;
label
  done;
begin
  ok := False;
  Result := nil;
  p := BN_new;
  a := BN_new;
  b := BN_new;
  g_x := BN_new;
  g_y := BN_new;
  order := BN_new;
  cof := BN_new;
  ret := BN_hex2bn(p, PAnsiChar(AnsiString(p_hex)));
  ret := BN_hex2bn(a, PAnsiChar(AnsiString(a_hex)));
  ret := BN_hex2bn(b, PAnsiChar(AnsiString(b_hex)));
  group := EC_GROUP_new_curve_GFp(p, a, b, nil);
  if group = nil then
    goto done;
  generator := EC_POINT_new(group);
  if generator = nil then
    goto done;
  ret := BN_hex2bn(g_x, PAnsiChar(AnsiString(x_hex)));
  ret := BN_hex2bn(g_y, PAnsiChar(AnsiString(y_hex)));
  ret := EC_POINT_set_affine_coordinates_GFp(group, generator, g_x, g_y, nil);
  ret := BN_hex2bn(order, PAnsiChar(AnsiString(order_hex)));
  ret := BN_hex2bn(cof, PAnsiChar(AnsiString(cof_hex)));
  ret := EC_GROUP_set_generator(group, generator, order, cof);
  ok := True;
done:
  BN_free(p);
  BN_free(a);
  BN_free(b);
  BN_free(g_x);
  BN_free(g_y);
  EC_POINT_free(generator);
  BN_free(order);
  BN_free(cof);
  if not ok then
  begin
    EC_GROUP_free(group);
    group := nil;
  end;
  Result := group;
end;

end.
