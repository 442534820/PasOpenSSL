unit PasOpenSSL;

interface

uses
 System.SysUtils, System.Variants, System.Classes, Winapi.Windows, IdSSLOpenSSLHeaders, IdSSL, IdSSLOpenSSL;



type
  TSupportCipherList = record
    Alog: string;
    Mode: string;
  end;

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
function ERR_get_error: ULONG; external libcrypto;
//BigNumber functions
function BN_new: PBIGNUM; external libcrypto;
procedure BN_free(a: PBIGNUM); external libcrypto;
function BN_bn2hex(const a: PBIGNUM): PAnsiChar; external libcrypto;
function BN_bn2dec(const a: PBIGNUM): PAnsiChar; external libcrypto;
function BN_hex2bn(var bn: PBIGNUM; const a: PAnsiChar): Integer; external libcrypto;  //BIGNUM **bn
function BN_dec2bn(var bn: PBIGNUM; const a: PAnsiChar): Integer; external libcrypto;  //BIGNUM **bn
function BN_asc2bn(var bn: PBIGNUM; const a: PAnsiChar): Integer; external libcrypto;  //BIGNUM **bn
//EC Point functions
function EC_POINT_point2oct(const group: PEC_GROUP; const point: PEC_POINT; form: Tpoint_conversion_form; buf: PByte; len: SIZE_T; ctx: PBN_CTX): SIZE_T; external libcrypto;
function EC_POINT_oct2point(const group: PEC_GROUP; point: PEC_POINT; const buf: PByte; len: SIZE_T; ctx: PBN_CTX): Integer; external libcrypto;
function EC_POINT_point2buf(const group: PEC_GROUP; const Pointer: PEC_POINT; form: Tpoint_conversion_form; var pbuf: PByte; ctx: PBN_CTX): SIZE_T; external libcrypto;
function EC_POINT_point2bn(const group: PEC_GROUP; const point: PEC_POINT; form: Tpoint_conversion_form; ret: PBIGNUM; ctx: PBN_CTX): PBIGNUM; external libcrypto;
function EC_POINT_bn2point(const group: PEC_GROUP; const bn: PBIGNUM; point: PEC_POINT; ctx: PBN_CTX): PEC_POINT; external libcrypto;
function EC_POINT_point2hex(const group: PEC_GROUP; const point: PEC_POINT; form: Tpoint_conversion_form; ctx: PBN_CTX): PAnsiChar; external libcrypto;
function EC_POINT_hex2point(const group: PEC_GROUP; const buf: PAnsiChar; point: PEC_POINT; ctx: PBN_CTX): PEC_POINT; external libcrypto;
//EVP Cipher functions
function EVP_CIPHER_CTX_new: PEVP_CIPHER_CTX; stdcall; external libcrypto;
function EVP_CipherInit_ex(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; impl: PENGINE; key: PAnsiChar; iv: PAnsiChar; enc: Integer): Integer; stdcall; external libcrypto;
function EVP_CipherUpdate(ctx: PEVP_CIPHER_CTX; _out : PAnsiChar; var outl: Integer; _in: PAnsiChar; inl: Integer): Integer; stdcall; external libcrypto;
function EVP_CipherFinal_ex(ctx: PEVP_CIPHER_CTX; outm: PAnsiChar; var outl: Integer): Integer; stdcall; external libcrypto;
procedure EVP_CIPHER_CTX_fre(a: PEVP_CIPHER_CTX); stdcall; external libcrypto;
function EVP_get_cipherbyname(const name: PAnsiChar): PEVP_CIPHER; stdcall; external libcrypto;
function EVP_CIPHER_CTX_set_padding(c: PEVP_CIPHER_CTX; pad: Integer): Integer; stdcall; external libcrypto;
//EVP Message Digest functions
function EVP_MD_CTX_new:PEVP_MD_CTX; stdcall; external libcrypto;
procedure EVP_MD_CTX_set_pkey_ctx(ctx: PEVP_MD_CTX; pctx: PEVP_PKEY_CTX); external libcrypto;
function EVP_DigestInit_ex(ctx: PEVP_MD_CTX; const AType: PEVP_MD; impl: PENGINE): Integer; stdcall; external libcrypto;
function EVP_DigestUpdate(ctx: PEVP_MD_CTX; d: Pointer; cnt: SIZE_T): Integer; external libcrypto;
function EVP_DigestFinal(ctx: PEVP_MD_CTX; md: PByte; size: PUINT): Integer; external libcrypto;
function EVP_DigestFinal_ex(ctx: PEVP_MD_CTX; md: PAnsiChar; var s: UINT): Integer; external libcrypto;
procedure EVP_MD_CTX_free(ctx: PEVP_MD_CTX); external libcrypto;
function EVP_get_digestbyname(const name: PAnsiChar): PEVP_MD; external libcrypto;
//EVP PKEY functions
function EVP_PKEY_new: PEVP_PKEY; external libcrypto;
function EVP_PKEY_new_raw_public_key(_type: Integer; e: PENGINE; const public: PByte; len: SIZE_T): PEVP_PKEY; external libcrypto;
function EVP_PKEY_assign(pkey: PEVP_PKEY; _type: Integer; key: Pointer): Integer; external libcrypto;
function EVP_PKEY_CTX_new(pkey: PEVP_PKEY; e: PENGINE): PEVP_PKEY_CTX; external libcrypto;
procedure EVP_PKEY_CTX_free(ctx: PEVP_PKEY_CTX); external libcrypto;
function EVP_PKEY_CTX_ctrl(ctx: PEVP_PKEY_CTX; keytype: Integer; optype: Integer; cmd: Integer; p1: Integer; p2: Pointer): Integer; external libcrypto;
function EVP_PKEY_set_type(pkey: PEVP_PKEY; _type: Integer): Integer; external libcrypto;
function EVP_PKEY_set_alias_type(pkey: PEVP_PKEY; _type: Integer): Integer; external libcrypto;
//EVP m_sigver.c
function EVP_DigestSignInit(ctx: PEVP_MD_CTX; PCTX: PPEVP_PKEY_CTX; const _type: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): Integer; external libcrypto;
function EVP_DigestVerifyInit(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; const _type: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): Integer; external libcrypto;
function EVP_DigestSignFinal(ctx: PEVP_MD_CTX; sigret: PByte; siglen: PSIZE_T): Integer; external libcrypto;
function EVP_DigestSign(ctx: PEVP_MD_CTX; sigret: PByte; siglen: PSIZE_T; const tbs: PByte; tbslen: SIZE_T): Integer; external libcrypto;
function EVP_DigestVerifyFinal(ctx: PEVP_MD_CTX; const sig: PByte; siglen: SIZE_T): Integer; external libcrypto;
function EVP_DigestVerify(ctx: PEVP_MD_CTX; const sigret: PByte; siglen: SIZE_T; const tbs: PByte; tbslen: SIZE_T): Integer; external libcrypto;
function EVP_DigestInit(ctx: PEVP_MD_CTX; const _type: PEVP_MD): Integer; external libcrypto;
//function EVP_DigestInit_ex(ctx: PEVP_MD_CTX; const _type: PEVP_MD; impl: PENGINE): Integer; external libcrypto;
//function EVP_DigestUpdate(ctx: PEVP_MD_CTX; const data: Pointer; count: SIZE_T): Integer; external libcrypto;
//function EVP_DigestFinal(ctx: PEVP_MD_CTX; md: PByte; size: PUINT): Integer; external libcrypto;
//function EVP_DigestFinal_ex(ctx: PEVP_MD_CTX; md: PByte; size: PUINT): Integer; external libcrypto;
//
function EVP_EncryptUpdate(ctx: PEVP_CIPHER_CTX; _out: PByte; outl: PINT; const _in: PByte; inl: Integer): Integer; external libcrypto;
function EVP_DecryptUpdate(ctx: PEVP_CIPHER_CTX; _out: PByte; outl: PINT; const _in: PByte; inl: Integer): Integer; external libcrypto;
//EC Group functions
function EC_GROUP_new_by_curve_name(nid: Integer): PEC_GROUP; external libcrypto;
//EC Point functions
function EC_POINT_new(const group: PEC_GROUP): PEC_POINT; external libcrypto;
procedure EC_POINT_free(point: PEC_POINT); external libcrypto;
procedure EC_POINT_clear_free(point: PEC_POINT); external libcrypto;
function EC_POINT_copy(dst: PEC_POINT; const src: PEC_POINT): Integer; external libcrypto;
function EC_POINT_dup(const src: PEC_POINT; const group: PEC_GROUP): PEC_POINT; external libcrypto;
//EC Key functions
function EC_KEY_new: PEC_KEY; external libcrypto;
function EC_KEY_new_by_curve_name(nid: Integer): PEC_KEY; external libcrypto;
procedure EC_KEY_free(r: PEC_KEY); external libcrypto;
function EC_KEY_copy(dest: PEC_KEY; const src: PEC_KEY): PEC_KEY; external libcrypto;
function EC_KEY_dup(const ec_key: PEC_KEY): PEC_KEY; external libcrypto;
function EC_KEY_up_ref(r: PEC_KEY): Integer; external libcrypto;
function EC_KEY_get0_engine(const eckey: PEC_KEY): PENGINE; external libcrypto;
function EC_KEY_generate_key(eckey: PEC_KEY): Integer; external libcrypto;
function ec_key_simple_generate_key(eckey: PEC_KEY): Integer; external libcrypto;
function ec_key_simple_generate_public_key(eckey:PEC_KEY): Integer; external libcrypto;
function EC_KEY_check_key(const eckey: PEC_KEY): Integer; external libcrypto;
function ec_key_simple_check_key(const eckey: PEC_KEY): Integer; external libcrypto;
function EC_KEY_set_public_key_affine_coordinates(key: PEC_KEY; x: PBIGNUM; y: PBIGNUM): Integer; external libcrypto;
function EC_KEY_get0_group(const key: PEC_KEY): PEC_GROUP; external libcrypto;   //return const
function EC_KEY_set_group(key: PEC_KEY; const group: PEC_GROUP): Integer; external libcrypto;
function EC_KEY_get0_private_key(const key: PEC_KEY): PBIGNUM; external libcrypto;
function EC_KEY_set_private_key(key: PEC_KEY; const priv_key: PBIGNUM): Integer; external libcrypto;
function EC_KEY_get0_public_key(const key: PEC_KEY): PEC_POINT; external libcrypto;
function EC_KEY_set_public_key(key: PEC_KEY; const pub_key: PEC_POINT): Integer; external libcrypto;
function EC_KEY_get_enc_flags(const key: PEC_KEY): UINT; external libcrypto;
procedure EC_KEY_set_enc_flags(key: PEC_KEY; flags: UINT); external libcrypto;
function EC_KEY_get_conv_form(const key: PEC_KEY): Tpoint_conversion_form; external libcrypto;
procedure EC_KEY_set_conv_form(key: PEC_KEY; cform: Tpoint_conversion_form); external libcrypto;
procedure EC_KEY_set_asn1_flag(key: PEC_KEY; flag: Integer); external libcrypto;
function EC_KEY_precompute_mult(key: PEC_KEY; ctx: PBN_CTX): Integer; external libcrypto;
function EC_KEY_get_flags(const key: PEC_KEY): Integer; external libcrypto;
procedure EC_KEY_set_flags(key: PEC_KEY; flags: Integer); external libcrypto;
procedure EC_KEY_clear_flags(key: PEC_KEY; flags: Integer); external libcrypto;


//macro functions
function EVP_PKEY_CTX_set1_id(ctx: PEVP_PKEY_CTX; id: Pointer; id_len: Integer): Integer;
function EVP_PKEY_CTX_get1_id(ctx: PEVP_PKEY_CTX; id: Pointer): Integer;
function EVP_PKEY_CTX_get1_id_len(ctx: PEVP_PKEY_CTX; id_len: Integer): Integer;
function EVP_SignIint_ex(ctx: PEVP_MD_CTX; const _type: PEVP_MD; impl: PENGINE): Integer;
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
function GetPByteFromASCIIStrs(in_str: TStrings; var out_len: Integer): PByte;
function PByteToString(in_pbyte: PByte; in_len: Integer; split_str: string): string;
function PAnsiCharToString(in_pansichar: PAnsiChar; in_len: Integer; split_str: string): string;


///////////////////////////////////////

procedure do_md(alog_name: string;
    input: PByte; output: PByte;
    input_len: Integer; var output_len: Integer);
procedure do_cipher(alog_name: string; do_enc: Integer; padding: Integer;
    input: PByte; output: PByte; key: PByte; iv: PByte;
    input_len: Integer; var output_len: Integer; key_len: Integer; iv_len: Integer);
function check_cipher(alog_name: string): Boolean;
function get_cipher_key_size(alog_name: string): Integer;
function get_cipher_iv_size(alog_name: string): Integer;
function get_cipher_block_size(alog_name: string): Integer;
function get_cipher_all_size(alog_name: string; var key_size: Integer; var iv_size: Integer; var block_size: Integer): Boolean;

function set_public_key_by_hex(key: PEC_KEY; key_hex_str: string): Boolean;
function set_private_key_by_hex(key: PEC_KEY; key_hex_str: string): Boolean;

implementation

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

function EVP_SignIint_ex(ctx: PEVP_MD_CTX; const _type: PEVP_MD; impl: PENGINE): Integer;
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

//////////////////////////////////////////////////////////////////////////////////////////

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

function GetPByteFromASCIIStrs(in_str: TStrings; var out_len: Integer): PByte;
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

procedure do_sm2sign(group: PEC_GROUP;
  userid: PByte; prikey: PByte; msg: PByte; k: PByte; sig: PByte;
  userid_len: Integer; msg_len: Integer);
var
  ok : Integer;
begin

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



end.
