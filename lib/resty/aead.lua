local ffi = require "ffi"
local base = require "resty.core.base"

local C = ffi.C
local ffi_new = ffi.new
local ffi_gc = ffi.gc
local ffi_str = ffi.string
local setmetatable = setmetatable
local tonumber = tonumber
local type = type
local get_size_ptr = base.get_size_ptr
local get_string_buf = base.get_string_buf

ffi.cdef[[
typedef struct evp_aead_st EVP_AEAD;
typedef struct evp_aead_ctx_st {
	const EVP_AEAD *aead;
	void *aead_state;
} EVP_AEAD_CTX;
typedef struct engine_st ENGINE;

uint32_t ERR_get_error_line(const char **file, int *line);
const char *ERR_lib_error_string(uint32_t packed_error);
const char *ERR_func_error_string(uint32_t packed_error);
const char *ERR_reason_error_string(uint32_t packed_error);
void ERR_error_string_n(uint32_t packed_error, char *buf, size_t len);

int RAND_bytes(uint8_t *buf, size_t len);

const EVP_AEAD *EVP_aead_aes_128_gcm(void);
const EVP_AEAD *EVP_aead_aes_256_gcm(void);
const EVP_AEAD *EVP_aead_chacha20_poly1305(void);
const EVP_AEAD *EVP_aead_chacha20_poly1305_old(void);
const EVP_AEAD *EVP_aead_aes_128_key_wrap(void);
const EVP_AEAD *EVP_aead_aes_256_key_wrap(void);
const EVP_AEAD *EVP_aead_aes_128_ctr_hmac_sha256(void);
const EVP_AEAD *EVP_aead_aes_256_ctr_hmac_sha256(void);

int EVP_has_aes_hardware(void);

size_t EVP_AEAD_key_length(const EVP_AEAD *aead);
size_t EVP_AEAD_nonce_length(const EVP_AEAD *aead);
size_t EVP_AEAD_max_overhead(const EVP_AEAD *aead);
size_t EVP_AEAD_max_tag_len(const EVP_AEAD *aead);

void EVP_AEAD_CTX_zero(EVP_AEAD_CTX *ctx);
int EVP_AEAD_CTX_init(EVP_AEAD_CTX *ctx, const EVP_AEAD *aead,
                      const uint8_t *key, size_t key_len,
                      size_t tag_len, ENGINE *impl);
void EVP_AEAD_CTX_cleanup(EVP_AEAD_CTX *ctx);

int EVP_AEAD_CTX_seal(const EVP_AEAD_CTX *ctx, uint8_t *out,
                      size_t *out_len, size_t max_out_len,
                      const uint8_t *nonce, size_t nonce_len,
                      const uint8_t *in, size_t in_len,
                      const uint8_t *ad, size_t ad_len);
int EVP_AEAD_CTX_open(const EVP_AEAD_CTX *ctx, uint8_t *out,
                      size_t *out_len, size_t max_out_len,
                      const uint8_t *nonce, size_t nonce_len,
                      const uint8_t *in, size_t in_len,
                      const uint8_t *ad, size_t ad_len);
]]

local ERR_ERROR_STRING_BUF_LEN = 256

local EVP_AEAD_MAX_KEY_LENGTH = 80
local EVP_AEAD_MAX_NONCE_LENGTH = 16
local EVP_AEAD_MAX_OVERHEAD = 64
local EVP_AEAD_DEFAULT_TAG_LENGTH = 0

local emt = {}

function emt.__tostring(self)
	local buf = get_string_buf(ERR_ERROR_STRING_BUF_LEN)
	C.ERR_error_string_n(self._code, buf, ERR_ERROR_STRING_BUF_LEN)
	return ffi_str(buf)
end

local ccharpp = ffi.new("const char*[1]")
local intp = ffi.new("int[1]")

local function error_str()
	local code = C.ERR_get_error_line(ccharpp, intp)
	if code == 0 then
		return nil
	end

	return setmetatable({
		_code = code,

		file = ffi_str(ccharpp[0]),
		line = intp[0],

		library = ffi_str(C.ERR_lib_error_string(code)),
		func = ffi_str(C.ERR_func_error_string(code)),
		reason = ffi_str(C.ERR_reason_error_string(code)),
	}, emt)
end

local _M = {}
local mt = { __index = _M }

_M.AES_128_GCM = {}
_M.AES_256_GCM = {}
_M.CHACHA20_POLY1305 = {}
_M.CHACHA20_POLY1305_OLD = {}
_M.AES_128_CTR_HMAC256 = {}
_M.AES_256_CTR_HMAC256 = {}
_M.AES_128_KEY_WRAP = {}
_M.AES_256_KEY_WRAP = {}

local AEAD_CTXS = {
	[_M.AES_128_GCM] = C.EVP_aead_aes_128_gcm,
	[_M.AES_256_GCM] = C.EVP_aead_aes_256_gcm,
	[_M.CHACHA20_POLY1305] = C.EVP_aead_chacha20_poly1305,
	[_M.CHACHA20_POLY1305_OLD] = C.EVP_aead_chacha20_poly1305_old,
	[_M.AES_128_CTR_HMAC256] = C.EVP_aead_aes_128_ctr_hmac_sha256,
	[_M.AES_256_CTR_HMAC256] = C.EVP_aead_aes_256_ctr_hmac_sha256,
	[_M.AES_128_KEY_WRAP] = C.EVP_aead_aes_128_key_wrap,
	[_M.AES_256_KEY_WRAP] = C.EVP_aead_aes_256_key_wrap,
}

function _M.has_aes_hardware()
	return C.EVP_has_aes_hardware() == 1
end

function _M.rand(len)
	local buf = get_string_buf(len)

	if C.RAND_bytes(buf, len) ~= 1 then
		return nil, error_str()
	end

	return ffi_str(buf, len)
end

local function aead_length(fn, self)
	if self.ctx then
		return tonumber(fn(self.aead))
	end

	local ctx_fn = AEAD_CTXS[self]
	if not ctx_fn then
		return nil, "invalid cipher"
	end

	return tonumber(fn(ctx_fn()))
end

function _M.key_len(...)
	return aead_length(C.EVP_AEAD_key_length, ...)
end

function _M.nonce_len(...)
	return aead_length(C.EVP_AEAD_nonce_length, ...)
end

function _M.max_overhead(...)
	return aead_length(C.EVP_AEAD_max_overhead, ...)
end

function _M.max_tag_len(...)
	return aead_length(C.EVP_AEAD_max_tag_len, ...)
end

local evp_aead_ctx_type = ffi.typeof("EVP_AEAD_CTX[1]")

function _M.new(id, key, tag_len)
	local ctx_fn = AEAD_CTXS[id]
	if not ctx_fn then
		return nil, "invalid cipher"
	end

	local ctx = ffi_new(evp_aead_ctx_type)
	local aead = ctx_fn()

	if C.EVP_AEAD_CTX_init(ctx, aead, key, #key, tag_len or EVP_AEAD_DEFAULT_TAG_LENGTH, nil) ~= 1 then
		return nil, error_str()
	end

	ffi_gc(ctx, C.EVP_AEAD_CTX_cleanup)

	return setmetatable({ ctx = ctx, aead = aead }, mt)
end

function _M.seal(self, nonce, pt, ad)
	if not self.ctx then
		return error("not initialized")
	end

	local pt_len = #pt
	local max_ct_len = pt_len + C.EVP_AEAD_max_overhead(self.aead)
	local ct = get_string_buf(max_ct_len)
	local ct_len = get_size_ptr()

	if C.EVP_AEAD_CTX_seal(self.ctx, ct, ct_len, max_ct_len, nonce, #nonce, pt, pt_len, ad, #ad) ~= 1 then
		return nil, error_str()
	end

	return ffi_str(ct, ct_len[0])
end

function _M.open(self, nonce, ct, ad)
	if not self.ctx then
		return error("not initialized")
	end

	local ct_len = #ct
	local pt = get_string_buf(ct_len)
	local pt_len = get_size_ptr()

	if C.EVP_AEAD_CTX_open(self.ctx, pt, pt_len, ct_len, nonce, #nonce, ct, ct_len, ad, #ad) ~= 1 then
		return nil, error_str()
	end

	return ffi_str(pt, pt_len[0])
end

return _M
