local aes = require 'resty.aes'
local random = require 'resty.random'
local hmac = require 'resty.hmac'

local ngx = ngx

local IV_RANDOM_BYTES = 16
local ZLIB_WINDOW_BITS = -15
local ZLIB_COMPRESSION_LEVEL = 6

local function generate_hmac(data, hash_key)
    local hmac_sha256 = hmac:new(hash_key, hmac.ALGOS.SHA256)
    return ngx.encode_base64(hmac_sha256:final(data, false))
end

--[[--
    Generate encrypted payload and components in base64
    Deflate payload, then encrypt, and base64 encode
    function(string, string) -> { iv: string, hmac: string, payload: string }
--]]
local function encrypt(data, key)

    -- Load keys
    local encryption_key = key:sub(1, 32)
    local hash_key = key:sub(-32)

    local iv_bytes = random.bytes(IV_RANDOM_BYTES)
    local iv_base64 = ngx.encode_base64(iv_bytes)

    -- Deflate payload
    local zlib = require 'zlib'
    local deflate = zlib.deflate(ZLIB_COMPRESSION_LEVEL, ZLIB_WINDOW_BITS)

    local status, unencrypted_compressed_payload = pcall(deflate, data, 'finish')
    if not status then
        return nil, 'Compression failed'
    end

    -- Encrypt deflated payload
    local aes_256_cbc, aes_err = aes:new(encryption_key, nil, aes.cipher(256,'cbc'), { iv = iv_bytes })
    if not aes_256_cbc then
        return nil, 'AES Error: ' .. tostring(aes_err)
    end

    local encrypted_compressed_payload = aes_256_cbc:encrypt(unencrypted_compressed_payload)
    if not encrypted_compressed_payload then
        return nil, 'Unable to encrypt payload'
    end

    -- Base64 encode payload
    local payload_base64 = ngx.encode_base64(encrypted_compressed_payload)

    return {
        iv = iv_base64,
        hmac = generate_hmac(payload_base64, hash_key),
        payload = payload_base64
    }

end

--[[--
    Decrypts token payload from base64 encoded strings
    Take base64 encoded payload, decrypt, inflate
    function({ iv: string, hmac: string, payload: string }, string) -> string
--]]
local function decrypt(encrypted_data, key)
    if not encrypted_data.iv or not encrypted_data.hmac or not encrypted_data.payload or not key then
        return nil, 'Missing decryption parameter'
    end

    -- Load keys
    local encryption_key = key:sub(1, 32)
    local hash_key = key:sub(-32)

    -- Verify HMAC
    if encrypted_data.hmac ~= generate_hmac(encrypted_data.payload, hash_key) then
        return nil, "Invalid HMAC"
    end

    -- Decode base64 payload and iv
    local payload_bytes = ngx.decode_base64(encrypted_data.payload)
    local iv_bytes = ngx.decode_base64(encrypted_data.iv)

    -- Decrypt payload
    local aes_256_cbc, aes_err = aes:new(encryption_key, nil, aes.cipher(256,'cbc'), { iv = iv_bytes })
    if not aes_256_cbc then
        return nil, 'AES Error: ' .. tostring(aes_err)
    end

    local decrypted_compressed_payload = aes_256_cbc:decrypt(payload_bytes)

    if not decrypted_compressed_payload then
        return nil, 'Unable to decrypt payload'
    end

    -- Inflate decrypted payload
    local zlib = require 'zlib'
    local inflate = zlib.inflate(ZLIB_WINDOW_BITS)
    local status, decrypted_uncompressed_payload = pcall(inflate, decrypted_compressed_payload)
    if not status then
        return nil, 'Inflation failed'
    end

    return decrypted_uncompressed_payload
end

return {
    decrypt = decrypt,
    encrypt = encrypt
}
