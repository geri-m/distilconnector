local BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

local function base64_encode(data)
    return ((data:gsub('.', function(x)
        local r, b = '', x:byte()
        for i = 8,1,-1 do
            r = r..(b % 2^i - b % 2^(i - 1) > 0 and '1' or '0')
        end
        return r
    end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if #x < 6 then
            return ''
        end
        local c = 0
        for i = 1,6 do
            c = c + (x:sub(i,i) == '1' and 2^(6 - i) or 0)
        end
        return BASE64_CHARS:sub(c+1, c+1)
    end)..({ '', '==', '=' })[#data % 3 + 1])
end

local function split_token(token)
    local t = {}
    for v in string.gmatch(token, "([^:]+)") do
        t[#t + 1] = v
    end

    return t
end

-------------------------------------------------------------------------------

local function is_status_success(status)
    return type(status) == "number" and 200 <= status and status < 300
end

local function is_status_timeout(status)
    return status == 504
end

local function should_lead_to_throttling(status)
    if type(status) ~= "number" then
        return true
    end

    -- Internal errors
    if status >= 500 then return true end

    -- Unauthorized
    if status == 401 then return true end

    -- Forbidden
    if status == 403 then return true end

    -- Request Timeout
    if status == 408 then return true end

    -- Too Many Requests
    if status == 429 then return true end

    return false
end

local THROTTLED_ERROR = "Throttled"

--[[
Wrap a fetcher so that many failed fetches lead to throttling.

A simple healthcheck strategy that changes state to unhealthy after
`unhealthyThreshold` consecutive failed requests and changes state back to
healthy after `healthyThreshold` consecutive successful requests.  When in
the unhealthy state, it will still probe with a low frequency
`minAttemptProbability` as long as probes fails but will probe with
`recoveryAttemptProbability` when probes succeeds.
The goal is to globally minimize latency while returning fast from downtime.
--]]
local function healthcheck_fetch(inner_fetch)
    local HEALTHY_THRESHOLD = 5
    local UNHEALTHY_THRESHOLD = 3
    local MIN_ATTEMPT_PROBABILITY = 0.01
    local RECOVERY_ATTEMPT_PROBABILITY = 0.1

    local consecutive_successful_requests = 0
    local consecutive_failed_requests = 0
    local healthy = true
    local current_attempt_probability = MIN_ATTEMPT_PROBABILITY

    return function(host, port, request)
        if not healthy and math.random() > current_attempt_probability then
            return nil, THROTTLED_ERROR
        end

        local status, body = inner_fetch(host, port, request)

        if should_lead_to_throttling(status) then
            consecutive_successful_requests = 0
            consecutive_failed_requests = consecutive_failed_requests + 1
            current_attempt_probability = MIN_ATTEMPT_PROBABILITY
        else
            consecutive_successful_requests = consecutive_successful_requests + 1
            consecutive_failed_requests = 0
            current_attempt_probability = RECOVERY_ATTEMPT_PROBABILITY
        end

        if consecutive_failed_requests >= UNHEALTHY_THRESHOLD then
            healthy = false
        elseif consecutive_successful_requests >= HEALTHY_THRESHOLD then
            healthy = true
        end

        return status, body
    end
end

-------------------------------------------------------------------------------

local Statistics = {}

function Statistics:new()
    return setmetatable({
        error_stats = {
            num_other = 0;
            num_throttle = 0;
            num_timeout = 0;
        };
        success_latency_ms = {};
    }, { __index = Statistics })
end

function Statistics:add_stats(other)
    self.error_stats.num_other    = self.error_stats.num_other    + other.error_stats.num_other
    self.error_stats.num_throttle = self.error_stats.num_throttle + other.error_stats.num_throttle
    self.error_stats.num_timeout  = self.error_stats.num_timeout  + other.error_stats.num_timeout

    if other.success_latency_ms then
        for _, v in ipairs(other.success_latency_ms) do
            table.insert(self.success_latency_ms, v)
        end
    end
end

function Statistics:json_friendly()
    return {
        error_stats = self.error_stats;

        -- Avoid problem with {} == empty array == empty object in Lua
        success_latency_ms = #self.success_latency_ms > 0 and self.success_latency_ms or nil;
    }
end

-------------------------------------------------------------------------------

-- os.clock() only has has 10ms granularity
-- ngx.now() has millisecond granularity
-- ngx.now returns a cached Nginx time. Hopefully it is updated by the fetch.
local now_sec = ngx and ngx.now or os.clock

-------------------------------------------------------------------------------

local Protection = {}

--[[
Create a new protection instance.
You should create on of these and reuse.

-- Ask your Distil contact person for how to fill this in
settings: {
    analysis_host = "analysishost.com";
    analysis_host_port = 443;
    api_key_id = "api-key-id-uuid";
    api_secret_key = "api-secret-key-base64";
    challenge_path = "/6657193977244c13";
    debug_header_value = "debug-me";
    integration_type = "openresty, vdms, or similar";
    token_encryption_key = "debug012345678901234567890123456789";
}

-- This is methods used by the Distil library that you will need to supply:
libs: {
    -- A method for doing a HTTP request.
    -- request = { method: string, path: string, headers: table, body: string }
    -- function(host, port, request) -> status_code, body
    -- Return nil, error_str if there is a non-http error.
    fetch = function(host, port, request) ... end;

    -- function(string) -> table  or  nil, err
    json_decode = function(string) ... end;

    -- function(table) -> string
    json_encode = function(table) ... end;

    -- What does the json library use to represent null values?
    -- (e.g. cjson.null)
    json_null = nil;

    -- How do we encrypt data?
    -- function(string, string) -> { iv: string, hmac: string, payload: string }
    encrypt = function(data, key) ... end;

    -- How do we decrypt data?
    -- function({ iv: string, hmac: string, payload: string }, string) -> string
    decrypt = function(encrypted, key) ... end;
}
--]]
function Protection:new(settings, libs)
    local protection = {
        _analysis_path = "/v6/analysis";
        _instance_id = settings.integration_type .. "-" .. os.date("!%Y-%m-%dT%H:%M:%S") .. "-" .. math.random(1000000000);
        _libs = {
            fetch = healthcheck_fetch(libs.fetch);
            json_decode = libs.json_decode;
            json_encode = libs.json_encode;
            json_null = libs.json_null;
            encrypt = libs.encrypt;
            decrypt = libs.decrypt;
        };
        _settings = settings;
        _start_time = now_sec();
        _statistics = Statistics:new();
    }
    return setmetatable(protection, { __index = Protection })
end

--[[
Ask the Distil edge to analyze the request

client_ip: a string with the IP
raw_request: a string with the raw request excluding the body but including the \r\n\r\n before the body
request_id: optional string which uniquely identifies this request

Returns either an analysis or nil, error
Analysis: { action: string or nil; tags: [string]; flags: [string]; }
--]]
function Protection:remote_analyze(client_ip, raw_request, request_id)
    local analysis_request = {
        client_ip = client_ip;
        integration_info = self:_integration_info();
        raw_request = base64_encode(raw_request);
        request_id = request_id;
        statistics = self._statistics:json_friendly();
    }
    self._statistics = Statistics:new()

    local body = self._libs.json_encode(analysis_request)

    local request = {
        method = "POST";
        path = "/v6/analysis";
        headers = {
            ["Authorization"] = "Basic " .. base64_encode(self._settings.api_key_id .. ":" .. self._settings.api_secret_key);
            ["Content-Length"] = body:len();
            ["Content-Type"] = "application/json";
        };
        body = body;
    }

    local start_clock = now_sec()
    local status, body = self._libs.fetch(self._settings.analysis_host, self._settings.analysis_host_port, request)
    local latency_milli_sec = 1000.0 * (now_sec() - start_clock)

    if status == 200 then
        table.insert(self._statistics.success_latency_ms, latency_milli_sec)
    else
        -- The statistics didn't make it to Distil, so save them again so we can resend them later:
        self._statistics:add_stats(analysis_request.statistics)

        if status == nil and body == THROTTLED_ERROR then
            self._statistics.error_stats.num_throttle = self._statistics.error_stats.num_throttle + 1
        elseif is_status_timeout(status) then
            self._statistics.error_stats.num_timeout = self._statistics.error_stats.num_timeout + 1
        else
            self._statistics.error_stats.num_other = self._statistics.error_stats.num_other + 1
        end
    end

    if not is_status_success(status) then
        return nil, "fetch(): " .. (body or "UNKNOWN ERROR")
    end

    return self:_as_analysis(body)
end

--[[
Extract an analysis from the Distil token, which may or may not be present.

cookies: A table of the cookies present in the request

Returns an analysis or nil, error
Analysis: { action: string or nil; tags: [string]; flags: [string]; }
--]]
function Protection:extract_analysis_from_token(cookies)
    if self._libs.decrypt == nil then
        return nil, "Decryption support is required for decrypting tokens but is unavailable"
    end

    local token = cookies["reese84"]
    if token == nil then
        return nil, nil
    end

    local token_parts = split_token(token)
    local iv = token_parts[2]
    if iv == nil then
        return nil, "Malformed token (missing IV)"
    end

    local payload = token_parts[3]
    if payload == nil then
        return nil, "Malformed token (missing payload)"
    end

    local hmac = token_parts[4]
    if hmac == nil then
        return nil, "Malformed hmac"
    end

    local encrypted = {
        iv = iv;
        hmac = hmac;
        payload = payload;
    }

    local decrypted_token, err = self._libs.decrypt(encrypted, self._settings.token_encryption_key)
    if decrypted_token == nil then
        return nil, "Failed to decrypt token: " .. err
    end

    return self:_as_analysis(decrypted_token)
end

--[[
Fetch a captcha or identify interstitial from the Distil edge.

action: The action returned from the analysis call. Either captcha or identify.
interstitial_request: { method: string; headers: table; client_ip: string; formdata: string or nil }

Returns content, err
--]]
function Protection:fetch_interstitial(analysis, interstitial_request, template)
    local action = analysis.action
    if action ~= "captcha" and action ~= "identify" then
        return nil, "Unsupported interstitial action: " .. action
    end

    -- request should contain method, headers, client_ip, formdata
    local host = interstitial_request.headers["Host"]

    local fetch_request = {
        method = interstitial_request.method;
        path = "/v6/" .. action .. "/" .. self._settings.api_key_id .. self._settings.challenge_path;
        headers = {
            ["x-d-tags"] = table.concat(analysis.tags, ",");
            ["x-d-condition-ids"] = table.concat(analysis.deciding_condition_ids, ",");
            ["X-Forwarded-Host"] = host;
            ["X-Forwarded-For"] = interstitial_request.client_ip;
            ["Content-Type"] = "application/x-www-form-urlencoded";
            ["Accept"] = "application/json";
        };
    }

    local status, content = self._libs.fetch(self._settings.analysis_host, self._settings.analysis_host_port, fetch_request)
    if status == nil then
        return nil, "Failed to fetch interstitial: " .. content
    end

    local interstitial_data, err = self._libs.json_decode(content)
    if interstitial_data == nil then
        return nil, "Failed to parse insterstitial data: " .. err
    end

    local response = {}
    response["status"] = status

    if interstitial_request.method == "POST" then
        if interstitial_request.headers["Content-Type"] ~= "application/x-www-form-urlencoded" then
            return nil, "identify/captcha on POST requests can only be done for form requests"
        end

        if self._libs.encrypt == nil then
            return nil, "Encryption support is required for processing POST requests but is unavailable"
        end

        local encrypted, err = self._libs.encrypt(interstitial_request.formdata, self._settings.token_encryption_key)

        interstitial_data.body = interstitial_data.body:gsub("__ENCRYPTED_REQUEST_BODY__", encrypted.payload)
        response["cookie"] = "reese84-resubmit-token=" .. encrypted.iv .. ":" .. encrypted.hmac .. "; HttpOnly; Max-Age=60"
    end

    content = self:render_interstitial(template, interstitial_data)

    response["content"] = content

    return response, nil
end

function Protection:render_interstitial(template, data)
    for k, v in pairs(data) do
        local substitution = "{{{? *" .. k .. " *}?}}"
        template = template:gsub(substitution, data[k])
    end

    return template
end

--[[
Decrypt an encrypted post payload

resubmit_token: The token, as derived from a cookie
resubmit_data: The payload, extracted from form data

Returns a string of decrypted data, err
--]]
function Protection:decrypt_resubmitted_data(resubmit_token, resubmit_data)
    if self._libs.decrypt == nil then
        return nil, "Decryption support is required for processing POST payloads, but is unavailable"
    end

    local token_parts = split_token(resubmit_token)
    local iv = token_parts[1]
    if iv == nil then
        return nil, "Malformed resubmit token (missing IV)"
    end

    local hmac = token_parts[2]
    if hmac == nil then
        return nil, "Malformed resubmit token (missing HMAC)"
    end

    local encrypted = {
        iv = iv;
        hmac = hmac;
        payload = resubmit_data;
    }

    local decrypted, err = self._libs.decrypt(encrypted, self._settings.token_encryption_key)
    if decrypted == nil then
        return nil, "Failed to decrypt: " .. err
    end

    return decrypted, nil
end

local function is_analysis(analysis)
    if analysis.action ~= nil and type(analysis.action) ~= "string" then return false end
    if analysis.flags ~= nil and type(analysis.flags) ~= "table" then return false end
    if analysis.tags ~= nil and type(analysis.tags) ~= "table" then return false end
    if analysis.deciding_condition_ids ~= nil and type(analysis.deciding_condition_ids) ~= "table" then return false end
    return true
end

function Protection:_as_analysis(body)
    local analysis, err = self._libs.json_decode(body)
    if not analysis then
        return nil, err or "JSON decode error"
    end

    local json_null = self._libs.json_null

    if analysis.action == json_null then analysis.action = nil end
    if analysis.flags == json_null then analysis.flags = nil end -- shouldn't happen, but nice to be future proof
    if analysis.tags == json_null then analysis.tags = {} end -- shouldn't happen, but nice to be future proof
    if analysis.deciding_condition_ids == json_null then analysis.deciding_condition_ids = {} end -- shouldn't happen, but nice to be future proof

    if not is_analysis(analysis) then
        return nil, "Not an analysis"
    end

    return {
        action = analysis.action;
        flags = analysis.flags;
        tags = analysis.tags;
        deciding_condition_ids = analysis.deciding_condition_ids;
    }
end

function Protection:_integration_info()
    return {
        instance_id = self._instance_id;
        integration_library = "DIL-Lua 0.6 2020-05-12";
        integration_type = self._settings.integration_type;
        uptime_sec = now_sec() - self._start_time;
    }
end

-- Safe set of headers which we can send to bon without needing to mask the contents as they could contain
-- passwords, API Keys, personal information etc
local safe_whitelist_headers = {
    ["accept"] = true,
    ["accept-charset"] = true,
    ["accept-encoding"] = true,
    ["accept-language"] = true,
    ["cf-connecting-ip"] = true,
    ["cache-control"] = true,
    ["connection"] = true,
    ["content-length"] = true,
    ["content-type"] = true,
    ["host"] = true,
    ["referer"] = true,
    ["user-agent"] = true,
    ["x-forwarded-for"] = true,
    ["x-forwarded-host"] = true,
    ["x-forwarded-proto"] = true,
    ["x-real-ip"] = true,
}

-- By default we want to mask any standard authorization headers so we don't send any access tokens
-- or username/passwords
local default_header_mask = {
    ["authorization"] = true,
    ["proxy-authenticate"] = true,
    ["proxy-authorization"] = true,
    ["www-authenticate"] = true,
}

local distil_whitelist_headers = {
    ["x-d-action"] = true,
    ["x-d-domain"] = true,
    ["x-d-test"] = true,
    ["x-d-token"] = true,
    ["x-distil-challenge"] = true,
    ["x-distil-debug"] = true,
}

-- These must be plain text no matter what or connector will mark the requests as bots
local distil_whitelist_cookies = {
    ["reese84"] = true,
    ["reese84-resubmit-token"] = true,
    ["x-d-token"] = true,
}

local function mask(value)
    return value:gsub("[^,%s]", "X")
end

-- https://stackoverflow.com/a/19329565
local function lines(s)
    if s:sub(-1) ~= "\n" then
        s = s.."\n"
    end
    return s:gmatch("(.-[\r\n]+)")
end

local M = {
    Protection = Protection;
}

local function trim(s)
   return s:match( "^%s*(.-)%s*$" )
end

-- Given the contents of the cookie header,
-- return a table mapping cookie keys to their values.
-- You can pass in either a string (single cookie header)
-- or a list of strings (multiple cookie headers).
-- nil results in an empty list.
function M.cookie_table(cookies)
    local t = {}
    M.parse_cookies(cookies, function (key, value)
        t[trim(key)] = trim(value)
    end)
    return t
end

function M.parse_cookies(cookies, consumer)
    if cookies == nil then
        return
    end

    if type(cookies) == "table" then
        for _, line in ipairs(cookies) do
            for k, v, sep in string.gmatch(line, "([^=]*)=([^;]*)(;?)") do
                consumer(k, v, sep)
            end
        end
    else
        for k, v, sep in string.gmatch(cookies, "([^=]*)=([^;]*)(;?)") do
            consumer(k, v, sep)
        end
    end
end

local function mask_header(name)
    return default_header_mask[name]
end

function M.mask_header(name, value)
    local lowerName = name:lower()

    if distil_whitelist_headers[lowerName] then
        return value
    end

    if lowerName == "cookie" then
        local values = {}
        local cookies = M.parse_cookies(value, function (key, cookieValue, sep)
            local lowerKey = trim(key):lower()
            if not distil_whitelist_cookies[lowerKey] then
                cookieValue = mask(cookieValue)
            end
            table.insert(values, key.."="..cookieValue..sep)
        end)
        return table.concat(values, "")
    end

    if mask_header(lowerName) then
        return mask(value)
    end

    return value
end

function M.mask_raw_headers(raw_headers)
    local output = {}
    for line in lines(raw_headers) do
        if #output == 0 then
            table.insert(output, line) -- leave the request line alone
        else
            for name, space, value, eol in line:gmatch("([^:%s]+)(%s*:%s*)([^\r\n]*)([\r\n]+)") do
                table.insert(output, name..space..M.mask_header(name, value)..eol)
            end
        end
    end
    return table.concat(output, "")
end

return M
