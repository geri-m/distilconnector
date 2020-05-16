--[[
CHANGELOG:

2019-04-24: Improve metrics
--]]

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

-------------------------------------------------------------------------------

local function is_status_success(status)
    return type(status) == "number" and 200 <= status and status < 300
end

local function is_status_timeout(status)
    return status == 504
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
    local UNHEALTHY_THRESHOLD = 2
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

        if is_status_success(status) then
            consecutive_successful_requests = consecutive_successful_requests + 1
            consecutive_failed_requests = 0
            current_attempt_probability = RECOVERY_ATTEMPT_PROBABILITY
        else
            consecutive_successful_requests = 0
            consecutive_failed_requests = consecutive_failed_requests + 1
            current_attempt_probability = MIN_ATTEMPT_PROBABILITY
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
    integration_type = "openresty, vdms, or similar";
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
}
--]]
function Protection:new(settings, libs)
    local protection = {
        _analysis_path = "/v5/analysis";
        _instance_id = settings.integration_type .. "-" .. os.date("!%Y-%m-%dT%H:%M:%S") .. "-" .. math.random(1000000000);
        _libs = {
            fetch = healthcheck_fetch(libs.fetch);
            json_decode = libs.json_decode;
            json_encode = libs.json_encode;
            json_null = libs.json_null;
        };
        _settings = settings;
        _start_time = os.clock();
        _statistics = Statistics:new();
    }
    return setmetatable(protection, { __index = Protection })
end

--[[
client_ip: a string with the IP
raw_request: a string with the raw request excluding the body but including the \r\n\r\n before the body
request_id: optional string which uniquely identifies this request

Returns either an analysis or nil, error
Analysis: { action: string or nil; tags: [string]; }
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
        path = "/v5/analysis";
        headers = {
            ["Authorization"] = "Basic " .. base64_encode(self._settings.api_key_id .. ":" .. self._settings.api_secret_key);
            ["Content-Length"] = body:len();
            ["Content-Type"] = "application/json";
        };
        body = body;
    }

    local start_clock = os.clock()
    local status, body = self._libs.fetch(self._settings.analysis_host, self._settings.analysis_host_port, request)
    local latency_milli_sec = 1000.0 * (os.clock() - start_clock)

    if status == 200 then
        table.insert(self._statistics.success_latency_ms, latency_milli_sec)
    else
        -- The statistics didn't make it to bon, so save them again so we can resend them later:
        self._statistics:add_stats(analysis_request.statistics)

        if status == nil and body == THROTTLED_ERROR then
            self._statistics.error_stats.num_throttle = self._statistics.error_stats.num_throttle + 1
        elseif is_status_timeout(status) then
            self._statistics.error_stats.num_timeout = self._statistics.error_stats.num_timeout + 1
        else
            self._statistics.error_stats.num_other = self._statistics.error_stats.num_other + 1
        end
    end

    return self:_as_analysis(status, body)
end

function Protection:_as_analysis(status, body)
    if not is_status_success(status) then
        return nil, "fetch(): " .. (body or "UNKNOWN ERROR")
    end

    local analysis, err = self._libs.json_decode(body)
    if not analysis then
        return nil, err or "JSON decode error"
    end

    if analysis.action == self._libs.json_null then
        analysis.action = nil
    end

    local is_analysis = (analysis.action == nil or type(analysis.action) == "string") and type(analysis.tags) == "table"
    if not is_analysis then
        return nil, "Not an analysis"
    end

    return {
        action = analysis.action;
        tags = analysis.tags;
    }
end

function Protection:_integration_info()
    return {
        instance_id = self._instance_id;
        integration_library = "LIL";
        integration_type = self._settings.integration_type;
        uptime_sec = os.clock() - self._start_time;
    }
end

return {
    Protection = Protection;
}
