local json = require "cjson.safe"
local http = require "resty.http"

local distil = require "distil.distil"

-------------------------------------------------------------------------------

local CONFIG = {
    connection_timeout = 500;
    send_timeout = 500;
    read_timeout = 500;
    keepalive_requests = 10000;
    max_idle_timeout = 65000;
    pool_size = 100;
}

local function fetch(host, port, request)
    local connection = http.new()
    connection:set_timeouts(CONFIG.connection_timeout, CONFIG.send_timeout, CONFIG.read_timeout)

    local ok, err = connection:connect(host, port)
    if not ok then
        return nil, "connect(): " .. err
    end
    local res, err = connection:request(request)

    if not res then
        return nil, "request(): " .. err
    end

    local body, err = res:read_body()
    if not body then
        return nil, err or "Error in read_body"
    end

    if res.status ~= 200 then
        return nil, res.status .. ": " .. body
    end

    local times, err = connection:get_reused_times()
    if not times then
        return nil, "get_reused_times(): " .. err
    end

    if times < CONFIG.keepalive_requests then
        local ok, err = connection:set_keepalive(CONFIG.max_idle_timeout, CONFIG.pool_size)
        if not ok then
            return nil, "set_keepalive(): " .. err
        end
    else
        local ok, err = connection:close()
        if not ok then
            return nil, "close(): " .. err
        end
    end

    return res.status, body
end

-------------------------------------------------------------------------------

-- Ask your Distil contact person for how to fill these in.
local SETTINGS = {
    analysis_host = "bonproxy";
    analysis_host_port = 80;
    api_key_id = "debug-id";
    api_secret_key = "password";
    integration_type = "openresty";
}

-- Functions needed by the Distil library.
local LIBS = {
    -- request = { method: string, path: string, headers: table, body: string }
    -- function(host, port, request) -> status_code, body
    fetch = fetch;

    -- function(string) -> table
    json_decode = json.decode;

    -- function(table) -> string
    json_encode = json.encode;

    -- What does the json library use to represent null values?
    json_null = json.null;
}

local protection = distil.Protection:new(SETTINGS, LIBS)

-------------------------------------------------------------------------------

local ngx = ngx
local ngx_req = ngx.req

local M = {}

function M.access()
    local client_ip = ngx.var.remote_addr
    local raw_request = ngx_req.raw_header()
    local analysis, err = protection:remote_analyze(client_ip, raw_request)

    if analysis then
        local action = analysis.action or ""
        ngx.log(ngx.INFO, "Action: " .. action)

        if action == "block" then
            local out = "You were blocked with action: " .. action .. "\n"
            ngx.status = ngx.HTTP_FORBIDDEN
            ngx.header.content_type = 'text/html'
            ngx.header["Content-Length"] = out:len()
            ngx.print(out)
            ngx.exit(ngx.HTTP_FORBIDDEN)
        end
    else
        ngx.log(ngx.ERR, "Error: " .. (err or "unknown error"))
        -- If there is a error reaching Distil the safe action is to fail open.
    end
end

return M
