local status, json = pcall(require, "cjson.safe")
local json_functions = {
    decode = nil;
    encode = nil;
    null = nil;
}
if not status then
    ngx.log(ngx.INFO, "cjson is not available. Attempting to load lua-json instead")
    json = require "json"
    json_functions = {
        decode = json.decode;
        encode = json.encode;
        null = json.util.null;
    }
else
    json_functions = {
        decode = json.decode;
        encode = json.encode;
        null = json.null;
    }
end

local http = require "resty.http"

local distil = require "distil.distil"

local crypto = require "distil.crypto"

local function readall(filename)
    local fh, err = io.open(filename, "rb")
    if fh == nil then
        return nil, err
    end

    local contents, err = fh:read("*a") -- "a" in Lua 5.3; "*a" in Lua 5.1 and 5.2
    if contents == nil then
        return nil, err
    end

    fh:close()

    return contents, nil
end

local template_path = ngx.var.template_path .. "/interstitial.html"
ngx.log(ngx.INFO, "Loading template from " .. template_path)

local interstitial_template, err = readall(template_path)
if interstitial_template == nil then
    ngx.log(ngx.ERR, "Failed to load interstitial: " .. err)
end

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

    if port == 443 then
        local ok, err = connection:ssl_handshake(nil, host, false)
        if not ok then
            return nil, "ssl_handshake():" .. err
        end
    end

    local res, err = connection:request(request)

    if not res then
        return nil, "request(): " .. err
    end

    local body, err = res:read_body()
    if not body then
        return nil, err or "Error in read_body"
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
    debug_header_value = "debug-me";
    token_encryption_key = "debug012345678901234567890123456789";
    integration_type = "openresty";
    challenge_path = "/6657193977244c13";
}

-- Functions needed by the Distil library.
local LIBS = {
    -- request = { method: string, path: string, headers: table, body: string }
    -- function(host, port, request) -> status_code, body
    fetch = fetch;

    -- function(string) -> table
    json_decode = json_functions.decode;

    -- function(table) -> string
    json_encode = json_functions.encode;

    -- What does the json library use to represent null values?
    json_null = json_functions.null;

    -- How do we decrypt arbitrary data?
    encrypt = crypto and crypto.encrypt;
    decrypt = crypto and crypto.decrypt;
}

local protection = distil.Protection:new(SETTINGS, LIBS)

-------------------------------------------------------------------------------

local function render_response(content, status)
    ngx.status = status
    ngx.header["Content-Type"] = "text/html; charset=UTF-8"
    ngx.header["Cache-Control"] = "no-cache, no-store, must-revalidate"
    ngx.header["Pragma"] = "no-cache"
    ngx.header["Expires"] = "0"
    ngx.header["Content-Length"] = content:len()
    ngx.print(content)
    ngx.exit(status)
end

local function block()
    local interstitial_data = {
        bon_path = SETTINGS.challenge_path;
        head = "<script>window.addEventListener('load', showBlockPage)</script>";
        body = "";
        body_explanation = "";
    }

    local body = protection:render_interstitial(interstitial_template, interstitial_data)

    render_response(body, ngx.HTTP_FORBIDDEN)
end

-------------------------------------------------------------------------------

local ngx = ngx
local ngx_req = ngx.req

local function get_cookies_as_table(headers)
    return distil.cookie_table(headers["Cookie"] or headers["cookie"])
end

local function check_resubmission(method, headers, cookies)
    if method ~= "POST" then
        return nil, nil
    end

    local resubmit_token = cookies["reese84-resubmit-token"]
    if resubmit_token == nil then
        return nil, nil
    end

    ngx_req.read_body()
    local form_fields = ngx_req.get_post_args()

    local resubmit_data = form_fields["reese84-resubmit-data"]
    if resubmit_data == nil then
        return nil, nil
    end

    return protection:decrypt_resubmitted_data(resubmit_token, resubmit_data)
end

local M = {}

function M.access()
    local method = ngx_req.get_method()
    local client_ip = ngx.var.remote_addr
    local headers = ngx_req.get_headers()
    local raw_request = distil.mask_raw_headers(ngx_req.raw_header())
    local cookies = get_cookies_as_table(headers)

    for name, value in pairs(headers) do
        if type(value) == "table" then
            local did_mask = false
            for i, v in ipairs(value) do
                value[i] = distil.mask_header(name, v)
                did_mask = did_mask or value[i] ~= v
            end
            if did_mask then
                headers[name] = value
            end
        else
            local newValue = distil.mask_header(name, value)
            if value ~= newValue then
                headers[name] = newValue
            end
        end
    end

    -- It is useful to be able to trigger a block easily in order to verify
    -- that the integration is active. This is especially true since the
    -- error handling behavior is to fail open, which means that it can be
    -- difficult to establish that the integration is active in the presence
    -- of errors. This block can be safely removed if it is undesirable.
    local x_block_me = headers["X-Block-Me"]
    if x_block_me ~= nil then
        block()
        return
    end

    -- Check for encrypted POST data that should be decrypted
    local resubmit_data, err = check_resubmission(method, headers, cookies)
    if resubmit_data ~= nil then
        ngx_req.set_body_data(resubmit_data)
    elseif err ~= nil then
        ngx.log(ngx.ERR, "Error processing resubmission: " .. err)
        render_response("Invalid data\n", 422)
        return
    end

    -- Ask the Distil edge to analyze the request
    local analysis, err = protection:remote_analyze(client_ip, raw_request)
    if err ~= nil then
        ngx.log(ngx.ERR, "Remote analysis error: " .. err)

        -- As a fallback, attempt to extract the information available in the
        -- token. This is less effective than making the remote analysis, as
        -- it only contains certain information that was available when the
        -- token was acquired. For each remote analysis call, more state about
        -- each client is accumulated, and the action may change as a result.
        analysis, err = protection:extract_analysis_from_token(cookies)
        if err ~= nil then
            ngx.log(ngx.ERR, "Local analysis error: " .. err)
        end
    end

    if analysis then

        -- Debug override: rather than proxying the request to the origin,
        -- return some debugging info. This can be removed if it is
        -- problematic for security purposes.
        local x_distil_debug = headers["X-Distil-Debug"]
        if x_distil_debug == SETTINGS.debug_header_value then

            local debug_response = {
                analysis = analysis;
                integration_info = protection:_integration_info();
            }

            local out = json.encode(debug_response) .. "\n"
            ngx.status = ngx.HTTP_SERVICE_UNAVAILABLE
            ngx.header.content_type = 'text/html'
            ngx.header["Content-Length"] = out:len()
            ngx.header["Content-Type"] = "application/json"
            ngx.print(out)
            ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
        end

        local action = analysis.action or ""

        if action == "block" then
            block()
        elseif action == "identify" or action == "captcha" then

            -- Load the form data of the present request, if it is a POST
            -- request, as we will encrypt it and embed it in the interstitial.
            local formdata = nil
            if method == "POST" then
                ngx_req.read_body()
                formdata = ngx.req.get_body_data()
            end

            local interstitial_request = {
                method = method;
                headers = headers;
                client_ip = client_ip;
                formdata = formdata;
            }

            local interstitial, err = protection:fetch_interstitial(analysis, interstitial_request, interstitial_template)
            if interstitial == nil then
                ngx.log(ngx.ERR, "Failed to retrieve interstitial: " .. err)
                return
            end

            if interstitial.cookie ~= nil then
                ngx.header['Set-Cookie'] = interstitial.cookie
            end

            render_response(interstitial.content, interstitial.status)
        end
        if action then
            ngx.req.set_header('x-d-action', action)
        end
        if #analysis.tags > 0 then
            ngx.req.set_header('x-d-tags', table.concat(analysis.tags, ","))
        end
    else
        ngx.log(ngx.ERR, "Error: " .. (err or "unknown error"))
        -- If there is a error reaching Distil the safe action is to fail open.
    end
end

function M.mask_headers()
    local ngx_req = ngx.req
    local headers = ngx_req.get_headers()

    for name, value in pairs(headers) do
        if type(value) == "table" then
            local did_mask = false
            for i, v in ipairs(value) do
                value[i] = distil.mask_header(name, v)
                did_mask = did_mask or value[i] ~= v
            end
            if did_mask then
                ngx_req.set_header(name, value)
            end
        else
            local newValue = distil.mask_header(name, value)
            if value ~= newValue then
                ngx_req.set_header(name, newValue)
            end
        end
    end
end

return M
