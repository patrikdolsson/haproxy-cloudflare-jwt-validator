--
-- JWT Validation implementation for HAProxy Lua host
-- This script is a heavily modified version of the following: https://github.com/haproxytech/haproxy-lua-jwt
-- 2020-05-21 - Bojan Zelic - Enabled support for JWKS urls, custom headers, multiple audience tokens
-- Copyright (c) 2019. Adis Nezirovic <anezirovic@haproxy.com>
-- Copyright (c) 2019. Baptiste Assmann <bassmann@haproxy.com>
-- Copyright (c) 2019. Nick Ramirez <nramirez@haproxy.com>
-- Copyright (c) 2019. HAProxy Technologies LLC
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--    http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
-- Use HAProxy 'lua-load' to load optional configuration file which
-- should contain config table.
-- Default/fallback config
if not config then
    config = {
        publicKeys = {
            keys = {},
            expiresIn = 1000 -- 1 second
        },
        max_cache = 24 * 60 * 60, -- 24 hours
        issuer = nil,
        jwks_url = nil
    }
end

local json   = require 'json'
local base64 = require 'base64'
local http   = require 'http'

local openssl = {
    pkey = require 'openssl.pkey',
    digest = require 'openssl.digest',
    x509 = require 'openssl.x509'
}

local function log_alert(msg)
    core.Alert("jwtverify.lua: <alert> - "..tostring(msg))
end

local function log_info(msg)
    core.Info("jwtverify.lua: <info> - "..tostring(msg))
end

local function log_debug(msg)
    core.Debug("jwtverify.lua: <debug> - "..tostring(msg))
end

local function log_notice(msg)
    core.log(core.notice, "jwtverify.lua: <notice> - "..tostring(msg))
end

local function dump(o)
    if type(o) == 'table' then
        local s = '{ '
        for k,v in pairs(o) do
            if type(k) ~= 'number' then k = '"'..k..'"' end
            s = s .. '['..k..'] = ' .. dump(v) .. ','
        end
        return s .. '} '
    else
        return tostring(o)
    end
end

local function decodeJwt(authorizationHeader)
    local headerFields = core.tokenize(authorizationHeader, " .")

    if #headerFields ~= 3 then
        log_debug("Improperly formated Authorization header. Should be followed by 3 token sections.")
        return nil
    end

    local token = {}
    token.header = headerFields[1]
    token.headerdecoded = json.decode(base64.decode(token.header))

    token.payload = headerFields[2]
    token.payloaddecoded = json.decode(base64.decode(token.payload))

    token.signature = headerFields[3]
    token.signaturedecoded = base64.decode(token.signature)

    log_debug('Authorization header: ' .. authorizationHeader)
    log_debug('Decoded JWT header: ' .. dump(token.headerdecoded))
    log_debug('Decoded JWT payload: ' .. dump(token.payloaddecoded))

    return token
end

local function algorithmIsValid(token)
    if token.headerdecoded.alg == nil then
        log_debug("No 'alg' provided in JWT header.")
        return false
    elseif token.headerdecoded.alg ~= 'RS256' then
        log_debug("RS256 supported. Incorrect alg in JWT: " .. token.headerdecoded.alg)
        return false
    end

    return true
end

local function signatureIsValid(token, publicKey)
    local digest = openssl.digest.new('SHA256')
    digest:update(token.header .. '.' .. token.payload)

    local isVerified = publicKey:verify(token.signaturedecoded, digest)
    return isVerified
end

local function has_value (tab, val)
    if tab == val then
        return true
    end

    for _, value in ipairs(tab) do
        if value == val then
            return true
        end
    end

    return false
end

local function expirationIsValid(token)
    return os.difftime(token.payloaddecoded.exp, core.now().sec) > 0
end

local function issuerIsValid(token, expectedIssuer)
    return token.payloaddecoded.iss == expectedIssuer
end

local function audienceIsValid(token, expectedAudience)
    -- audience is sometimes stored as an array of strings
    -- sometimes it's stored as a string
    return has_value(token.payloaddecoded.aud, expectedAudience)
end

local function execute_shell_command(command)
    local exit_code = os.execute(command)
    if exit_code == 0 then
        core.log(core.LOG_INFO, "Command executed successfully: " .. command)
        return true
    else
        core.log(core.LOG_ALERT, "Command failed: " .. command .. " (Exit code: " .. exit_code .. ")")
        return false
    end
end



-- This function loads the JSON from our JWKS url. However because we cannot do DNS lookups in haproxy, We have to
-- use the IP address directly. We depend on a backend that's set in order for Haproxy to resolve an IP address
-- for the JWKS url.
-- If there are any errors (ex: if cloudflare endpoint is down... then we will rely on the last-used public key
-- local function getJwksData(url)
--     --check for existence of public keys

--     local publicKeys = {}
--     local expiresIn = 60 * 60 -- 1 hour default

--     local be = string.gsub(string.match(url, '|.*|'), '|', '')
--     local addr
--     local server_name
--     for name, server in pairs(core.backends[be].servers) do
--         local status = server:get_stats()['status']
--         if status == "no check" or status:find("UP") == 1 then
--             addr = server:get_addr()
--             server_name = name
--             log_info("addr: '" .. addr .. "'")
--             log_info("server_name: '" .. server_name .. "'")
--             break
--         end
--     end
--     log_info("final addr: '" .. tostring(addr) .. "'")
--     log_info("final server_name: '" .. tostring(server_name) .. "'")

--     if addr == nil or addr == '<unknown>' then
--         log_info("No servers available for auth-request backend: '" .. be .. "'")
--         return {
--             keys = config.publicKeys.keys,
--             expiresIn = 1 -- 1 second
--         }
--     end

--     local ip_url = string.gsub(url, '|'..be..'|', addr)
--     local domain_url = string.gsub(url, '|'..be..'|', server_name)

--     log_info('Retrieving JWKS Public Key Data from: ' .. domain_url)
--     -- Example: Fetch JWKS using curl (as in the previous example)
--     local success = execute_shell_command("curl -H \"Host: " .. server_name .. "\" \"" .. domain_url .. "\" > /tmp/jwks.json")

--     local jwks, err
--     if success then
--         local file = io.open("/tmp/jwks.json", "r")
--         if not file then
--             log_info("Failed to open JWKS file")
--             return nil
--         end

--         local content = file:read("*a")
--         file:close()
--         jwks, err = json.decode(content)
--         if not jwks then
--             log_alert("Failed to parse JWKS JSON: " .. err)
--             return nil
--         end

--         if is_cached then
--             return {
--                 keys = config.publicKeys.keys,
--                 expiresIn = 60 -- 60 second
--             }
--         end
--     end

--     -- local http_headers = {Host = server_name}

--     -- if config.jwks_proxy then
--     --     ip_url = config.jwks_proxy
--     --     http_headers = nil
--     -- end

--     -- log_info('Retrieving JWKS Public Key Data from: ' .. ip_url)
--     -- log_info('Retrieving JWKS Public Key Data from: ' .. domain_url)

--     -- local response, err = http.get{url=ip_url} --, headers={Host = server_name}}
--     -- local httpclient = core.httpclient()
--     -- local response, err = httpclient:get{url=ip_url, headers={Host=server_name}}
--     -- local response, err = http.get{url=domain_url}

--     -- if not response then
--     --     log_alert(err)
--     --     return {
--     --         keys = config.publicKeys.keys,
--     --         expiresIn = 1 -- 1 second
--     --     }
--     -- end
--     -- for key, value in pairs(response) do
--     --     log_info(tostring(key) .. ": " .. tostring(value))
--     -- end

--     -- if response.status_code ~= 200 then
--     --     log_info("JWKS data is not available.")
--     --     log_info("status_code: " .. response.status_code or "<none>")
--     --     log_info("body: " .. dump(response.content) or "<none>")
--     --     log_info("headers: " .. dump(response.headers) or "<none>")
--     --     log_info("reason: " .. response.reason or "<none>")

--     --     -- return already set publicKeys if already set
--         -- if is_cached then
--         --     return {
--         --         keys = config.publicKeys.keys,
--         --         expiresIn = 60 -- 60 second
--         --     }
--         -- end

--     --     log_alert("JWKS data is not available")
--     -- end

--     -- local JWKS_response = json.decode(response.content)
--     local JWKS_response = jwks

--     for _,v in pairs(JWKS_response.public_certs) do
--         table.insert(publicKeys,openssl.x509.new(v.cert):getPublicKey())
--         log_info("Public Key Cached: " .. v.kid)
--     end

--     local max_age

--     if response.headers['cache-control'] then
--         local has_max_age = string.match(response.headers['cache-control'], "max%-age=%d+")
--         if has_max_age then
--             max_age = tonumber(string.gsub(has_max_age, 'max%-age=', ''), 10)
--         end
--     end

--     if max_age then
--         expiresIn = math.min(max_age, config.max_cache)
--     else
--         log_info('cache-control headers not able to be retrieved from JWKS endpoint')
--     end

--     return {
--         keys = publicKeys,
--         expiresIn = expiresIn
--     }

-- end

local function getJwksData(url, host)
    local publicKeys = {}
    local expiresIn = 60 * 60 -- 1 hour default

    -- local cmd = string.format('curl -H "Host: %s" "%s" > /tmp/jwks.json', host, url) -- Construct the curl command
    -- local os_execute_response = os.execute('curl "' .. url .. '" -H "Accept: application/json" > /tmp/jwks.json')
    -- local file = io.open("/tmp/jwks.json", "r")
    -- log_info("os.execute response: " .. tostring(os_execute_response))
    -- if not file then
    --     log_alert("No file found at /tmp/jwks.json")
    --     file:close()
    --     return {keys = config.publicKeys.keys, expiresIn = 1} -- Fallback
    -- end

    -- if exit_code ~= 0 then
    --     log_alert("Failed to execute curl: " .. tostring(exit_code))
    --     file:close()
    --     return {keys = config.publicKeys.keys, expiresIn = 1} -- Fallback
    -- end

    -- local content = file:read("*a")
    -- file:close()


    local handle = io.popen('curl "' .. url .. '" -H "Accept: application/json" > /tmp/jwks.json')
    local content = handle:read("*a")
    handle:close()

    local JWKS_response, err = json.decode(content)
    if not JWKS_response then
        log_alert("Failed to decode JWKS JSON: " .. (err or "unknown error"))
        return {keys = config.publicKeys.keys, expiresIn = 1} -- Fallback
    end

    for _,v in pairs(JWKS_response.keys or JWKS_response.public_certs or {}) do -- Handle different JWKS formats
        local cert = v.x5c and v.x5c[1] or v.cert
        if cert then
            local x509_obj, err = openssl.x509.new(cert)
            if x509_obj then
                table.insert(publicKeys, x509_obj:getPublicKey())
                log_info("Public Key Cached: " .. (v.kid or "no kid"))
            else
                log_alert("Failed to parse cert: " .. (err or "unknown error"))
            end
        end
    end

    -- Extract cache control
    local cache_control_header = string.match(content, "Cache-Control: ([^\r\n]+)")
    if cache_control_header then
        local max_age_match = string.match(cache_control_header, "max-age=(%d+)")
        if max_age_match then
            expiresIn = math.min(tonumber(max_age_match), config.max_cache)
        end
    end

    return {keys = publicKeys, expiresIn = expiresIn}
end

function jwtverify(txn)

    local issuer = config.issuer
    local audience = txn.get_var(txn, 'txn.audience')
    local signature_valid = false

    -- 1. Decode and parse the JWT
    local token = decodeJwt(txn.sf:req_hdr("cf-access-jwt-assertion"))
    if token == nil then
        log_debug("Token could not be decoded.")
        goto out
    end

    -- 2. Verify the signature algorithm is supported (RS256)
    if algorithmIsValid(token) == false then
        log_debug("Algorithm not valid.")
        goto out
    end

    -- 3. Verify the signature with the certificate
    for k,pem in pairs(config.publicKeys.keys) do
        signature_valid = signature_valid or signatureIsValid(token, pem)
    end

    if signature_valid == false then
        log_debug("Signature not valid.")

        if not signature_valid then
            goto out
        end
    end

    -- 4. Verify that the token is not expired
    if expirationIsValid(token) == false then
        log_info("Token is expired.")
        goto out
    end

    -- 5. Verify the issuer
    if issuer ~= nil and issuerIsValid(token, issuer) == false then
        log_info("Issuer not valid.")
        goto out
    end

    -- 6. Verify the audience
    if audience ~= nil and audienceIsValid(token, audience) == false then
        log_info("Audience not valid.")
        goto out
    end

    -- 7. Add custom values from payload to variable
    if token.payloaddecoded.custom ~= nil then
        for name, payload in pairs(token.payloaddecoded.custom) do
            local clean_name = name:gsub("%W","_")
            local clean_value = payload
            if (type(payload) == 'table') then
                clean_value = table.concat(payload, ',')
            end

            txn.set_var(txn, "txn."..clean_name, clean_value)
            log_debug("txn."..clean_name.." is defined from payload")
        end
    end

    -- 8. Set authorized variable
    log_debug("req.authorized = true")
    txn.set_var(txn, "txn.authorized", true)

    -- exit
    do return end

    ::out::
    log_debug("req.authorized = false")
    txn.set_var(txn, "txn.authorized", false)
end

-- This function runs in the background similarly to a cronjob
-- On a high level it tries to get the public key from our jwks url
-- based on an interval. The interval we use is based on the cache headers as part of the JWKS response
function refresh_jwks()
    log_info("Refresh JWKS task initialized")
    while true do
        log_info('Refreshing JWKS data')
        local status, publicKeys = xpcall(getJwksData, debug.traceback, config.jwks_url, config.host) -- Pass the host
        if status then
            config.publicKeys = publicKeys
        else
            local err = publicKeys
            log_alert("Unable to set public keys: "..tostring(err))
        end

        log_info('Getting new Certificate in '..(config.publicKeys.expiresIn)..' seconds - '
            ..os.date('%c', os.time() + config.publicKeys.expiresIn))
        core.sleep(config.publicKeys.expiresIn)
    end
end

-- Called after the configuration is parsed.
-- Loads the OAuth public key for validating the JWT signature.
core.register_init(function()
    config.issuer = os.getenv("OAUTH_ISSUER")
    config.jwks_url = os.getenv("OAUTH_JWKS_URL")
    config.host = os.getenv("OAUTH_HOST")
    log_info("JWKS URL: " .. (config.jwks_url or "<none>"))
    log_info("Issuer: " .. (config.issuer or "<none>"))
    log_info("Host: " .. (config.host or "<none>"))
end)

-- Called on a request.
core.register_action('jwtverify', {'http-req'}, jwtverify, 0)

-- Task is similar to a cronjob
core.register_task(refresh_jwks)
