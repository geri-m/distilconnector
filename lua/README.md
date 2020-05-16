Imperva Connector Integration Example for OpenResty
=========================================

This is a template for a Openresty based integration with Imperva Connector.

Version 0.6 (2020-05-14)

Dependencies
------------
- NGINX with Lua module using LuaJIT
	- *Note:* This is the default [OpenResty](http://openresty.org/) configuration
- [`lua-cjson`](https://github.com/openresty/lua-cjson) >= 2.1.0.6
	- *Note:* `lua-cjson` is bundled with [OpenResty](http://openresty.org/)
- [`lua-resty-string`](https://github.com/openresty/lua-resty-string) >= 0.08
	- *Note:* `lua-resty-string` is bundled with [OpenResty](http://openresty.org/)
- [`lua-resty-http`](https://github.com/ledgetech/lua-resty-http)=0.14`
	- Available via `opm`: `opm install ledgetech/lua-resty-http=0.14`
- [`lua-resty-hmac`](https://github.com/jkeys089/lua-resty-hmac) =0.03
	- Available via `opm`: `opm install jkeys089/lua-resty-hmac=0.03`
- [`lua-zlib`](https://github.com/brimworks/lua-zlib) =1.2-0
	- Available via `luarocks`: `luarocks install lua-zlib 1.2-0`

Installation
------------

### Installing Connector Lua modules

The first step in installing the Imperva Connector is to ensure that the necessary Lua files are properly placed. The contents to the `lua/` folder in this package needs to be moved to a folder named `distil/` within your Lua package path.

In a default OpenResty configuration this can be done with the following steps:
```
$ mkdir -p /usr/local/openresty/site/lualib/distil
$ cp lua/* /usr/local/openresty/site/lualib/distil/
```

If you are unsure of your Lua package path, it's often available via the environment value `LUA_PATH` or, from within NGINX and Lua, by printing `package.path`. Alternatively, if you attempt calling a Lua package no in the package path, you will see a full list of searched paths in the NGINX error log.

Please make note of the path you've copied the files to, as it will be needed later.

### Update Settings

Open the `lua/init.lua` file and find the `SETTINGS` object on/around line 114. Values in this Lua table will be
populated with information from your Distil/Imperva Advanced Bot Protection portal.

JSON Configuration from Distil/Imperva Advanced Bot Protection portal:
```
{
    analysisHost: "http://bonproxy",
    apiKeyId: "debug-id",
    apiSecretKey: "password",
    debugHeaderValue: "debug-me",
    tokenEncryptionKey: "debug012345678901234567890123456789"
}
```
converted to Lua `SETTINGS` table:
```
local SETTINGS = {
    analysis_host = "bonproxy"; -- Note: This is the portion following the http:// or https://
    analysis_host_port = 80; -- Note: If the JSON analysisHost is http:// set to 80; https:// to 443
    api_key_id = "debug-id";
    api_secret_key = "password";
    debug_header_value = "debug-me";
    token_encryption_key = "debug012345678901234567890123456789";
    integration_type = "openresty";
    challenge_path = "/6657193977244c13";
}
```

The `integration_type` value should be left as `openresty` and `challenge_path` is covered below.

### NGINX Configuration Changes

#### Challenge Paths

As part of the the integration, you'll need to include a snippet of JavaScript on all Connector protected pages. The path of the JavaScript is dependent on the `SETTINGS.challenge_path` value shown above and should always begin with a `/`. This value should be set to an inconspicuous value unique to your website. The objective is to set a path that is hard to find both for ad blockers and adversaries. For example:
```
local SETTINGS = {
	...snip...
	challenge_path = "/6657193977244c13";	
}
```

After updating the `challenge_path` key, you'll need to create an NGINX `location` path designed to forward JavaScript requests to Imperva. With the `server` block of your NGINX configuration, please add the `location` block:
```
location /6657193977244c13 {
   proxy_set_header Host $host;
   proxy_set_header X-Forwarded-For $remote_addr;
   proxy_pass http://bonproxy/v6/challenge/debug-id$request_uri;
}
```
- The `location /6657193977244c13` is determined by the value in `challenge_path` above.
- The `http://bonproxy` should be replaced with the `analysisHost` from the Distil/Imperva portal.
- The `debug-id` should be replaced with the `apiKeyId` from the Distil/Imperva portal.

Once you have selected a path and created the necessary NGINX `location` block, you can add the following JavaScript snippet to all pages:
```
<script type="text/javascript" src="/6657193977244c13"></script>
```

#### Interstitial Page Installation

When selected, the OpenResty Connector integration is designed to show an interstitial page to bots. This page can be customized per deployment and is originally found as `interstitial.html` within the `lua/` directory. After making any changes, you'll want to place the HTML page alongside the Lua packages installed in the `distil/` folder from earlier.

Note: Within the interstitial page you'll see a number of fields surrounded by the `{{` and `}}` characters. These are template strings for the integration and should remain in the page.

#### Protect Traffic

After completing the SETTINGS table and integrating the Challenge Path and JavaScript, you're ready to enable Imperva protection. This is done by adding an `access_by_lua_block` block within your main NGINX configuration `location` block.

```
[location block] {
	# Set $template_path to the location of the interstitial.html you created earlier
	set $template_path '/usr/local/openresty/site/lualib/distil';

	# Access_by_lua_block calls the Imperva Connector Integration
	access_by_lua_block {
		local distil = require "distil";
		distil.access()
	}
}
```
Note: This code should be integrated with any *existing* default location block you currently maintain. Completely replacing your default `location` with only the lines above may cause traffic interruption. 

Additional integration examples can be found in the `conf.d/` folder.

This distribution also includes Dockerfiles which demonstrates how to deploy the integration, and to which you can refer to see the steps needed, even if you use some other mode of deployment.

Failure handling
----------------

The code is written to ensure that no failure will inadvertantly prevent an
end user from reaching the origin. If the code is modified, care should be
taken to preserve this property.

The integration contains a built in circuit breaker. After a succession of
failures, it will stop performing calls to Distil. The circuit breaker ensures
that any disruption of the Distil edge won't affect the availability of your
service.
