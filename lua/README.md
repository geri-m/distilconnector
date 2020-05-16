Distil Integration Example for Openresty
=========================================

This is a template for a Openresty based integration with Distil Networks
Connector. Version 0.4

Installation
------------

Independent of how you deploy nginx, you will need to:

 * Open `lua/init.lua`, and look for the `SETTINGS` object. Replace the
   credentials with the ones assigned to you. They can be found in the Distil
   portal.
 * In the same location, set the `challenge_path` to some inconspicuous value.
   This is the path that will be used to load the Distil javascript. The
   objective is to make it hard to find for adblockers and adversaries.

In your nginx server config, you'll need to add a proxy directive for the
challenge path. This typically looks as follows:

```
location /6657193977244c13 {
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_pass http://YOUR-HOST.distil.ninja/v6/challenge/YOUR-API-KEY-ID$request_uri;
}
```

Make sure to use the same path as you configured for `challenge_path` in
`init.lua`.

You are now ready to update your nginx configuration to enable Distil
protection. Refer to `conf.d/default.conf` for an example. Pay particular
attention to the `access_by_lua` block within the `location` block, which
is what invokes the integration code, and to the `location` block which
handles the proxying of the javascript challenge.

This distribution includes Dockerfiles which demonstrates how to deploy the
integration, and to which you can refer to see the steps needed, even if you
use some other mode of deployment.

Native encryption library
-------------------------

The native encryption library has been built and tested on ubuntu. If you are
running on some other platform, talk to your Distil contact person about
building the library for your platform.

Failure handling
----------------

The code is written to ensure that no failure will inadvertantly prevent an
end user from reaching the origin. If the code is modified, care should be
taken to preserve this property.

The integration contains a built in circuit breaker. After a succession of
failures, it will stop performing calls to Distil. The circuit breaker ensures
that any disruption of the Distil edge won't affect the availability of your
service.

Challenge Javascript
--------------------

You will need to embed a script tag in the HTML of your site. The source of
this script should be set to the `challenge_path`, as configured in your
`init.lua`. For the default value `/6657193977244c13`, the tag looks as
follows:

```html
<script type="text/javascript" src="/6657193977244c13" async></script>
```

Cryptography library
--------------------

Certain cryptographic features are not available in Openresty or native lua
and has been implemented as a shared library. If the supplied binary is
incompatible with your system or architecture, contact Distil support.
