# Java Implementation of the Distil Connector

Documentation on [Distil Connector](https://docs.distilconnector.com/) on the official site.

This implementation is based on the OpenRestly/Lua implementation given.

## Set your Credentials

We set the credentials as environment variables. You can do this on your local machine via

```
nano ~/.bash_profile
```

and add these lines to your config

```
export analysis_host="bonproxy"
export analysis_host_port=80
export api_key_id="debug-id"
export api_secret_key="password"
```

Environment variables are a comfortable way to keep parameters for running application in Containers
as well as during CI. 