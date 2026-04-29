# infoblox for [`libdns`](https://github.com/libdns/libdns)

This package implements the [libdns interfaces](https://github.com/libdns/libdns)
for [infoblox](https://www.infoblox.com), allowing you to manage DNS records.

## Authenticating
The following parameters are used to authenticate with the Infoblox API:
* `Host` - The hostname of the Infoblox server, e.g. `infoblox.example.com`
* `Version` - The version of the Infoblox API, e.g. `2.9.7`
* `Username` - The username to authenticate with
* `Password` - The password to authenticate with
* `View` - The view to interact with

## Logging
This library supports Caddy-compatible logging via `go.uber.org/zap`. To enable logging, call `SetLogger()` on the provider instance with a zap logger. If no logger is set, logging is silently disabled.

```go
provider := &infoblox.Provider{
    Host:     "infoblox.example.com",
    Version:  "2.9.7",
    Username: "admin",
    Password: "password",
    View:     "default",
}
provider.SetLogger(logger) // Pass your zap.Logger instance
```

## Supported Record Types
I'm really only using this for ACME DNS-01 challenges, so only `TXT` and `CNAME` records are supported. Feel free to open a PR to add more record types.
