# firewall-manager
Universal iptables script to simplify firewall setup

## Extras
The `extras` array in the config holds custom rules beyond the built-in `ssh`, `http` and `https` entries. Each item is either a raw string or an object.

### Raw strings
A string is treated as a ready-made command and appended to the command list as-is, unless an identical command is already in the list.
```json
"extras": [
    "iptables -A INPUT -p icmp -j ACCEPT"
]
```

### Objects
An object describes a single port rule. Keys are matched case-insensitively.
```json
"extras": [
    {
        "enabled": true,
        "protocol": "tcp",
        "port": 25565,
        "policy": "filter_by_ipset",
        "ipset_v4": {
            "name": "mc_allowed_v4",
            "list": ["203.0.113.10", "198.51.100.0/24"]
        },
        "ipset_v6": {
            "name": "mc_allowed_v6",
            "list": ["2001:db8::/32"]
        }
    }
]
```

| Field | Type | Description |
|---|---|---|
| `enabled` | bool | Whether the rule is active |
| `protocol` | string | Protocol for the rule (e.g. `tcp`, `udp`) |
| `port` | int | Port the rule applies to |
| `policy` | string | How traffic to the port is handled |
| `ipset_v4` | object | `name` and `list` of IPv4 addresses/ranges, used by `filter_by_ipset` |
| `ipset_v6` | object | `name` and `list` of IPv6 addresses/ranges, used by `filter_by_ipset` |

Note that the object form of `ipset_v4`/`ipset_v6` (with `name` and `list`) differs from the empty-array placeholders in the built-in `ssh`/`http`/`https` entries.

### How objects are processed

**`policy: "filter_by_ipset"`**

1. An IPv4 ipset is created with `ipset_v4.name`, and each entry in `ipset_v4.list` is added to it.
2. An IPv6 ipset is created with `ipset_v6.name`, and each entry in `ipset_v6.list` is added to it.
3. The ipset create/add commands are queued into the ipset command list.
4. One iptables rule is generated for IPv4 and one for IPv6, both referencing the matching ipset by name, and appended unless they already exist.

## Preservation
Docker and Kubernetes firewall rules are preserved, make sure your NAT bridges don't expose anything to the public internet that shouldn't be.

Check what's exposed before you rely on this:

```sh
# containers publishing ports on all interfaces
docker ps --format '{{.Names}}\t{{.Ports}}' | grep '0.0.0.0'

# what's actually listening on the host
ss -tlnp | grep -E '0\.0\.0\.0|\[::\]'

# the NAT rules Docker created
iptables -t nat -L DOCKER -n -v
```

To keep a port private, bind it to localhost (`-p 127.0.0.1:8080:80`) instead of publishing it on all interfaces.

## Fallbacks
If fetching IP lists from Bunny or Cloudflare fails, it falls back to JSONs hosted on [https://cdn.perosofic.dev](https://cdn.perosofic.dev) (backed by Cloudflare S3). Failures are rare, though the fallback data can be stale.

## Requirements
- iptables
- ipset
- grep
