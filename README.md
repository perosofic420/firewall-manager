# firewall-manager
Universal iptables script to simplify firewall setup

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
