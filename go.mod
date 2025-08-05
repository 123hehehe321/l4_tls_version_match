module github.com/123hehehe321/l4_tls_version_match

go 1.20

require (
    github.com/caddyserver/caddy/v2 v2.10.0
    github.com/mholt/caddy-l4 v0.0.0-20250530154005-4d3c80e89c5f
)

replace github.com/mholt/caddy-l4 => ../caddy-l4
