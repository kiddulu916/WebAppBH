CF_HEADERS = {
    "Server": "cloudflare",
    "X-Powered-By": "Express",
    "Set-Cookie": "__cf_bm=abc; path=/",
    "CF-RAY": "abc123-DFW",
    "Content-Type": "text/html",
}
CF_404_BODY = "<html>Cloudflare error... ray id abc123</html>"
TLSX_OUT = '{"host":"api.acme.com","ja3s_hash":"e7d705","tls_version":"tls13","issuer_cn":"Cloudflare Inc","subject_an":["*.acme.com"],"alpn":["h2","http/1.1"]}'
WAFW00F_OUT = '{"detected":true,"firewall":"Cloudflare"}'
HTTPX_OUT = "\n".join([
    '{"url":"https://api.acme.com:443","port":"443","status_code":200,"tech":[]}',
    '{"url":"http://api.acme.com:80","port":"80","status_code":301,"tech":[]}',
])
WHATWEB_OUT = '[{"target":"https://api.acme.com","plugins":{"Cloudflare":{}}}]'
