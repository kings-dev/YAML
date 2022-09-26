#!/bin/bash
#!/bin/bash/env bash
set fileformat=unix
name=`echo $(basename $0)`
sed -i 's/\r$//' $name
# 主题：Zeever
yum -y install yum-utils ntp ntpdate
ntpdate pool.ntp.org
rpm --import http://mirrors.163.com/centos/RPM-GPG-KEY-CentOS-7
#curl -O -L 'https://bootstrap.pypa.io/pip/2.7/get-pip.py'
yum-config-manager --add-repo http://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo
curl -sSL https://get.docker.com/ | CHANNEL=stable sh
systemctl enable docker.service
curl -L https://get.daocloud.io/docker/compose/releases/download/v$(curl -Ls https://www.servercow.de/docker-compose/latest.php)/docker-compose-$(uname -s)-$(uname -m) > /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
docker-compose --version
#UA检测
#https://useragent.buyaocha.com/
#
#Chrome
#Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36
#
#MSIE
#Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko
#
#Microsoft Edge
#Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.53
#
#chedot
#Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.81 Safari/537.36
#
#Firefox
#Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0
#
#wget https://bootstrap.pypa.io/pip/2.7/get-pip.py --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.53"
#python get-pip.py
#Successfully installed PyYAML-5.4.1 attrs-21.4.0 backports.shutil-get-terminal-size-1.0.0 backports.ssl-match-hostname-3.7.0.1 bcrypt-3.1.7 cached-property-1.5.2 certifi-2021.10.8 cffi-1.15.1 chardet-4.0.0 configparser-4.0.2 contextlib2-0.6.0.post1 cryptography-3.3.2 distro-1.6.0 docker-4.4.4 docker-compose-1.26.2 dockerpty-0.4.1 docopt-0.6.2 enum34-1.1.10 functools32-3.2.3.post2 idna-2.10 importlib-metadata-2.1.3 ipaddress-1.0.23 jsonschema-3.2.0 paramiko-2.11.0 pathlib2-2.3.7.post1 pycparser-2.21 pynacl-1.4.0 pyrsistent-0.16.1 python-dotenv-0.18.0 requests-2.27.1 scandir-1.10.0 six-1.16.0 subprocess32-3.5.4 texttable-1.6.4 typing-3.10.0.0 urllib3-1.26.12 websocket-client-0.59.0 zipp-1.2.0
#pip install --upgrade setuptools
#sudo pip install docker-compose
systemctl start docker.service
sudo systemctl status docker
mkdir -p wordpress && cd $_ && touch docker-compose.yml && mkdir -p ./volumes/nginx/{html,conf.d/ssl,log}
cat > ./docker-compose.yml <<EOF
version: "3.9"

services:
  db:
    #image: mysql:5.7
    image: mysql
    volumes:
      - ./volumes/database:/var/lib/mysql
    restart: always
    environment:
      MYSQL_ROOT_PASSWORD: wordpress
      MYSQL_DATABASE: wordpress
      MYSQL_USER: huixst
      MYSQL_PASSWORD: wordpress
  phpmyadmin:
    image: phpmyadmin
    depends_on:
      - db
    ports:
      - "8081:80"
    environment:
      PMA_HOST: db
  wordpress:
    depends_on:
      - db
    image: wordpress:latest
    volumes:
      - ./volumes/html:/var/www/html
    ports:
      - "8000:80"
    restart: always
    environment:
      WORDPRESS_DB_HOST: db
      WORDPRESS_DB_USER: wordpress
      WORDPRESS_DB_PASSWORD: wordpress
      WORDPRESS_DB_NAME: wordpress
  nginx:
    depends_on:
      - wordpress
    # image: docker.io/library/nginx:latest
    image: nginx:latest
    links:
      - wordpress
    restart: always
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./volumes/nginx/html:/usr/share/nginx/html
      - ./volumes/nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./volumes/nginx/conf.d:/etc/nginx/conf.d
      - ./volumes/nginx/log:/var/log/nginx
      - ./volumes/nginx/conf.d/ssl:/etc/nginx/conf.d/ssl
EOF
#############################--- default.conf ---#############################
cat > ./volumes/nginx/nginx.conf <<EOF

user  nginx;
worker_processes  auto;

error_log  /var/log/nginx/error.log notice;
pid        /var/run/nginx.pid;


events {
    worker_connections  1024;
}


http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    keepalive_timeout  65;

    #gzip  on;
    server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    server_name \$host;

    location / {
        root   /usr/share/nginx/html;
        index  index.html index.htm;
        proxy_pass http://\$host:8000;

        proxy_http_version    1.1;
        proxy_cache_bypass    \$http_upgrade;

        proxy_set_header Upgrade             \$http_upgrade;
        proxy_set_header Connection          "upgrade";
        proxy_set_header Host                \$host;
        proxy_set_header X-Real-IP           \$remote_addr;
        proxy_set_header X-Forwarded-For     \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto   \$scheme;
        proxy_set_header X-Forwarded-Host    \$host;
        proxy_set_header X-Forwarded-Port    \$server_port;
        
        add_header Content-Security-Policy "default-src 'self' gooperating.com www.gooperating.com 'unsafe-inline' 'unsafe-eval'; img-src * blob: *;";
        add_header Cache-Control no-cache;
        add_header X-Frame-Options "SAMEORIGIN";
        add_header X-XSS-Protection "1; mode=block";
        add_header X-Content-Type-Options "nosniff";
        # add_header Content-Security-Policy "policy";
        # add_header Content-Security-Policy "script-src * 'unsafe-inline' 'unsafe-eval'";
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        # add_header Content-Security-Policy "upgrade-insecure-requests;connect-src *";
        # add_header Content-Security-Policy "default-src 'self'; font-src *;img-src * data:; script-src *; style-src *";
    }
    location =/robots.txt {
        default_type text/html;
        add_header Content-Type "text/plain; charset=UTF-8";
        return 200 "User-Agent: *nDisallow: /";
    }
    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }

    # certs sent to the client in SERVER HELLO are concatenated in ssl_certificate
    # ssl_certificate      /etc/ssl/certs/api.example.com.crt;
    # ssl_certificate_key  /etc/ssl/private/api.example.com.key;
    ssl_certificate      /etc/nginx/conf.d/ssl/gooperating.com_server.crt;
    ssl_certificate_key  /etc/nginx/conf.d/ssl/gooperating.com_server.key;
    ssl_session_timeout 5m;
    ssl_session_cache    shared:SSL:10m;  # about 40000 sessions
    ssl_session_tickets on;

    # curl https://ssl-config.mozilla.org/ffdhe2048.txt > /path/to/dhparam.pem
    # ssl_dhparam /etc/ssl/dhparam.pem;

    # intermediate configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers          HIGH:!aNULL:!MD5;
    # ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    
    ssl_prefer_server_ciphers on;

    # HSTS (ngx_http_headers_module is required) (63072000 seconds)
    add_header Strict-Transport-Security "max-age=63072000" always;

    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;

    # verify chain of trust of OCSP response using Root CA and Intermediate certs
    # ssl_trusted_certificate /etc/ssl/gooperating.com/chain1.pem;

    # replace with the IP address of your resolver
    resolver 8.8.8.8 8.8.4.4;
    
    error_page 404 = @400;         # Invalid paths are treated as bad requests
    proxy_intercept_errors on;     # Do not send backend errors to the client
    #include api_json_errors.conf;  # API client friendly JSON error responses
    default_type application/json; # If no content-type then assume JSON
    }
server  {
    listen       80;
    listen  [::]:80;
        server_name    \$host;

        rewrite ^(.*)\$ https://\$host\$1;
        client_max_body_size    1024M;
        sendfile       on;
        tcp_nopush     on;
        aio            on;

        location / {
        root   /usr/share/nginx/html;
        index  index.html index.htm;
        set \$fixed_destination \$http_destination;
        if ( \$http_destination ~* ^https(.*)\$ )
        {
        set \$fixed_destination http\$1;
        }
                
                client_max_body_size 32M;
                client_body_buffer_size 512k;
                proxy_connect_timeout 300;
                proxy_send_timeout 300;
                proxy_read_timeout 300;
                proxy_buffer_size 4k;
                proxy_buffers 4 32k;
                proxy_busy_buffers_size 64k;
                proxy_temp_file_write_size 64k;
                proxy_pass \$host:8000;
                proxy_hide_header Date;
                proxy_set_header Host      \$host;
                proxy_set_header X-Real-IP \$remote_addr;
                proxy_set_header Destination \$fixed_destination;
                proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
                return 301 https://\$host\$request_uri;
                
                # location ~ \.(gif|jpg|png)$ {
                # root /data/images;
                add_header Cache-Control no-cache;
                add_header X-Frame-Options "SAMEORIGIN";
                add_header X-XSS-Protection "1; mode=block";
                add_header X-Content-Type-Options "nosniff";
                add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
                add_header Content-Security-Policy "default-src 'self' gooperating.com www.gooperating.com 'unsafe-inline' 'unsafe-eval'; img-src * blob: *;";
                # add_header Content-Security-Policy "policy";
                # add_header Content-Security-Policy "upgrade-insecure-requests;connect-src *";
                # add_header Content-Security-Policy "script-src * 'unsafe-inline' 'unsafe-eval'";
                # add_header Content-Security-Policy "default-src 'self'; font-src *;img-src * data:; script-src *; style-src *";

                location =/robots.txt {
                    default_type text/html;
                    add_header Content-Type "text/plain; charset=UTF-8";
                    return 200 "User-Agent: *nDisallow: /";
                }
        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
        root   /usr/share/nginx/html;
        }
        # redirect all HTTP requests to HTTPS with a 301 Moved Permanently response.
        return 301 https://\$host\$request_uri;
        }

      include /etc/nginx/conf.d/*.conf;
      }
}
EOF
#############################--- default.conf ---#############################
#mkdir /etc/docker
cat > /etc/docker/daemon.json <<EOF
{
 "registry-mirrors":["https://pee6w651.mirror.aliyuncs.com","http://hub-mirror.c.163.com","https://docker.mirrors.ustc.edu.cn","https://registry.docker-cn.com"],
 "live-restore": true
}
EOF
#gooperating.com_server.crt#
cat > ./volumes/nginx/conf.d/ssl/gooperating.com_server.crt <<EOF
-----BEGIN CERTIFICATE-----
MIIGCTCCBPGgAwIBAgIQDFa1UHaAg5UURUBLfPlYajANBgkqhkiG9w0BAQsFADBu
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMS0wKwYDVQQDEyRFbmNyeXB0aW9uIEV2ZXJ5d2hlcmUg
RFYgVExTIENBIC0gRzEwHhcNMjIwNDI2MDAwMDAwWhcNMjMwNDI1MjM1OTU5WjAa
MRgwFgYDVQQDEw9nb29wZXJhdGluZy5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQCclM+DjppJV2H1q5jH21dp8tj6A3iDaJyuSB64HOZdHtr9tO5u
vHYYZVlQuOrUWa0rh/eqZJm+XBzMKmlTkKUsCdqETeKFAjKh86Ev+qP0oALr6GMN
uXH0MyISFgM206xSZBg8hOtHOVgVolU95ZDw18pg3c+wbpLPo7bc3X7+AtzAQSnZ
kf49J5Vu2Zgpp/znQIZLxWjKqEUxHkJGyjv893Wln8Yd1fpk8RRN/hewoQhTy6UP
PEvEHTqN+b2pa+QFZesGjN3xG+rZh/KQu1QN0hxW5WkbrdU5371L7Sgntts7YNo0
4aVkVaKkiXP1EUDQv4pmArlfUEwOq/SdnTDLAgMBAAGjggL1MIIC8TAfBgNVHSME
GDAWgBRVdE+yck/1YLpQ0dfmUVyaAYca1zAdBgNVHQ4EFgQU1j5foc6mvhklT4Fu
zqb7OyVx6oQwLwYDVR0RBCgwJoIPZ29vcGVyYXRpbmcuY29tghN3d3cuZ29vcGVy
YXRpbmcuY29tMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYI
KwYBBQUHAwIwPgYDVR0gBDcwNTAzBgZngQwBAgEwKTAnBggrBgEFBQcCARYbaHR0
cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMIGABggrBgEFBQcBAQR0MHIwJAYIKwYB
BQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBKBggrBgEFBQcwAoY+aHR0
cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0VuY3J5cHRpb25FdmVyeXdoZXJlRFZU
TFNDQS1HMS5jcnQwCQYDVR0TBAIwADCCAX8GCisGAQQB1nkCBAIEggFvBIIBawFp
AHYArfe++nz/EMiLnT2cHj4YarRnKV3PsQwkyoWGNOvcgooAAAGAZOn1OwAABAMA
RzBFAiAmKkBchfPywVaxVukDkWANVVflc0lbrt7l0opvr63KfgIhANWxTjb0diSG
lmB+8ChPcJ0M/VYoEzHiJmuVVerZ90HVAHcANc8ZG7+xbFe/D61MbULLu7YnICZR
6j/hKu+oA8M71kwAAAGAZOn1KgAABAMASDBGAiEAxBzmyjElyb8oBLZSRjKHGjIH
4weI8E0jd8QJnL8t+EECIQCLRe3Jl1gijjc0Rgyw701dsHxSi4HVnlcrr+oAddS6
6gB2ALNzdwfhhFD4Y4bWBancEQlKeS2xZwwLh9zwAw55NqWaAAABgGTp9WMAAAQD
AEcwRQIgN1YQphplV96BVDnRC4EvKn3WBaKjzOIUl10EuqP9oOICIQCHSveL0j4Y
T8ug2N6ylJ316oGDPZ6eH31vl6hNGUAySDANBgkqhkiG9w0BAQsFAAOCAQEApgeS
QFtdV6jcuhfpXjiQEvDllD0j9DYnVd9vU2u/CDjW4wxdbblso76yCd6sCpem4OOl
prL9oOfEQslrnNl2wHcJ7XVd0CCZI0ml6hYzL5oOdd7G0Kx0u36dOh/wkhHhuVgN
GW1Yh/IjvIEIyp+3wOBpjmlBiUj1Q8p6l74Tx2AjKCcn1hTpM85xM85Lyg7aSSCX
0eoEgA3ApDmq724B+4vENsUIBO3M6hBYx6lB9hkQuzfEZuvUA68kOet5x/0OKQjp
ObsuA4g/6j/Ff09IhvfAzkzc8ybD8UPYJBrt/i6ywDLWyuUZ4CFP30ZrAdaKl2ym
jIh3tiOxMXYaztp6fQ==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEqjCCA5KgAwIBAgIQAnmsRYvBskWr+YBTzSybsTANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0xNzExMjcxMjQ2MTBaFw0yNzExMjcxMjQ2MTBaMG4xCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xLTArBgNVBAMTJEVuY3J5cHRpb24gRXZlcnl3aGVyZSBEViBUTFMgQ0EgLSBH
MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALPeP6wkab41dyQh6mKc
oHqt3jRIxW5MDvf9QyiOR7VfFwK656es0UFiIb74N9pRntzF1UgYzDGu3ppZVMdo
lbxhm6dWS9OK/lFehKNT0OYI9aqk6F+U7cA6jxSC+iDBPXwdF4rs3KRyp3aQn6pj
pp1yr7IB6Y4zv72Ee/PlZ/6rK6InC6WpK0nPVOYR7n9iDuPe1E4IxUMBH/T33+3h
yuH3dvfgiWUOUkjdpMbyxX+XNle5uEIiyBsi4IvbcTCh8ruifCIi5mDXkZrnMT8n
wfYCV6v6kDdXkbgGRLKsR4pucbJtbKqIkUGxuZI2t7pfewKRc5nWecvDBZf3+p1M
pA8CAwEAAaOCAU8wggFLMB0GA1UdDgQWBBRVdE+yck/1YLpQ0dfmUVyaAYca1zAf
BgNVHSMEGDAWgBQD3lA1VtFMu2bwo+IbG8OXsj3RVTAOBgNVHQ8BAf8EBAMCAYYw
HQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBIGA1UdEwEB/wQIMAYBAf8C
AQAwNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
Y2VydC5jb20wQgYDVR0fBDswOTA3oDWgM4YxaHR0cDovL2NybDMuZGlnaWNlcnQu
Y29tL0RpZ2lDZXJ0R2xvYmFsUm9vdENBLmNybDBMBgNVHSAERTBDMDcGCWCGSAGG
/WwBAjAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BT
MAgGBmeBDAECATANBgkqhkiG9w0BAQsFAAOCAQEAK3Gp6/aGq7aBZsxf/oQ+TD/B
SwW3AU4ETK+GQf2kFzYZkby5SFrHdPomunx2HBzViUchGoofGgg7gHW0W3MlQAXW
M0r5LUvStcr82QDWYNPaUy4taCQmyaJ+VB+6wxHstSigOlSNF2a6vg4rgexixeiV
4YSB03Yqp2t3TeZHM9ESfkus74nQyW7pRGezj+TC44xCagCQQOzzNmzEAP2SnCrJ
sNE2DpRVMnL8J6xBRdjmOsC3N6cQuKuRXbzByVBjCqAA8t1L0I+9wXJerLPyErjy
rMKWaBFLmfK/AHNF4ZihwPGOc7w6UHczBZXH5RFzJNnww+WnKuTPI0HfnVH8lg==
-----END CERTIFICATE-----

EOF
#gooperating.com_server.key#
cat > ./volumes/nginx/conf.d/ssl/gooperating.com_server.key <<EOF
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAnJTPg46aSVdh9auYx9tXafLY+gN4g2icrkgeuBzmXR7a/bTu
brx2GGVZULjq1FmtK4f3qmSZvlwczCppU5ClLAnahE3ihQIyofOhL/qj9KAC6+hj
Dblx9DMiEhYDNtOsUmQYPITrRzlYFaJVPeWQ8NfKYN3PsG6Sz6O23N1+/gLcwEEp
2ZH+PSeVbtmYKaf850CGS8VoyqhFMR5CRso7/Pd1pZ/GHdX6ZPEUTf4XsKEIU8ul
DzxLxB06jfm9qWvkBWXrBozd8Rvq2YfykLtUDdIcVuVpG63VOd+9S+0oJ7bbO2Da
NOGlZFWipIlz9RFA0L+KZgK5X1BMDqv0nZ0wywIDAQABAoIBAAGpFlZH0d0LPy+y
xSkBa3jlKWXlWYbTOi4i96huLgc4x4u/OnQULZBuqrbPbzYXSV3X0EmPTY4WPfvw
SzOmqgnAhP+4L7nHXzAWfFQc7VYvyDgmO76ug8XaMPdOInSXZBFvnE4v/qq/se5w
zUSdxZ64Ox4x2/z7/zSSgOLwumMJMnTPQjb0Ow+6mP1pVAnAoAYCkpknfa7DXZk9
C3s8lG4lMicJ2ecUhzyC9VuwpZ/Bg/+PQ6Y1ZWCl+LSzJmKg8DuKWUx4xTI47xQR
9+yjNpP4FKQCAOV2g2uQc7IOYJUTyWchLy8d/S9TkEhI0a2SC+Eed+wrWUbxvoN6
37Y4T3kCgYEA4mA9XNzp2ll8/PMRCuFZKLNgT55kafcerWzGcmjQTTPgePbIBncz
4t+wXqxZ9QnaS/ryB+PD/hSdIt/8Kg7GtCXbbN1eI98RND6NCLfCQlajzCVMRvtk
fBXC4473zRtkjZR3BCi6sP781xZeg/rMhvf7M67mcLRI8vTtgbyx9JcCgYEAsRJm
I9aNnRb98fz0lnYbV9YYtvZHRXR8kUhXi/zlD00YWcm7ChT6YM57UwtauA0f90Et
41l/FgyQK1KxqoXmER/JigOV/GAVSNZEN1hepzJVgGoWCaS9a4ec8GNsdt/77wSg
DTAvrwfhOh1qrMuXEdICNJezgmPuIcQlJX3TZ+0CgYBnVqGMa7hBGcrJubfU7KwD
vWbA0cBq8wlJB7fLcHduVrko3xbOhMnlzlE31pu2FUpWlva3jUziBsz4p6D4Hgit
If75wlAANgsne0psaV4/ZEefoIMigA4N6u0tbg1GzzNmwhhWiLU4qR4InciFnQ6S
qk8896FwX4xRhGeLavUdfwKBgGdsrroKDIcPsd4Q+K+VZp0kUSU0riZURpn5HiGG
4ifQyQNQv+3AmQnIMOIthJxyFhSuPmZHlOJFDkQvtdQ7B0lDPs1dENLrMCNt+0Q0
Wnzf+m7aB+s0DOtst271M5ovc5CFLBLn7UIXoSb3naI1/BQNjPo5DUGAqsuQLH48
gyl1AoGBALh668J2qAPDTjwBPPsZCWJwkHU8FErsrSaIAJVCP7HgKxBNMRwfql49
p7SfLdQKC7Um3UnjT1tIq2dJ46hPw/F/FLmm7TCedEAuBa/FlaQzlOdQf2tVv2ad
YVFVZSCLL+G/DwMKzEZ+1BFqku0WWKry6yy9KYH9v7OjrYvmuXPZ
-----END RSA PRIVATE KEY-----

EOF
systemctl daemon-reload
systemctl restart docker
cd && cd wordpress/ && docker-compose up -d
docker ps -a && pwd
