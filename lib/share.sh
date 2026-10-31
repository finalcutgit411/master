#!/usr/bin/env bash
# =============================================================================
#  seedtunnel — one-time download links
#
#  To get a file (VPN configuration, FileZilla site, backup) onto a computer
#  without scp: the HTTPS site of the seedbox serves
#  https://<domain>/share/<token>/, a page with a download button. The token
#  is random (128 bits): impossible to guess.
#
#  nginx serves the file of a link once: any other request on it is refused on
#  the spot (even right after, on the same connection, or with another form of
#  the address), never a partial download, and a HEAD request is refused
#  without using the link up. The file is also deleted the moment nginx opens
#  it (inotify). An unused link expires after 10 minutes. Everything lives in
#  /run, which is emptied at boot.
#  Opening the page does not count: a messaging app that previews the link
#  does not use it up.
# =============================================================================

SHARE_DIR="/run/seedtunnel-share"
SHARE_URL_PATH="/share"
SHARE_LIFETIME=600

# Watches one link (started on its own by systemd-run): waits for the first
# opening of the file, or the end of the lifetime, then deletes the link.
# If a mark file is given, it is touched when the file was really opened.
#   $1 file   $2 lifetime (seconds)   $3 folder of the link   $4 mark file
read -r -d '' SHARE_WATCHER <<'SH' || true
if inotifywait -qq -t "$2" -e open -- "$1"; then
    if [[ -n $4 ]]; then touch -- "$4"; fi
fi
rm -rf -- "$3"
SH

# nginx directives at the top of the seedbox site (http level)
share_generate_nginx_http() {
    cat <<'EOF'
# One-time links (see the location /share/ below). The file of a link (never
# its page) is served once: any other request on it gets a 404 for a minute,
# and by then the file is long gone. nginx decides it on the spot, so two
# requests one right after the other cannot both get the file.
map $uri $seedtunnel_share_file {
    "~^/share/[0-9a-f]{32}/[^/]+$" $uri;
    default "";
}
limit_req_zone $seedtunnel_share_file zone=seedtunnel_share:1m rate=1r/m;
# Only GET gets the file: HEAD (or anything else) would open it, using the link
# up, without downloading it
map "$request_method $uri" $seedtunnel_share_refused {
    "~^GET " 0;
    "~^[^ ]+ /share/[0-9a-f]{32}/[^/]+$" 1;
    default 0;
}
EOF
}

# nginx block inside the HTTPS server of the seedbox (see nginx_generate_site).
# $1: HSTS header, if any, already formatted.
share_generate_nginx() {
    cat <<EOF

    # One-time links (seedtunnel vpn share, seedbox sftp-config, backup share):
    # no password, the random token of the link plays that role
    location ^~ $SHARE_URL_PATH/ {
        auth_basic off;
        alias $SHARE_DIR/;
        log_not_found off;
        # the file: GET only, served once (see the top of the site), always
        # whole (no Range, no cache)
        if (\$seedtunnel_share_refused) {
            return 405;
        }
        limit_req zone=seedtunnel_share;
        limit_req_status 404;
        max_ranges 0;
        open_file_cache off;
        if_modified_since off;
        etag off;
        types {
            text/html html;
        }
        default_type application/octet-stream;
        add_header Cache-Control "no-store" always;
        add_header X-Content-Type-Options nosniff always;
        add_header Referrer-Policy no-referrer always;
        add_header X-Robots-Tag "noindex, nofollow" always;
        add_header Content-Security-Policy "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'" always;${1-}
    }
EOF
}

# Links go through the seedbox site: it must be installed and running.
# $1: what to do instead, without a seedbox.
share_require() {
    seedbox_installed || die 'Download links go through the HTTPS site of the seedbox, which is not installed.\n  %s' "$1"
    systemctl is-active --quiet nginx || die 'nginx is stopped:  seedtunnel seedbox restart'
}

# Safety net: link folders whose watcher has disappeared
share_purge() {
    [[ -d $SHARE_DIR ]] || return 0
    find "$SHARE_DIR" -mindepth 1 -maxdepth 1 -type d -mmin +$((SHARE_LIFETIME / 60 + 5)) \
        -exec rm -rf {} + 2>/dev/null || true
}

# Home page of a link: download button + how to use the file.
# Everything inserted here was checked before (names, domain): no HTML.
share_generate_page() {
    local name=$1 title=$2 steps=$3 note=$4
    cat <<EOF
<!doctype html>
<html lang="$APP_LANG">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>$title</title>
<style>
body { font: 16px/1.55 system-ui, sans-serif; max-width: 34rem; margin: 2.5rem auto; padding: 0 1rem; color: #1f2328; background: #f6f8fa; }
h1 { font-size: 1.35rem; }
.button { display: inline-block; margin: .5rem 0 1rem; padding: .75rem 1.3rem; border-radius: .5rem; background: #1f6feb; color: #fff; font-weight: 600; text-decoration: none; }
li { margin: .35rem 0; }
code { background: #eaeef2; padding: .1rem .3rem; border-radius: .25rem; word-break: break-all; }
.note { color: #57606a; font-size: .92rem; }
@media (prefers-color-scheme: dark) {
  body { color: #e6edf3; background: #0d1117; }
  code { background: #2d333b; }
  .note { color: #8d96a0; }
}
</style>
</head>
<body>
<h1>$title</h1>
<a class="button" href="$name" download>$(t 'Download %s' "$name")</a>
<ol>
$steps
</ol>
<p class="note">$note $(t 'This link works only once and expires after %s minutes.' "$((SHARE_LIFETIME / 60))")</p>
</body>
</html>
EOF
}

# share_create FILE NAME "Title" "<li>steps…</li>" "Note" [MARK_FILE]
# Publishes FILE under the name NAME and prints the link.
share_create() {
    local source=$1 name=$2 title=$3 steps=$4 note=$5 mark=${6-} token dir unit i ready=0
    apt_install inotify-tools
    # the site must know /share/ (if it was installed by an older version)
    seedbox_apply_nginx
    share_purge
    install -d -m 750 -o root -g www-data "$SHARE_DIR"
    token=$(openssl rand -hex 16)
    dir="$SHARE_DIR/$token"
    install -d -m 750 -o root -g www-data "$dir"
    install -m 640 -o root -g www-data "$source" "$dir/$name"
    share_generate_page "$name" "$title" "$steps" "$note" >"$dir/index.html"
    chown root:www-data "$dir/index.html"
    chmod 640 "$dir/index.html"

    printf '\n=== %(%F %T)T · download link for %s\n' -1 "$name" >>"$APP_LOG"
    # The watcher runs as a service of its own. Whatever ends it (download,
    # expiry, crash, killed), systemd deletes the link afterwards
    # (ExecStopPost); RuntimeMaxSec ends it at the latest after the lifetime.
    unit="seedtunnel-share-${token:0:12}"
    if ! systemd-run --quiet --collect --unit="$unit" \
        --property=RuntimeMaxSec=$((SHARE_LIFETIME + 60)) \
        --property="ExecStopPost=/bin/rm -rf -- $dir" \
        /bin/bash -c "$SHARE_WATCHER" seedtunnel-share \
        "$dir/$name" "$SHARE_LIFETIME" "$dir" "$mark" >>"$APP_LOG" 2>&1; then
        rm -rf "$dir"
        die 'Cannot start the watcher of the link (details in %s).' "$APP_LOG"
    fi
    # the watch must be in place before the link is shown: otherwise, no link
    for i in {1..50}; do
        if pgrep -f -- "inotifywait.*$dir/$name" >/dev/null; then
            ready=1
            break
        fi
        sleep 0.1
    done
    if ((!ready)); then
        systemctl stop "$unit" >>"$APP_LOG" 2>&1 || true
        rm -rf "$dir"
        die 'The watcher of the link did not start (details in %s): link cancelled.' "$APP_LOG"
    fi
    sleep 0.2

    echo
    say 'Download link (%sone time only, for %s minutes%s):' "$C_BOLD" "$((SHARE_LIFETIME / 60))" "$C_RESET"
    printf '  %shttps://%s%s/%s/%s\n\n' "$C_BOLD" "$SEEDBOX_DOMAIN" "$SHARE_URL_PATH" "$token" "$C_RESET"
    if [[ $SEEDBOX_CERTIFICATE == selfsigned ]]; then
        say 'Self-signed certificate: the browser will show a warning, to accept.'
        echo
    fi
}
