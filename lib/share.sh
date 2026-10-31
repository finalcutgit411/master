#!/usr/bin/env bash
# =============================================================================
#  finalcut — liens de téléchargement à usage unique
#
#  Pour récupérer un fichier (configuration VPN, connexion FileZilla) sur un
#  ordinateur ou un téléphone sans scp : le site HTTPS de la seedbox sert
#  https://<domaine>/partage/<jeton>/, une page avec un bouton de
#  téléchargement. Le jeton est aléatoire (128 bits) : impossible à deviner.
#
#  Le fichier disparaît dès qu'il a été téléchargé une fois, et au plus tard au
#  bout de 10 minutes. Tout est rangé dans /run, vidé au redémarrage.
#  Ouvrir la page ne compte pas : l'aperçu de lien d'une messagerie ne
#  « consomme » pas le téléchargement.
# =============================================================================

SHARE_DIR="/run/finalcut-share"
SHARE_LOG="/var/log/nginx/finalcut-partage.log"
SHARE_PATH="/partage"
SHARE_TTL=600

# Surveillance d'un lien (lancée à part par systemd-run) : attend dans le
# journal de nginx le premier téléchargement réussi du fichier, ou la fin du
# délai, puis supprime le dossier du lien.
#   $1 jeton  $2 fichier  $3 taille du journal au départ  $4 délai (s)
#   $5 dossier du lien  $6 journal nginx  $7 chemin web
read -r -d '' SHARE_WATCHER <<'SH' || true
end=$((SECONDS + $4))
while ((SECONDS < end)); do
    if IFS= read -r -t "$((end - SECONDS))" line; then
        if [[ $line == *"\"GET $7/$1/$2 HTTP/"*"\" 200 "* ]]; then break; fi
    elif (($? <= 128)); then
        break
    fi
done < <(exec tail -c "+$(($3 + 1))" -F "$6" 2>/dev/null)
rm -rf -- "$5"
SH

# Bloc nginx inséré dans le site HTTPS de la seedbox (voir sb_gen_nginx).
# $1 : en-tête HSTS éventuel, déjà mis en forme.
share_gen_nginx() {
    cat <<EOF

    # Liens à usage unique (finalcut vpn share, finalcut seedbox sftp-config) :
    # pas de mot de passe, le jeton aléatoire du lien en tient lieu
    location ^~ $SHARE_PATH/ {
        auth_basic off;
        alias $SHARE_DIR/;
        access_log $SHARE_LOG;
        log_not_found off;
        types {
            text/html html;
            application/octet-stream conf xml;
        }
        add_header Cache-Control "no-store" always;
        add_header X-Content-Type-Options nosniff always;
        add_header Referrer-Policy no-referrer always;
        add_header X-Robots-Tag "noindex, nofollow" always;
        add_header Content-Security-Policy "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'" always;${1-}
    }
EOF
}

# Les liens passent par le site de la seedbox : il doit être en place.
# $1 : solution de repli à proposer sans seedbox.
share_require() {
    sb_installed || die "Les liens de téléchargement passent par le site HTTPS de la seedbox, qui n'est pas installée.
  $1"
    systemctl is-active --quiet nginx || die "nginx est arrêté :  finalcut seedbox restart"
}

# Filet de sécurité : dossiers dont la surveillance aurait disparu
share_purge() {
    [[ -d $SHARE_DIR ]] || return 0
    find "$SHARE_DIR" -mindepth 1 -maxdepth 1 -type d -mmin +$((SHARE_TTL / 60 + 5)) \
        -exec rm -rf {} + 2>/dev/null || true
}

# Page d'accueil du lien : bouton de téléchargement + mode d'emploi.
# Tout ce qui y est inséré a été validé avant (noms, domaine) : pas de HTML.
share_gen_page() {
    local name=$1 title=$2 steps=$3 note=$4
    cat <<EOF
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>$title</title>
<style>
body { font: 16px/1.55 system-ui, sans-serif; max-width: 34rem; margin: 2.5rem auto; padding: 0 1rem; color: #1f2328; background: #f6f8fa; }
h1 { font-size: 1.35rem; }
.btn { display: inline-block; margin: .5rem 0 1rem; padding: .75rem 1.3rem; border-radius: .5rem; background: #1f6feb; color: #fff; font-weight: 600; text-decoration: none; }
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
<a class="btn" href="$name" download>Télécharger $name</a>
<ol>
$steps
</ol>
<p class="note">$note Ce lien ne fonctionne qu'une fois et expire au bout de $((SHARE_TTL / 60)) minutes.</p>
</body>
</html>
EOF
}

# share_create FICHIER NOM "Titre" "<li>étapes…</li>" "Remarque"
# Publie FICHIER sous le nom NOM et affiche le lien.
share_create() {
    local src=$1 name=$2 title=$3 steps=$4 note=$5 token dir size
    # le site doit connaître /partage/ (installations antérieures à la 2.2)
    sb_apply_nginx
    share_purge
    install -d -m 750 -o root -g www-data "$SHARE_DIR"
    token=$(openssl rand -hex 16)
    dir="$SHARE_DIR/$token"
    install -d -m 750 -o root -g www-data "$dir"
    install -m 640 -o root -g www-data "$src" "$dir/$name"
    share_gen_page "$name" "$title" "$steps" "$note" >"$dir/index.html"
    chown root:www-data "$dir/index.html"
    chmod 640 "$dir/index.html"

    size=$(stat -c %s "$SHARE_LOG" 2>/dev/null || echo 0)
    printf '\n=== %(%F %T)T · lien de téléchargement pour %s\n' -1 "$name" >>"$FC_LOG"
    if ! systemd-run --quiet --collect --unit="finalcut-partage-${token:0:12}" \
        --property=RuntimeMaxSec=$((SHARE_TTL + 60)) \
        /bin/bash -c "$SHARE_WATCHER" finalcut-partage \
        "$token" "$name" "$size" "$SHARE_TTL" "$dir" "$SHARE_LOG" "$SHARE_PATH" >>"$FC_LOG" 2>&1; then
        rm -rf "$dir"
        die "Impossible de programmer la suppression du lien (détails dans $FC_LOG)."
    fi

    printf '\nLien de téléchargement (%sune seule fois, pendant %s minutes%s) :\n' \
        "$C_BLD" "$((SHARE_TTL / 60))" "$C_END"
    printf '  %shttps://%s%s/%s/%s\n\n' "$C_BLD" "$SB_DOMAIN" "$SHARE_PATH" "$token" "$C_END"
    if [[ $SB_CERT == selfsigned ]]; then
        echo "Certificat auto-signé : le navigateur affichera une alerte, à accepter."
        echo
    fi
}
