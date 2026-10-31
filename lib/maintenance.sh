#!/usr/bin/env bash
# =============================================================================
#  finalcut — sauvegarde, restauration, mise à jour
#
#  Sauvegarde : archive chiffrée (AES-256, clé dérivée de la phrase de passe)
#  contenant /etc/finalcut (clés et clients du VPN, réglages et empreintes des
#  mots de passe de la seedbox, pare-feu), les certificats Let's Encrypt et les
#  clés SSH du SFTP. Les fichiers téléchargés ne sont pas inclus.
#
#  Restauration : sur un serveur neuf, remet tout en place et réinstalle ce
#  qu'il faut. Les clients du VPN continuent de fonctionner sans rien changer
#  si l'adresse du serveur (idéalement un nom de domaine) pointe vers lui.
#
#  Mise à jour : télécharge la dernière version publiée sur GitHub, vérifie son
#  empreinte SHA-256, puis remplace le dossier du script (ou « git checkout »
#  de la dernière étiquette si le script a été installé avec git).
# =============================================================================

BK_PASS=""
BK_TMP=""
BK_PATHS=(etc/finalcut etc/letsencrypt etc/ssh/finalcut_authorized_keys)

bk_cleanup() {
    if [[ -n $BK_TMP && -d $BK_TMP ]]; then rm -rf "$BK_TMP"; fi
    BK_TMP=""
    BK_PASS=""
}

# bk_passphrase 1|0 — 1 : nouvelle phrase (confirmée, 12 caractères minimum)
bk_passphrase() {
    local again
    if [[ -n $FC_PASSFILE ]]; then
        [[ -r $FC_PASSFILE ]] || die "Fichier de phrase de passe introuvable : $FC_PASSFILE"
        IFS= read -r BK_PASS <"$FC_PASSFILE" || true
    elif [[ -t 0 ]]; then
        IFS= read -r -s -p "Phrase de passe de la sauvegarde : " BK_PASS || exit 130
        echo
        if (($1)); then
            IFS= read -r -s -p "Confirmez-la : " again || exit 130
            echo
            [[ $BK_PASS == "$again" ]] || die "Les deux saisies sont différentes."
        fi
    else
        die "Sans terminal, indiquez la phrase de passe avec --passphrase-file FICHIER."
    fi
    if (($1)) && ((${#BK_PASS} < 12)); then die "Phrase de passe : 12 caractères minimum."; fi
    [[ -n $BK_PASS ]] || die "Phrase de passe vide."
}

# Archive tar compressée puis chiffrée ; la phrase de passe passe par un
# descripteur de fichier, jamais en argument (invisible dans « ps »).
bk_create() {
    local out=$1
    shift
    tar -czf - --numeric-owner -C / "$@" \
        | openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass fd:3 -out "$out" 3<<<"$BK_PASS"
}

backup_main() {
    local out p old_umask
    local -a list=()
    titre
    section "SAUVEGARDE"
    if ! vpn_installed && ! sb_installed && ! fw_enabled; then
        die "Rien à sauvegarder : ni VPN, ni seedbox, ni pare-feu installés."
    fi
    for p in "${BK_PATHS[@]}"; do
        if [[ -e /$p ]]; then list+=("$p"); fi
    done
    out=${FC_OUTPUT:-/root/finalcut-$(hostname -s)-$(date +%Y%m%d-%H%M%S).tar.gz.enc}
    echo "Contenu : clés et clients du VPN, réglages et empreintes des mots de passe de la"
    echo "seedbox, pare-feu, certificats. Les fichiers téléchargés ne sont pas inclus."
    echo
    bk_passphrase 1
    old_umask=$(umask)
    umask 077
    run "Création de l'archive chiffrée" bk_create "$out" "${list[@]}"
    umask "$old_umask"
    BK_PASS=""
    echo
    ok "Sauvegarde : $out"
    echo "  Copiez-la ailleurs que sur ce serveur, par exemple :"
    echo "    scp root@$(hostname -f 2>/dev/null || hostname):$out ."
    echo "  Sans la phrase de passe, elle est irrécupérable."
    pause
}

restore_main() {
    local file=${1-} list bad stamp was=$FC_INTERACTIVE
    [[ -n $file ]] || die "Usage : finalcut restore FICHIER"
    [[ -r $file ]] || die "Fichier introuvable : $file"
    titre
    section "RESTAURATION"
    bk_passphrase 0
    BK_TMP=$(mktemp -d)
    if ! openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -in "$file" -out "$BK_TMP/b.tar.gz" \
        -pass fd:3 3<<<"$BK_PASS" 2>>"$FC_LOG"; then
        bk_cleanup
        die "Déchiffrement impossible : phrase de passe incorrecte ou fichier abîmé."
    fi
    BK_PASS=""
    if ! list=$(tar -tzf "$BK_TMP/b.tar.gz" 2>>"$FC_LOG"); then
        bk_cleanup
        die "Archive illisible."
    fi
    # On n'extrait rien d'autre que ce que finalcut sauvegarde
    bad=$(grep -vE '^(etc/finalcut|etc/letsencrypt|etc/ssh/finalcut_authorized_keys)(/|$)' <<<"$list" || true)
    if [[ -n $bad ]]; then
        bk_cleanup
        die "Archive refusée : chemin inattendu « ${bad%%$'\n'*} »"
    fi
    echo "La sauvegarde contient :"
    if grep -qx 'etc/finalcut/vpn.conf' <<<"$list"; then echo "  - le VPN et ses clients"; fi
    if grep -qx 'etc/finalcut/seedbox.conf' <<<"$list"; then echo "  - la seedbox (réglages, mots de passe, certificats)"; fi
    if grep -qx 'etc/finalcut/firewall.conf' <<<"$list"; then echo "  - le pare-feu"; fi
    echo
    if ! confirm "Restaurer ? Les réglages actuels de finalcut seront remplacés" n; then
        bk_cleanup
        return 0
    fi
    echo
    mkdir "$BK_TMP/x"
    run "Extraction de l'archive" tar -xzf "$BK_TMP/b.tar.gz" --numeric-owner -C "$BK_TMP/x"
    stamp=$(date +%Y%m%d-%H%M%S)
    if [[ -n $(ls -A "$FC_ETC" 2>/dev/null) ]]; then
        mv "$FC_ETC" "$FC_ETC.avant-restauration-$stamp"
        warn "Anciens réglages mis de côté dans $FC_ETC.avant-restauration-$stamp"
    else
        rm -rf "$FC_ETC"
    fi
    cp -a "$BK_TMP/x/etc/finalcut" /etc/
    if [[ -d $BK_TMP/x/etc/letsencrypt ]]; then cp -a "$BK_TMP/x/etc/letsencrypt" /etc/; fi
    if [[ -d $BK_TMP/x/etc/ssh/finalcut_authorized_keys ]]; then
        cp -a "$BK_TMP/x/etc/ssh/finalcut_authorized_keys" /etc/ssh/
    fi
    bk_cleanup

    # Tout est réinstallé à partir des réglages restaurés, sans question
    vpn_load
    sb_load
    FC_INTERACTIVE=0
    if vpn_installed; then
        vpn_check_kernel
        base_setup
        vpn_apply
    fi
    if sb_installed; then
        base_setup
        sb_apply
    fi
    if fw_enabled; then fw_enable; fi
    FC_INTERACTIVE=$was
    echo
    ok "Restauration terminée."
    if sb_installed; then
        echo "  Pensez à recopier les fichiers téléchargés dans $SB_DATA, par exemple :"
        echo "    rsync -a --info=progress2 ancien-serveur:$SB_DATA/ $SB_DATA/"
    fi
}

# --- Mise à jour -----------------------------------------------------------------

# version_gt A B → vrai si A est strictement plus récente que B
version_gt() {
    [[ $1 != "$2" && $(printf '%s\n' "$1" "$2" | sort -V | tail -n 1) == "$1" ]]
}

update_verify() {
    (cd "$1" && grep " finalcut-$2.tar.gz\$" SHA256SUMS | sha256sum -c -)
}

update_check_syntax() {
    local f
    for f in "$1"/finalcut.sh "$1"/lib/*.sh; do bash -n "$f" || return 1; done
}

update_tarball() {
    local tag ver tmp base
    tag=$(curl -fsSL --max-time 15 "https://api.github.com/repos/$FC_REPO/releases/latest" 2>/dev/null \
        | jq -r '.tag_name // empty' 2>/dev/null || true)
    [[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Impossible de connaître la dernière version publiée sur github.com/$FC_REPO."
    ver=${tag#v}
    if ! version_gt "$ver" "$FC_VERSION"; then
        ok "finalcut est à jour (version $FC_VERSION)."
        return 0
    fi
    echo "Version installée : $FC_VERSION → disponible : $ver"
    echo "  Nouveautés : https://github.com/$FC_REPO/releases/tag/$tag"
    echo
    if ! confirm "Mettre à jour ?" o; then return 0; fi
    tmp=$(mktemp -d)
    base="https://github.com/$FC_REPO/releases/download/$tag"
    run "Téléchargement de finalcut $ver" curl -fsSL -o "$tmp/finalcut-$ver.tar.gz" "$base/finalcut-$ver.tar.gz"
    run "Téléchargement des empreintes" curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"
    run "Vérification de l'empreinte SHA-256" update_verify "$tmp" "$ver"
    run "Extraction" tar -xzf "$tmp/finalcut-$ver.tar.gz" -C "$tmp"
    run "Contrôle de la syntaxe" update_check_syntax "$tmp/finalcut-$ver"
    # Remplacement par renommage : le script en cours garde ses fichiers ouverts
    rm -rf "$FC_DIR.ancien"
    mv "$FC_DIR" "$FC_DIR.ancien"
    mv "$tmp/finalcut-$ver" "$FC_DIR"
    rm -rf "$FC_DIR.ancien" "$tmp"
    ok "finalcut mis à jour en version $ver (voir $FC_DIR/CHANGELOG.md)."
    exit 0
}

update_git() {
    local tag
    [[ -z $(git -C "$FC_DIR" status --porcelain 2>/dev/null) ]] \
        || die "Le dossier $FC_DIR contient des modifications locales : mise à jour annulée."
    run "Récupération des versions publiées" git -C "$FC_DIR" fetch --tags --quiet
    tag=$(git -C "$FC_DIR" tag -l 'v*' --sort=-v:refname | awk 'NR == 1')
    [[ -n $tag ]] || die "Aucune version publiée (étiquette vX.Y.Z) dans le dépôt."
    if ! version_gt "${tag#v}" "$FC_VERSION"; then
        ok "finalcut est à jour (version $FC_VERSION)."
        return 0
    fi
    echo "Version installée : $FC_VERSION → disponible : ${tag#v}"
    if ! confirm "Mettre à jour ?" o; then return 0; fi
    run "Passage à la version ${tag#v}" git -C "$FC_DIR" -c advice.detachedHead=false checkout --quiet "$tag"
    ok "finalcut mis à jour en version ${tag#v} (voir $FC_DIR/CHANGELOG.md)."
    exit 0
}

update_main() {
    titre
    section "MISE À JOUR DE FINALCUT"
    if [[ -d $FC_DIR/.git ]]; then
        update_git
    else
        [[ $FC_REPO != VOTRE-COMPTE/* ]] \
            || die "Indiquez le dépôt GitHub du projet (FC_REPO) dans $FC_DIR/lib/common.sh."
        update_tarball
    fi
    pause
}

# Sous-menu « Sauvegarder / restaurer »
maintenance_menu() {
    local choix file
    while true; do
        titre
        section "SAUVEGARDER / RESTAURER"
        cat <<EOF
1) Créer une sauvegarde chiffrée
2) Restaurer une sauvegarde

Q) Retour
EOF
        echo
        ask choix "Votre choix" ""
        case ${choix,,} in
            1) backup_main ;;
            2)
                ask file "Chemin du fichier de sauvegarde" "/root/"
                if [[ -n $file ]]; then
                    restore_main "$file"
                    pause
                fi
                ;;
            q) return 0 ;;
        esac
    done
}
