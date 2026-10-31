#!/usr/bin/env bash
# =============================================================================
#  seedtunnel — update, and applying the configuration again
#
#  Update: downloads the latest version published on GitHub, checks its
#  SHA-256 fingerprint, then replaces the folder of the script (or
#  « git checkout » of the latest tag if the script was installed with git).
#  The new version then applies its own fixes (« seedtunnel apply »).
# =============================================================================

# version_greater A B → true if A is strictly newer than B
version_greater() {
    [[ $1 != "$2" && $(printf '%s\n' "$1" "$2" | sort -V | tail -n 1) == "$1" ]]
}

update_verify_checksum() {
    (cd "$1" && grep " seedtunnel-$2.tar.gz\$" SHA256SUMS | sha256sum -c -)
}

update_check_syntax() {
    local file
    for file in "$1"/seedtunnel.sh "$1"/lib/*.sh "$1"/lang/*.sh; do
        bash -n "$file" || return 1
    done
}

update_from_release() {
    local tag version tmp base
    tag=$(curl -fsSL --max-time 15 "https://api.github.com/repos/$APP_REPO/releases/latest" 2>/dev/null \
        | jq -r '.tag_name // empty' 2>/dev/null || true)
    [[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die 'Cannot find the latest version published on github.com/%s.' "$APP_REPO"
    version=${tag#v}
    if ! version_greater "$version" "$APP_VERSION"; then
        ok 'seedtunnel is up to date (version %s).' "$APP_VERSION"
        return 0
    fi
    say 'Installed version: %s → available: %s' "$APP_VERSION" "$version"
    say '  What is new: %s' "https://github.com/$APP_REPO/releases/tag/$tag"
    echo
    if ! confirm 'Update?' y; then return 0; fi
    tmp=$(mktemp -d)
    base="https://github.com/$APP_REPO/releases/download/$tag"
    run "$(t 'Downloading seedtunnel %s' "$version")" curl -fsSL -o "$tmp/seedtunnel-$version.tar.gz" "$base/seedtunnel-$version.tar.gz"
    run 'Downloading the fingerprints' curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"
    run 'Checking the SHA-256 fingerprint' update_verify_checksum "$tmp" "$version"
    run 'Extracting' tar -xzf "$tmp/seedtunnel-$version.tar.gz" -C "$tmp"
    run 'Checking the syntax' update_check_syntax "$tmp/seedtunnel-$version"
    # Replaced by renaming: the running script keeps its files open
    rm -rf "$APP_DIR.old"
    mv "$APP_DIR" "$APP_DIR.old"
    mv "$tmp/seedtunnel-$version" "$APP_DIR"
    rm -rf "$APP_DIR.old" "$tmp"
    ok 'seedtunnel updated to version %s (see %s).' "$version" "$APP_DIR/CHANGELOG.md"
    update_reapply
}

update_from_git() {
    local tag="" candidate
    [[ -z $(git -C "$APP_DIR" status --porcelain 2>/dev/null) ]] \
        || die 'The folder %s has local changes: update cancelled.' "$APP_DIR"
    run 'Fetching the published versions' git -C "$APP_DIR" fetch --tags --quiet
    # newest tag of seedtunnel (older tags of the repository belong to finalcut)
    while IFS= read -r candidate; do
        if git -C "$APP_DIR" cat-file -e "$candidate:seedtunnel.sh" 2>/dev/null; then
            tag=$candidate
            break
        fi
    done < <(git -C "$APP_DIR" tag -l 'v*' --sort=-v:refname)
    [[ -n $tag ]] || die 'No published version (vX.Y.Z tag) in the repository.'
    if ! version_greater "${tag#v}" "$APP_VERSION"; then
        ok 'seedtunnel is up to date (version %s).' "$APP_VERSION"
        return 0
    fi
    say 'Installed version: %s → available: %s' "$APP_VERSION" "${tag#v}"
    if ! confirm 'Update?' y; then return 0; fi
    run "$(t 'Switching to version %s' "${tag#v}")" git -C "$APP_DIR" -c advice.detachedHead=false checkout --quiet "$tag"
    ok 'seedtunnel updated to version %s (see %s).' "${tag#v}" "$APP_DIR/CHANGELOG.md"
    update_reapply
}

update_main() {
    banner
    section 'UPDATING SEEDTUNNEL'
    if [[ -d $APP_DIR/.git ]]; then update_from_git; else update_from_release; fi
    pause
}

# After an update: the new version applies its own fixes
update_reapply() {
    echo
    exec "$APP_DIR/seedtunnel.sh" apply
}

# Puts the server back in the state saved in /etc/seedtunnel, with the settings
# of the installed version: after an update, or if something was changed by
# hand. As when the installation runs again, only the files that change are
# written and only the services concerned are restarted.
apply_main() {
    local count=0
    banner
    section 'APPLYING THE CONFIGURATION'
    if vpn_installed; then
        vpn_apply
        count=$((count + 1))
    fi
    if seedbox_installed; then
        seedbox_apply
        count=$((count + 1))
    fi
    if firewall_enabled; then
        firewall_refresh
        count=$((count + 1))
    fi
    if [[ -r $BACKUP_PASSPHRASE_FILE ]]; then backup_auto_install_units; fi
    if ((count)); then
        ok 'Configuration up to date (seedtunnel %s).' "$APP_VERSION"
    else
        say 'Nothing to apply: neither VPN, nor seedbox, nor firewall.'
    fi
}
