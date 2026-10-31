#!/usr/bin/env bash
# =============================================================================
#  seedtunnel — translations (English and French)
#
#  Messages are written in English, right in the code, as printf formats:
#      ok 'Client "%s" created.' "$name"
#  In French, each format is looked up in lang/fr.txt, a plain text file in
#  which every English line ("en: …") is followed by its translation
#  ("fr: …"). A missing translation simply shows the English text.
#
#  Longer texts (help, summaries) are functions in lang/en.sh and lang/fr.sh,
#  named text_en_<name> and text_fr_<name>, and shown with:  text <name>
#
#  Language, in order of priority:
#    1. SEEDTUNNEL_LANG=en or fr in the environment;
#    2. the choice saved with « seedtunnel language » (/etc/seedtunnel/language);
#    3. the system language (LC_ALL, LC_MESSAGES, LANG): French if it starts
#       with « fr »;
#    4. English.
# =============================================================================

APP_LANG=en
APP_LANGUAGES=" en fr "
declare -gA TRANSLATIONS=()

is_language() { [[ -n $1 && $APP_LANGUAGES == *" $1 "* ]]; }

# Language chosen by the environment, the saved choice or the system
i18n_detect() {
    local saved="" system=${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}
    if is_language "${SEEDTUNNEL_LANG-}"; then
        printf '%s' "$SEEDTUNNEL_LANG"
        return 0
    fi
    if [[ -r $APP_LANG_FILE ]]; then
        IFS= read -r saved <"$APP_LANG_FILE" || true
        if is_language "$saved"; then
            printf '%s' "$saved"
            return 0
        fi
    fi
    if [[ $system == fr* ]]; then printf fr; else printf en; fi
}

# i18n_load LANGUAGE — loads the long texts and the translated messages
i18n_load() {
    local line key="" catalog
    APP_LANG=$1
    TRANSLATIONS=()
    # shellcheck source=lang/en.sh
    . "$APP_DIR/lang/en.sh"
    [[ $APP_LANG != en ]] || return 0
    # shellcheck source=/dev/null
    if [[ -r $APP_DIR/lang/$APP_LANG.sh ]]; then . "$APP_DIR/lang/$APP_LANG.sh"; fi
    catalog="$APP_DIR/lang/$APP_LANG.txt"
    [[ -r $catalog ]] || return 0
    while IFS= read -r line || [[ -n $line ]]; do
        case $line in
            "en: "*) key=${line#en: } ;;
            "$APP_LANG: "*)
                if [[ -n $key ]]; then TRANSLATIONS[$key]=${line#"$APP_LANG: "}; fi
                key=""
                ;;
        esac
    done <"$catalog"
}

i18n_init() { i18n_load "$(i18n_detect)"; }

# t FORMAT [ARGUMENTS…] → the message in the current language
t() {
    local format=$1
    shift
    if [[ $APP_LANG != en && -n $format && -n ${TRANSLATIONS[$format]-} ]]; then
        format=${TRANSLATIONS[$format]}
    fi
    # shellcheck disable=SC2059 # the format comes from the code or from lang/
    printf -- "$format" "$@"
}

# text NAME → a long text from lang/<language>.sh (English if missing)
text() {
    if declare -F "text_${APP_LANG}_$1" >/dev/null; then
        "text_${APP_LANG}_$1"
    else
        "text_en_$1"
    fi
}

# Saves the language for the next runs
language_save() {
    install -d -m 700 "$APP_STATE_DIR"
    printf '%s\n' "$1" >"$APP_LANG_FILE"
    i18n_load "$1"
}

# First menu run without a saved choice: the question is asked once
language_first_run() {
    local choice default=1
    [[ ! -e $APP_LANG_FILE ]] || return 0
    is_language "${SEEDTUNNEL_LANG-}" && return 0
    if [[ $APP_LANG == fr ]]; then default=2; fi
    printf '\n  1) English\n  2) Français\n\n'
    IFS= read -r -e -i "$default" -p "Language / Langue [1-2] : " choice || exit 130
    if [[ $choice == 2 ]]; then language_save fr; else language_save en; fi
}

# seedtunnel language [en|fr]
language_cli() {
    case ${1-} in
        "") say 'Language: %s   (change it with: seedtunnel language en|fr)' "$APP_LANG" ;;
        en | fr)
            language_save "$1"
            ok 'Language: %s.' "$(t 'English')"
            ;;
        *) die 'Usage: seedtunnel language en|fr' ;;
    esac
}

language_menu() {
    local choice
    printf '\n  1) English\n  2) Français\n\n'
    IFS= read -r -p "Language / Langue [1-2] : " choice || return 0
    case $choice in
        1) language_save en ;;
        2) language_save fr ;;
    esac
}
