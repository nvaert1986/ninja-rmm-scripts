#!/bin/bash
# /usr/local/bin/dpkg
#
# NinjaOne agent compatibility wrapper for Gentoo Linux.
# Handles the dpkg calls the agent makes for uninstall detection.
# Package removal via this wrapper is disabled for safety.
#
# Requires: app-portage/portage-utils (qlist)

readonly WRAPPER_PKG="a-gentoo-dpkg-wrapper"
readonly WRAPPER_VER="1.0.0"
readonly WRAPPER_ARCH="amd64"
readonly WRAPPER_DESC="Portage-to-dpkg compatibility wrapper: lists Gentoo packages in dpkg format"
readonly WRAPPER_CAT="gentoo-meta"

_portage_packages() {
    qlist -IRv 2>/dev/null | awk '
    {
        sub(/::.*$/, "")
        n = split($0, p, "/")
        cat  = p[1]; rest = p[2]
        pn   = rest; pvr  = ""
        for (i = length(rest); i >= 2; i--) {
            if (substr(rest, i, 1) == "-" && substr(rest, i+1, 1) ~ /[0-9]/) {
                pn = substr(rest, 1, i-1); pvr = substr(rest, i+1); break
            }
        }
        sub(/-r0$/, "", pvr)
        printf "%s\t%s\t%s\n", pn, pvr, cat
    }'
    printf '%s\t%s\t%s\n' "$WRAPPER_PKG" "$WRAPPER_VER" "$WRAPPER_CAT"
}

_cmd_list() {
    local pattern="${1:-}"
    local -a names vers cats
    local name ver cat w_name=4 w_ver=7

    while IFS=$'\t' read -r name ver cat; do
        [[ -z "$name" ]] && continue
        if [[ -n "$pattern" ]]; then
            [[ "$name" == $pattern || "${name}:${WRAPPER_ARCH}" == $pattern ]] || continue
        fi
        names+=("$name"); vers+=("$ver"); cats+=("$cat")
        local dn="${name}:${WRAPPER_ARCH}"
        (( ${#dn}  > w_name )) && w_name=${#dn}
        (( ${#ver} > w_ver  )) && w_ver=${#ver}
    done < <(_portage_packages)

    _rep() { printf "%${2}s" | tr ' ' "${1}"; }

    printf 'Desired=Unknown/Install/Remove/Purge/Hold\n'
    printf '| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n'
    printf '|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n'
    printf "||/ %-${w_name}s %-${w_ver}s %-12s %s\n" "Name" "Version" "Architecture" "Description"
    printf '+++-%s-%s-%s-%s\n' "$(_rep = "$w_name")" "$(_rep = "$w_ver")" "$(_rep = 12)" "$(_rep = 50)"

    local i desc
    for (( i = 0; i < ${#names[@]}; i++ )); do
        local dn="${names[$i]}:${WRAPPER_ARCH}"
        [[ "${names[$i]}" == "$WRAPPER_PKG" ]] && desc="$WRAPPER_DESC" \
            || desc="Gentoo ${cats[$i]}/${names[$i]}"
        printf "ii  %-${w_name}s %-${w_ver}s %-12s %s\n" "$dn" "${vers[$i]}" "$WRAPPER_ARCH" "$desc"
    done
}

main() {
    (( $# == 0 )) && { printf 'Usage: dpkg ACTION [OPTIONS]\n' >&2; return 1; }
    local cmd="$1"; shift
    case "$cmd" in
        -l|--list)           _cmd_list "${1:-}" ;;
        -r|--remove|--purge) printf 'dpkg: package removal via dpkg is disabled. Use emerge --unmerge.\n' >&2; return 1 ;;
        --purge)             printf 'dpkg: package removal via dpkg is disabled. Use emerge --unmerge.\n' >&2; return 1 ;;
        -i|--install)        printf 'dpkg: .deb installation not supported on Gentoo. Use emerge.\n' >&2; return 1 ;;
        --configure|-a)      return 0 ;;
        -p|--print-architecture) printf '%s\n' "$WRAPPER_ARCH" ;;
        --version)           printf 'Gentoo dpkg wrapper %s (NinjaOne/Portage compatibility)\n' "$WRAPPER_VER" ;;
        *)                   printf 'dpkg: unsupported action: %s\n' "$cmd" >&2; return 1 ;;
    esac
}

main "$@"
