#!/bin/bash                                                                                                                                                                                                                              
# /usr/local/bin/dpkg-query
#
# NinjaOne agent compatibility wrapper for Gentoo Linux.
# Translates dpkg-query calls against the Portage package database.
#
# The agent calls:
#   dpkg-query -W --showformat='${binary:Package}\t${Version}\tINSTALLDATE_TEMPLATE\t${source:Package}\tdpkg\n'
#
# Requires: app-portage/portage-utils (qlist)

  readonly WRAPPER_PKG="a-gentoo-dpkg-wrapper"
  readonly WRAPPER_VER="1.0.0"
  readonly WRAPPER_ARCH="amd64"
  readonly WRAPPER_DESC="Portage-to-dpkg compatibility wrapper: lists Gentoo packages in dpkg format"
  readonly WRAPPER_CAT="gentoo-meta"

  # ---------------------------------------------------------------------------
  # Emit all installed packages as TAB-separated: name TAB version TAB category
  # Single awk pass — no per-line subprocesses.
  # ---------------------------------------------------------------------------
  _portage_packages() {
      qlist -IRv 2>/dev/null | awk '
      {
          sub(/::.*$/, "")
          n = split($0, p, "/")
          cat  = p[1]
          rest = p[2]
          pn   = rest
          pvr  = ""
          for (i = length(rest); i >= 2; i--) {
              if (substr(rest, i, 1) == "-" && substr(rest, i+1, 1) ~ /[0-9]/) {
                  pn  = substr(rest, 1, i-1)
                  pvr = substr(rest, i+1)
                  break
              }
          }
          sub(/-r0$/, "", pvr)
          printf "%s\t%s\t%s\n", pn, pvr, cat
      }'
      printf '%s\t%s\t%s\n' "$WRAPPER_PKG" "$WRAPPER_VER" "$WRAPPER_CAT"
  }

  # ---------------------------------------------------------------------------
  # dpkg-query -W [--showformat=...] [package]
  #
  # Outputs one line per package in the format NinjaOne expects:
  #   name:arch  TAB  version  TAB  INSTALLDATE_TEMPLATE  TAB  source  TAB  dpkg
  #
  # The showformat argument is accepted but ignored — we always emit the five
  # fields NinjaOne needs regardless, because any other showformat the agent
  # might use in future will still get parseable tabular data.
  # ---------------------------------------------------------------------------
  _cmd_show() {
      local filter=""

      # Parse args: absorb -W, --showformat=..., -f=...; last bare word is filter
      while (( $# > 0 )); do
          case "$1" in
              -W|--show) ;;
              --showformat=*|-f=*|--showformat|-f)
                  # Consume showformat value (with or without =)
                  [[ "$1" == *=* ]] || shift
                  ;;
              --*)  ;;          # ignore other long opts
              -*)   ;;          # ignore other short opts
              *)    filter="$1" ;;
          esac
          shift
      done

      local name ver cat
      while IFS=$'\t' read -r name ver cat; do
          [[ -z "$name" ]] && continue
          if [[ -n "$filter" ]]; then
              # Accept filter with or without :arch suffix
              local bare="${filter%:*}"
              [[ "$name" == "$bare" || "$name" == "$filter" ]] || continue
          fi
          printf '%s:%s\t%s\tINSTALLDATE_TEMPLATE\t%s\tdpkg\n' \
              "$name" "$WRAPPER_ARCH" "$ver" "$cat"
      done < <(_portage_packages)
  }

  # ---------------------------------------------------------------------------
  # dpkg-query -s <package>  (status block)
  # ---------------------------------------------------------------------------
  _cmd_status() {
      local pkg="${1%:*}"   # strip :arch suffix
      [[ -z "$pkg" ]] && { printf 'dpkg-query: --status needs a package name\n' >&2; return 1; }

      if [[ "$pkg" == "$WRAPPER_PKG" ]]; then
          printf 'Package: %s\nStatus: install ok installed\nPriority: optional\n' "$WRAPPER_PKG"
          printf 'Section: %s\nInstalled-Size: 1\n' "$WRAPPER_CAT"
          printf 'Maintainer: Gentoo System <root@localhost>\n'
          printf 'Architecture: %s\nVersion: %s\nDescription: %s\n' \
              "$WRAPPER_ARCH" "$WRAPPER_VER" "$WRAPPER_DESC"
          return 0
      fi

      local name ver cat found=0
      while IFS=$'\t' read -r name ver cat; do
          [[ "$name" == "$pkg" ]] || continue
          found=1
          printf 'Package: %s\nStatus: install ok installed\nPriority: optional\n' "$name"
          printf 'Section: %s\nInstalled-Size: unknown\n' "$cat"
          printf 'Maintainer: Gentoo Portage <portage@gentoo.org>\n'
          printf 'Architecture: %s\nSource: %s\nVersion: %s\n' "$WRAPPER_ARCH" "$cat" "$ver"
          printf 'Description: Gentoo %s/%s\n' "$cat" "$name"
          break
      done < <(_portage_packages)

      (( found == 0 )) && {
          printf "dpkg-query: package '%s' is not installed and no information is available\n" "$pkg" >&2
          return 1
      }
  }

  # ---------------------------------------------------------------------------
  # dpkg-query -l [pattern]  (same table as dpkg -l)
  # ---------------------------------------------------------------------------
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
          if [[ "${names[$i]}" == "$WRAPPER_PKG" ]]; then
              desc="$WRAPPER_DESC"
          else
              desc="Gentoo ${cats[$i]}/${names[$i]}"
          fi
          printf "ii  %-${w_name}s %-${w_ver}s %-12s %s\n" "$dn" "${vers[$i]}" "$WRAPPER_ARCH" "$desc"
      done
  }

  # ---------------------------------------------------------------------------
  # Main
  # ---------------------------------------------------------------------------
  main() {
      (( $# == 0 )) && { printf 'dpkg-query: need an action option\n' >&2; return 1; }

      local cmd="$1"; shift
      case "$cmd" in
          -W|--show)          _cmd_show "$@" ;;
          -s|--status)        _cmd_status "${1:-}" ;;
          -l|--list)          _cmd_list "${1:-}" ;;
          --print-architecture|-p) printf '%s\n' "$WRAPPER_ARCH" ;;
          --version)
              printf 'Gentoo dpkg-query wrapper %s (NinjaOne/Portage compatibility)\n' "$WRAPPER_VER" ;;
          *)
              # Forward unknown flags to -W (agent might call dpkg-query -W directly)
              _cmd_show "$cmd" "$@" ;;
      esac
  }

  main "$@"
