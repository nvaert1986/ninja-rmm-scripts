#!/bin/bash
  # /usr/local/sbin/generate-dpkg-log
  #
  # Generates /var/log/dpkg.log from Portage package directory timestamps.
  # Run once after installing the dpkg-query wrapper, and after large updates.
  # The NinjaOne agent parses this file to populate the "Install date" column.

  DPKG_LOG="/var/log/dpkg.log"
  ARCH="amd64"

  printf 'Generating %s from Portage database...\n' "$DPKG_LOG"

  {
      for pkgdir in /var/db/pkg/*/*/; do
          [[ -d "$pkgdir" ]] || continue

          # Directory name is category/name-version
          cpv="${pkgdir%/}"          # strip trailing slash
          cat="${cpv%/*}"            # .../category
          cat="${cat##*/}"           # category
          namever="${cpv##*/}"       # name-version

          # Split name from version (last hyphen before digit)
          pn="$namever"; pvr=""
          for (( i=${#namever}-1; i>=1; i-- )); do
              c="${namever:$i:1}"
              n="${namever:$((i+1)):1}"
              if [[ "$c" == "-" && "$n" =~ [0-9] ]]; then
                  pn="${namever:0:$i}"
                  pvr="${namever:$((i+1))}"
                  break
              fi
          done
          pvr="${pvr%-r0}"

          # Get install timestamp from directory mtime
          ts=$(stat -c '%Y' "$pkgdir" 2>/dev/null) || continue
          datestamp=$(date -d "@${ts}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null) || continue

          printf '%s install %s:%s <none> %s\n' "$datestamp" "$pn" "$ARCH" "$pvr"
      done
  } | sort > "$DPKG_LOG"

  count=$(wc -l < "$DPKG_LOG")
  printf 'Done: %d package entries written to %s\n' "$count" "$DPKG_LOG"
