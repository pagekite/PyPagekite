
(service pagekite status >/dev/null \
  && service pagekite stop \
  || true)

(chkconfig --del pagekite || true)

# HACK: uninstall config files that have not changed.
cd /etc/pagekite.d/default
for conffile in *; do
  if [ -f "../$conffile" ]; then
    md5org=$(md5sum "$conffile" |awk '{print $1}')
    md5act=$(md5sum "../$conffile" |awk '{print $1}')
    [ "$md5org" = "$md5act" ] && rm -f "../$conffile"
  fi
done
