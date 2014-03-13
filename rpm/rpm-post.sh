# HACK: Enable default config files, without overwriting.
cd /etc/pagekite.d/default
for conffile in *; do
  [ -e ../$conffile ] || cp -a $conffile ..
done

# Make sure PageKite is restarted if necessary
chkconfig --add pagekite || true
service pagekite status && service pagekite restart

