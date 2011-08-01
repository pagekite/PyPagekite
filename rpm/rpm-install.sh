# This is a replacement for the default disttools RPM build method
# which gets the file lists right, including the byte-compiled files.
#
# We also process our man-pages here.

python setup.py install --root=$RPM_BUILD_ROOT

for manpage in $(cd doc && echo *.1); do
  mkdir -m 755 -p $RPM_BUILD_ROOT/usr/share/man/man1/
  install -v -m 644 doc/$manpage $RPM_BUILD_ROOT/usr/share/man/man1/
  gzip --verbose $RPM_BUILD_ROOT/usr/share/man/man1/$manpage
done

mkdir -m 755 -p $RPM_BUILD_ROOT/etc/pagekite.d/default
for rcfile in etc/pagekite.d/*; do
  install -v -m 644 $rcfile $RPM_BUILD_ROOT/etc/pagekite.d/default/
done
chmod 600 $RPM_BUILD_ROOT/etc/pagekite.d/default/*account*

find $RPM_BUILD_ROOT -type f \
  |sed -e "s|^$RPM_BUILD_ROOT/*|/|" \
       -e 's|/[^/]*$||' \
  |uniq >INSTALLED_FILES

mkdir -m 755 -p $RPM_BUILD_ROOT/var/log/pagekite
echo /var/log/pagekite >>INSTALLED_FILES

for where in init.d logrotate.d sysconfig; do
  if [ -e etc/$where/pagekite.fedora ]; then
    mkdir -m 755 -p $RPM_BUILD_ROOT/etc/$where
    install -v -m 755 etc/$where/pagekite.fedora $RPM_BUILD_ROOT/etc/$where/pagekite
    echo /etc/$where/pagekite >>INSTALLED_FILES
  fi
done
