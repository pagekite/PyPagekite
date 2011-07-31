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

find $RPM_BUILD_ROOT -type f \
  |sed -e "s|^$RPM_BUILD_ROOT/*|/|" \
       -e 's|/[^/]*$||' \
  |uniq >INSTALLED_FILES
