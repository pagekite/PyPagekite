# This is a replacement for the default disttools RPM build method
# which gets the file lists right, including the byte-compiled files.
python setup.py install --root=$RPM_BUILD_ROOT
find $RPM_BUILD_ROOT -type f \
  |sed -e "s|^$RPM_BUILD_ROOT/*|/|" \
       -e 's|/[^/]*$||' \
  |uniq >INSTALLED_FILES
cat INSTALLED_FILES
