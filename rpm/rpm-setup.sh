#!/bin/bash
cat <<tac >setup.cfg
[install]
prefix=/usr
install_lib=$2
single_version_externally_managed=yes

[bdist_rpm]
release=$1
vendor=PageKite Packaging Team <packages@pagekite.net>
tac
