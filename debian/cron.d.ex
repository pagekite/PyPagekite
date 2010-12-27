#
# Regular cron jobs for the pagekite package
#
0 4	* * *	root	[ -x /usr/bin/pagekite_maintenance ] && /usr/bin/pagekite_maintenance
