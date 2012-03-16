set -x
autopoint 
aclocal
autoheader
automake --add-missing
autoconf
