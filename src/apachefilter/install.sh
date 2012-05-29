#!/bin/sh
# Install script for the aselect filter

APXS=/opt/anoigo/am/apache/bin/apxs
SRC="mod_aselect_filter.c asf_common.c"
OBJ="mod_aselect_filter.so"

LAST_VERSION=`cat filter_version`
#echo -n 'Enter version number: '
#read LAST_VERSION
#case $LAST_VERSION in
#'') exec echo No number given;
#esac
sed -i -e "/subversion_[0-9]*/s//subversion_${LAST_VERSION}/" src/mod_aselect_filter.c

case $@ in
''|apache20)
    cd src
    $APXS -i -a -c $SRC
    cd ..
    echo Version=$LAST_VERSION
    ;;
clean)
    rm -f src/*.o src/*.so
    ;;
*)
    cat << EOF
Usage: ./install.sh apache20|clean

apache20     compile & install the filter for Apache 2.0.x
clean        remove generated object files after compile

EOF
    ;;
esac
