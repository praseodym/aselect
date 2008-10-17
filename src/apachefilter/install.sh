#!/bin/sh

# Install script for the A-Select Apache Filter.
# Alfa & Ariss, 2005

APXS=/opt/anoigo/am/apache/bin/apxs
SRC="mod_aselect_filter.c asf_common.c"
OBJ="mod_aselect_filter.so"

case $@ in
apache13)
    cd src
    $APXS -c -DAPACHE_13_ASELECT_FILTER $SRC && \
    $APXS -i -a -n aselect_filter $OBJ
    cd ..
    ;;
''|apache20)
    cd src
    if ( which apxs2 > /dev/null ) ; then APXS=apxs2 ; fi
    $APXS -i -a -c -DAPACHE_20_ASELECT_FILTER $SRC
    cd ..
    ;;
clean)
    rm -f src/*.o src/*.so
    ;;
*)
    cat << EOF
Usage: ./install.sh apache13|apache20|clean

apache13     compile & install the filter for Apache 1.3.x
apache20     compile & install the filter for Apache 2.0.x
clean        remove generated object files after compile

EOF
    ;;
esac
