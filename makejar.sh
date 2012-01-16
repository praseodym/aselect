#!/bin/sh
#
# Author: Bauke Hiemstra - www.anoigo.nl
#
JAR="/cygdrive/c/Program Files (x86)/Java/jdk1.6.0_16/bin/jar.exe"
WORK_HOME=/cygdrive/e/Eclipse

TARGET_DIR=$WORK_HOME/jars
if test ! -d $TARGET_DIR
then mkdir $TARGET_DIR
fi
BIN_DIR=$WORK_HOME/aselect/bin
SOURCE_DIR=$WORK_HOME/aselect/src
HERE=`pwd`

cd $SOURCE_DIR
echo "Make $1, Source in $SOURCE_DIR, Jars to $TARGET_DIR"

PROP_FILES=`find . -name all-wcprops`
LAST_VERSION=`grep '!svn' $PROP_FILES | \
	sed -e '/.*!svn\/ver\//s///' -e '/\/.*/s///' | \
	sort -r -n | head -1`
VERSION_FILE=subversion_$LAST_VERSION

cd $BIN_DIR
echo PWD=`pwd`
echo $LAST_VERSION >$VERSION_FILE
echo LAST_VERSION=$LAST_VERSION
echo Commit first to get the correct version number for a production war-file

case ''$1 in
lb*)
	"$JAR" cmf ../META-INF/MANIFEST.lbsensor.MF \
			org.aselect.lbsensor.jar $VERSION_FILE org/aselect/lbsensor
	mv org.aselect.lbsensor.jar $TARGET_DIR
	cd $HERE; ./makejar.sh system
	;;
agent)
	"$JAR" cmf ../META-INF/MANIFEST.MF \
			org.aselect.agent.jar $VERSION_FILE org/aselect/agent
	mv org.aselect.agent.jar $TARGET_DIR
	cd $HERE; ./makejar.sh system
	;;
server*)
	"$JAR" cf org.aselect.server.jar $VERSION_FILE org/aselect/server
	mv org.aselect.server.jar "$TARGET_DIR"
	"$JAR" cf org.aselect.authspserver.jar $VERSION_FILE org/aselect/authspserver
	mv org.aselect.authspserver.jar $TARGET_DIR/org.aselect.authspserver.jar
	cd $HERE; ./makejar.sh system
	;;
system)
	"$JAR" cf org.aselect.system.jar $VERSION_FILE org/aselect/system
	mv org.aselect.system.jar "$TARGET_DIR"
	;;
all)
	cd $HERE
	./makejar.sh agent
	./makejar.sh server
	./makejar.sh lbsensor
	;;
*)	echo "Usage: `basename $0` all|agent|server|system|lbsensor"
	rm -f $VERSION_FILE
	exit;;
esac
rm -f $VERSION_FILE
