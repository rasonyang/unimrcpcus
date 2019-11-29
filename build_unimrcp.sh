#!/bin/sh
CUR_DIR=`pwd`
cd `dirname $0`

UniMRCP_HOME=${INSTALL_HOME}/unimrcp
APR_HOME=${INSTALL_HOME}/unimrcp-deps/apr
SOFIA_HOME=${INSTALL_HOME}/unimrcp-deps

rm -fr $UniMRCP_HOME

./bootstrap
./configure --prefix=$UniMRCP_HOME --with-apr=$APR_HOME --with-apr-util=$APR_HOME --with-sofia-sip=$SOFIA_HOME
gmake
gmake install



sh platforms/unimrcp-clientcus/package.sh


cd $CUR_DIR

