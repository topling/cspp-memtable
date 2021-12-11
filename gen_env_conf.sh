#!/bin/bash
#set -x

CXX=$1
COMPILER=$2
EnvConf=$3
echo COMPILER=$COMPILER 1>&2

#EnvConf=Make.env.conf-${COMPILER}

rm -f $EnvConf
mkdir -p `dirname $EnvConf`

cat > is_cygwin.cpp << "EOF"
#include <stdio.h>
int main() {
  #ifdef __CYGWIN__
    printf("1");
  #else
    printf("0");
  #endif
    return 0;
}
EOF
if $CXX is_cygwin.cpp -o is_cygwin.exe; then
	IS_CYGWIN=`./is_cygwin.exe`
	echo IS_CYGWIN=$IS_CYGWIN >> $EnvConf
fi
rm -f is_cygwin.*

if [ "$IS_CYGWIN" -eq 1 ]; then
	rm -f a.exe
else
	rm -f a.out
fi

