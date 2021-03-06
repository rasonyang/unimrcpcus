#!/bin/bash

workdir=$(cd $(dirname $0); pwd)
cd ${workdir}

ErrColor='\033[31m'
InfoColor='\E[1;33m'
EClose='\E[0m'


Err(){
        echo -e "$ErrColor $@ $EClose"
        dates=`date '+%Y-%m-%d %H:%M:%S' `
        dated=${dates:0:10}
        echo $dates [$$] $@ >> ../log/unimrcptool_err_${dated}.log
}

Info(){
        echo -e "$InfoColor $@ $EClose"
        dates=`date '+%Y-%m-%d %H:%M:%S' `
        dated=${dates:0:10}
        echo $dates [$$] $@ >> ../log/unimrcptool_info_${dated}.log
}


Usage(){
        echo -e $InfoColor
        cat <<EOF
        $0 --h (display help)
        $0 [synth] <profile> <voice> <txtfilepath> <wavfilepath>
                ex: $0 synth nlsmsc0 siqi example.txt example.wav
EOF
        echo -e $EClose
        exit -1
}

if [ $# -ne 5 ];then
        Usage
fi

if [ $1 != "synth" ];then
        Err "[Err] no such run type $1] "
        exit -1
fi

profile=$2.xml
if [ ! -r ../conf/$profile ];then
        Err "[Err] profile not exist profile $profile"
        exit -1
fi

if [ ! -r $4 ];then
        Err "[Err] file $4 not exsits "
        exit -1
fi

wavext=${5##*.}

if [ "wav" != ${wavext} ];then
        Err "[Err] $5 ext format illegal $wavext "
        exit -1
fi

Info "$@"
pcmfile=${5/wav/pcm}
textcontent=`cat $4`
Info $textcontent

Info "text->pcm"
./unimrcpclientcus  --run=synth --profile=$profile --voice=$3 --text="${textcontent}" --pcmfile=${pcmfile}
Info "pcm->wav"
sox -t raw -c 1 -e signed-integer -b 16 -r 8000  ${pcmfile} ${5}
if [ ! -r ${5} ];then
        Err "${5} make failed..."
        exit -1
fi
Info "finish"
exit 0
