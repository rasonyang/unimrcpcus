#!/bin/bash

ErrColor='\033[31m'
InfoColor='\E[1;33m'
EClose='\E[0m'

Err(){
        echo -e "$ErrColor ${1} $EClose"
}

Usage(){
        echo -e $InfoColor
        cat <<EOF
        $0 --h (display help)
        $0 [synth] <profile> <voice> <txtfilepath> <wavfilepath>
                ex: $0 synth nlsmsc0 siqi text.txt example.wav
EOF
        echo -e $EClose
        exit 1
}

if [ $# -ne 5 ];then
        Usage
fi

if [ $1 != "synth" ];then
        Err "[Err] no such run type $1] "
        exit
fi

profile=$2.xml
if [ ! -r ../conf/$profile ];then
        Err "[Err] profile not exist profile "
        exit
fi

if [ ! -r $4 ];then
        Err "[Err] file $4 not exsits "
        exit
fi

wavext=${5##*.}

if [ "wav" != ${wavext} ];then
        Err "[Err] $5 ext format illegal $wavext "
        exit
fi

echo usage $1 $2 $3 $4 $5
pcmfile=${5/wav/pcm}
textcontent=`cat $4`
echo $textcontent

echo "text->pcm"
./unimrcpclientcus  --run=synth --profile=$profile --voice=$3 --text="${textcontent}" --pcmfile=${pcmfile}
echo "pcm->wav"
sox -t raw -c 1 -e signed-integer -b 16 -r 8000  ${pcmfile} ${5}
echo "finish"
exit 1
