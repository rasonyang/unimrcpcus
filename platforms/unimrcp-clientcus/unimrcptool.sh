#!/bin/bash

Usage(){
        cat <<EOF
        $0 --h (display help)
        $0 [synth] <txtfilepath> <wavfilepath>
EOF
        exit 1
}

if [ $# -ne 3 ];then
        Usage
fi

if [ $1 != "synth" ];then
        echo "[err] no such run type $1] "
        exit
fi

if [ ! -r $2 ];then
        echo "[err] file $2 not exsits "
        exit
fi

wavext=${3##*.}

if [ "wav" != ${wavext} ];then
        echo "[err] $3 ext format illegal $wavext "
        exit
fi
echo usage $1 $2 $3
pcmfile=${3/wav/pcm}
textcontent=`cat $2`
echo $textcontent

echo "text->pcm"
./unimrcpclientcus  --run=synth --text="${textcontent}" --pcmfile=${pcmfile}
echo "pcm->wav"
sox -t raw -c 1 -e signed-integer -b 16 -r 8000  ${pcmfile} ${3}
echo "finish"
exit 1
