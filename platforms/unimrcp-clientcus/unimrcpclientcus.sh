#!/bin/bash  $1 $2
textcontent=`cat $1`
./unimrcpclientcus  --run=synth --textfile=${textcontent} --wavfile=$2
sox -t raw -c 1 -e signed-integer -b 16 -r 8000  ${2}pcm ${2}
