#!/bin/bash
workdir=$(cd $(dirname $0); pwd)
cd $workdir
#test help
./unimrcptool.sh
#test Err
./unimrcptool.sh synth2 nlsmsc0 siqi example.txt example.wav
./unimrcptool.sh synth nlsmsc02 siqi example.txt example.wav
./unimrcptool.sh synth nlsmsc0 siqi example2.txt example.wav
./unimrcptool.sh synth nlsmsc0 siqi example.txt example.wav2
#test Suc
./unimrcptool.sh synth nlsmsc0 siqi example.txt example.wav
