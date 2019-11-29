#!/bin/bash
#test help
./unimrcptool.sh
#test Err
./unimrcptool.sh synth2 nlsmsc0 siqi test.txt example.wav
./unimrcptool.sh synth nlsmsc02 siqi test.txt example.wav
./unimrcptool.sh synth nlsmsc0 siqi test2.txt example.wav
./unimrcptool.sh synth nlsmsc0 siqi test.txt example.wav2
#test Suc
./unimrcptool.sh synth nlsmsc0 siqi test.txt example.wav
