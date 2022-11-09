#!/bin/bash
arr=("astar" "bwaves" "bzip2" "cactusADM" "calculix" "gamess" "gcc" "gobmk" "gromacs" "h264" "hmmer")
for i in ${!arr[@]}; do
echo "./bin/champsim --warmup_instructions 100000000 --simulation_instructions 1000000000 ../benchmarks/${arr[$i]}* > ../spec_mirage_${arr[$i]}"
./bin/champsim --warmup_instructions 100000000 --simulation_instructions 1000000000 ../benchmarks/${arr[$i]}* > ../spec_mirage_${arr[$i]}
done