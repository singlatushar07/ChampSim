#!/bin/bash
arr=(619 620 621 623 625 627 628 631 638 641 644 648 649 654 657)
for i in ${!arr[@]}; do
echo "./bin/champsim --warmup_instructions 1000000 --simulation_instructions 100000000 ../benchmarks/${arr[$i]}* > ../spec_mirage_${arr[$i]}"
./bin/champsim --warmup_instructions 1000000 --simulation_instructions 100000000 ../benchmarks/${arr[$i]}* > ../spec_mirage_${arr[$i]}
done