#!/bin/bash
net_bandwidths=("1Gbps" "500Mbps" "100Mbps" "50Mbps" "10Mbps" "5Mbps")
net_configs=("wan1" "wan2" "wan3" "wan4" "wan5" "wan6")
threads=(1 8)
securities=(0 1)
sec_names=("sh" "mal")

echo "///////////////////////////" > ferret_$1.txt
n_nets=${#net_bandwidths[@]}
for t in "${threads[@]}"
do
    for s in "${securities[@]}"
    do
        for (( i=0; i<n_nets; i++))
        do
            echo "[------ ${net_bandwidths[i]} $t-thread ${sec_names[$s]} ------]" >> ferret_$1.txt
            if [ "$1" = "1" ]; then
                echo "Deleting old OT data, throttle network..."
                rm -f ./data/*
                ../../mal2pc/Scripts/throttle.sh ${net_configs[i]}
            fi
            ./bin/test_ferret $1 12345 20 $t $s >> ferret_$1.txt
            sleep 1;
        done
    done
done