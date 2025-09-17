#!/bin/bash
net_bandwidths=("1Gbps" "500Mbps" "100Mbps" "50Mbps" "10Mbps" "5Mbps")
net_configs=("wan1" "wan2" "wan3" "wan4" "wan5" "wan6")
threads=(1 8)
securities=(0 1)
sec_names=("sh" "mal")
libote_sec_opt=("" "-mal")

echo "///////////////////////////" > libote_$1.txt
n_nets=${#net_bandwidths[@]}
for t in "${threads[@]}"
do
    for s in "${securities[@]}"
    do
        for (( i=0; i<n_nets; i++))
        do
            echo "[------ ${net_bandwidths[i]} $t-thread ${sec_names[$s]} ------]" >> libote_$1.txt
            if [ "$1" = "0" ]; then
                echo "Deleting old OT data, throttle network..."
                ./throttle.sh ${net_configs[i]}
            fi
            # NOTE: Update below to your libOTe path
            ./libOTe/out/build/linux/frontend/frontend_libOTe -t $t -n 10000000 -Silent ${libote_sec_opt[$s]} -multType 8 -r $1 >> libote_$1.txt
            sleep 3;
        done
    done
done