# Dory
This repo contains a POC implementation of Dory in our submission to IEEE Security & Privacy 2026.

It extends the [emp-ot](https://github.com/emp-toolkit/emp-ot.git) library.

## Compiling

```
wget https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/scripts/install.py
python install.py --install --tool
# Add `-DCMAKE_INSTALL_PREFIX=/PATH/TO/YOUR/LOCAL/DIR` to `cmake` if you need to install to a custom location
cmake .
make -j4
```

## Run Experiments
We assemble experiments in the script `run_dory.sh`
```
# Run Alice
./run_dory.sh 1
# Run Bob
./run_dory.sh 2
```

If we just want to test a single case, the major command looks like:
```
./bin/test_dory [party] [port] [log(OT num)] [threads] [LPN param idx] [is malicious?]
```

For example, use port `12345`, generate `2^20` OTs, use 8 threads, use LPN param 1, with malicious security:
```
# ALICE
./bin/test_dory 1 12345 20 8 1 1
# BOB
./bin/test_dory 2 12345 20 8 1 1
```

