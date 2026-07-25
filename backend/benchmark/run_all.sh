#!/bin/bash
sudo mn -c 2>/dev/null
sleep 1
cd /home/fyp2025/fyp/backend/benchmark
export PYTHONPATH=/home/fyp2025/fyp/backend/benchmark
/home/fyp2025/fyp/backend/benchmark/benchmarkenv/bin/python3 -u benchmark_runner.py > /home/fyp2025/fyp/backend/benchmark/results/master_runner.log 2>&1
