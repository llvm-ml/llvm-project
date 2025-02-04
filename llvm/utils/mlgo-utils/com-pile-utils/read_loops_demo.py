#!/usr/bin/env python3

import argparse
import os
import json
import subprocess
from datasets import load_dataset

def parse_args_and_run():
    parser = argparse.ArgumentParser(
        description='Reading ComPileLoop'
    )
    parser.add_argument('--dataset', required=True)
    parser.add_argument('--num', default=3, type=int)
    args = parser.parse_args()
    main(args)

def main(args):
    ds = load_dataset(args.dataset, split='train', streaming=True)
    for i, data in enumerate(ds):
        print(f'Processing loop {i}')
        process_module(data)

def process_module(data):
    bitcode_module = data['module']
    del data['module']
    dis_command_vector = ['llvm-dis', '-']
    with subprocess.Popen(
        dis_command_vector,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE) as dis_process:
      output = dis_process.communicate(
          input=bitcode_module)[0].decode('utf-8')
    print(data)
    print(output)

if __name__ == '__main__':
    parse_args_and_run()
