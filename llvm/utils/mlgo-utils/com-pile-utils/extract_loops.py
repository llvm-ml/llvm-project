#!/usr/bin/env python3
# Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
# See https://llvm.org/LICENSE.txt for license information.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Tool for making a corpus of loops from ComPile
"""

import argparse
import os
import tempfile
import subprocess
import json

import pandas
import pyarrow

from pyarrow import parquet
from datasets import load_dataset

def parse_args_and_run():
    parser = argparse.ArgumentParser(
        description='A tool for making a LLVM IR loop dataset'
    )
    parser.add_argument('--dataset', required=True)
    parser.add_argument('--language', default='c')
    parser.add_argument('--save-temps', action='store_true', default=False)
    parser.add_argument('--temp-dir', default=None)
    parser.add_argument('--output-dataset', required=True)
    parser.add_argument('--num', default=3, type=int)
    args = parser.parse_args()
    main(args)

def main(args):
    ds = load_dataset(os.path.join(args.dataset, args.language), split='train', streaming=True)
    os.mkdir(args.output_dataset)
    pfile = os.path.join(args.output_dataset, 'train.parquet')
    dfs = []
    i = 0
    for data in ds:
        module = data['content']
        language = data['language']
        new_df = process_module(module, language, i, pfile, args)
        if new_df is not None:
            dfs.append(new_df)
        i += 1
        if i == args.num:
            break

    df = pandas.concat(dfs)
    table = pyarrow.Table.from_pandas(df, preserve_index=False)
    parquet.write_table(table, pfile, compression='NONE')

def process_module(module, language, idx, pfile, args):
    with tempfile.TemporaryDirectory(dir=args.temp_dir, delete=(not args.save_temps)) as outdir:
        return process_module_in_dir(module, language, idx, outdir, pfile)

def process_module_in_dir(module, language, idx, temp_outdir, output_dataset):
    prefix = str(os.path.join(temp_outdir, 'output.'))
    suffix = '.bc'
    cmd = [
        'llvm-extract-loops',
        '-',
        '--output-prefix', prefix,
        '--output-suffix', suffix,
    ]
    verbose = False
    if verbose:
        print(' '.join(cmd))
    with subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE) as proc:
        output = proc.communicate(
            input=module)[0].decode('utf-8')

    dfs = []
    i = 0
    while True:
        try:
            module_path = prefix + str(i) + suffix
            metadata_path = module_path + '.json'

            module_file = open(module_path, 'br')
            loop_module = module_file.read()
            module_file.close()

            metadata_file = open(metadata_path, 'r')
            data = json.load(metadata_file)
            metadata_file.close()

            data['language_in_compile'] = language
            data['module_idx_in_compile'] = idx
            data['module'] = loop_module

            dfs.append(pandas.DataFrame(data, index=[0]))

        except OSError as e:
            break
        i += 1

    if len(dfs) == 0:
        return None

    return pandas.concat(dfs)

if __name__ == '__main__':
    parse_args_and_run()
