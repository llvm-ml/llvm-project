#!/usr/bin/env python3

import json
import subprocess
import argparse
import os
import sys
import multiprocessing
import functools
from datasets import load_dataset
import jug

import mass_input_gen as mig
import input_gen_module as igm

def handle_single_module_i(i):
    ds_i = ds.skip(i)
    row = list(ds_i.take(1))[0]
    module = row['content']
    language = row['language']
    return {'idx': i, 'language': language, 'stats': igm.handle_single_module((i, module), args)}

def note_down_configuration():
    return mig.note_down_configuration(args)

parser = argparse.ArgumentParser('MassInputGenJug')
mig.add_option_args(parser)
parser.add_argument('--invalidate-instrumentation-failures', action='store_true')
args = parser.parse_args()

configuration = jug.Task(note_down_configuration)

if not args.get_jug_results:

    if args.precompile_rts:
        if args.verbose:
            print('Precompiling runtimes...')
        igr = jug.Task(mig.precompile_runtime, args.input_gen_runtime, args.g, args.verbose)
        irr = jug.Task(mig.precompile_runtime, args.input_run_runtime, args.g, args.verbose)
        jug.barrier()
        if args.verbose:
            print('Done:')
        args.input_gen_runtime = jug.task.value(igr)
        args.input_run_runtime = jug.task.value(irr)
        if args.verbose:
            print(args.input_gen_runtime)
            print(args.input_run_runtime)

    if args.verbose:
        print('Will input gen for dataset {} in {}'.format(args.dataset, args.outdir))
    ds = load_dataset(args.dataset, split='train', streaming=True)
    os.makedirs(args.outdir, exist_ok=True)

tasks = []
for i in range(args.start, args.end):
    tasks.append(jug.Task(handle_single_module_i, i))
