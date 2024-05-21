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
import copy

import input_gen_module as igm

def precompile_runtimes(args):
    print('Precompiling runtimes...')
    args.input_gen_runtime = precompile_runtime(args.input_gen_runtime, args.g, args.verbose)
    args.input_run_runtime = precompile_runtime(args.input_run_runtime, args.g, args.verbose)
    print('Done.')

def precompile_runtime(fname, debug, verbose):
    if (fname.endswith('.c') or
        fname.endswith('.cpp') or
        fname.endswith('.cxx')):

        obj = fname + '.o'
        compargs = 'clang++ -Wall -std=c++17 -c'.split(' ') + [fname, '-o', obj]
        if debug:
            compargs.append('-O0')
            compargs.append('-g')
        else:
            compargs.append('-O3')
            compargs.append('-DNDEBUG')

        if verbose:
            print('Comp args:', ' '.join(compargs))

        subprocess.run(
            compargs,
            check=True)
        return obj
    else:
        return fname

def pretty_print_statistics(results):
    print('{')
    print('"Module-wise":')
    print('[')
    for res in results:
        print('{},'.format(res))
    print('],')

    langs = list({res['language'] for res in results})

    print('"Language-wise":')
    print('{')
    for lang in langs:
        print('"{}":'.format(lang))
        filt = [res['stats'] for res in results if res['language'] == lang]
        agg_stats = aggregate_statistics(filt)
        print('{{"num": {}, "stats": {}}},'.format(len(filt), agg_stats))
    print('},')

    print('"All":')
    all_stats = [res['stats'] for res in results]
    agg_stats = aggregate_statistics(all_stats)
    print('{{"num": {}, "stats": {}}},'.format(len(all_stats), agg_stats))
    print('}')

def aggregate_statistics(stats):
    empty = igm.get_empty_statistics()
    agg_stats = functools.reduce(
        igm.add_statistics, stats, empty)
    return agg_stats

def handle_single_module_i(i):
    ds_i = ds.skip(i)
    row = list(ds_i.take(1))[0]
    module = row['content']
    language = row['language']
    return {'idx': i, 'language': language, 'stats': igm.handle_single_module((i, module), args)}

def note_down_configuration(args):
    conf = {}
    env = os.environ.copy()

    env_vars_to_note_down = ['INPUT_GEN_PTR_CMP_RETRY']

    conf['env'] = {}
    for var in env_vars_to_note_down:
        if var in env:
            conf['env'][var] = env[var]
        else:
            conf['env'][var] = None
    script_dir = os.path.dirname(os.path.realpath(__file__))
    conf['script_version'] = subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD'], cwd=script_dir).decode('ascii').strip()
    conf['input_gen_version'] = subprocess.check_output(['input-gen', '--version']).decode('ascii')
    conf['args'] = copy.deepcopy(args)
    return conf

def add_option_args(parser):
    parser.add_argument('--dataset', default='llvm-ml/ComPile')
    parser.add_argument('--outdir', required=True)

    parser.add_argument('--start', type=int, default=0)
    parser.add_argument('--end', type=int, default=10)
    # Number of cores available by default
    parser.add_argument('--num-procs', type=int, default=None)

    parser.add_argument('--precompile-rts', action='store_true')
    parser.add_argument('--no-precompile-rts',
                        dest='precompile_rts', action='store_false')
    parser.set_defaults(precompile_rts=True)
    parser.add_argument('--get-jug-results', action='store_true')

    igm.add_option_args(parser)

if __name__ == '__main__':
    parser = argparse.ArgumentParser('MassInputGen')
    add_option_args(parser)
    args = parser.parse_args()

    if args.precompile_rts:
        precompile_runtimes(args)

    ds = load_dataset(args.dataset, split='train', streaming=True)

    os.makedirs(args.outdir, exist_ok=True)

    print('Will input gen for dataset {} in {}'.format(args.dataset, args.outdir))

    global_outdir = args.outdir
    igm_args = vars(args)
    with multiprocessing.Pool(args.num_procs) as pool:
        tasks = range(args.start, args.end)
        stats = pool.imap(handle_single_module_i, tasks, chunksize=1)
        stats = list(stats)
        pretty_print_statistics(stats)
