#!/usr/bin/env python3

import ray
import subprocess
import argparse
import os
import sys
import multiprocessing
import functools
from datasets import load_dataset
from ray.util.actor_pool import ActorPool

import input_gen_module

@ray.remote(num_cpus=1)
class ModuleHandler:
    def __init__(self, dataset, global_outdir, igm_args, verbose):
        self.ds = load_dataset(dataset, split='train', streaming=True)
        self.global_outdir = global_outdir
        self.igm_args = igm_args
        self.verbose = verbose
    def handle_single_module(self, i):
        if i % 100 == 0:
            print("Module #{}".format(i))
        ds_i = self.ds.skip(i)
        module = list(ds_i.take(1))[0]

        self.igm_args['outdir'] = os.path.join(self.global_outdir, str(i))
        os.makedirs(self.igm_args['outdir'], exist_ok=True)
        with open(self.igm_args['outdir'] +"/mod.bc", 'wb') as module_file:
            module_file.write(module['content'])
            module_file.flush()
            self.igm_args['input_module'] = module_file.name

            igm = input_gen_module.InputGenModule(**self.igm_args)
            igm.generate_inputs()
            igm.run_all_inputs()

            return igm.get_statistics()

def precompile_runtimes(args):
    print('Precompiling runtimes...')
    args.input_gen_runtime = precompile_runtime(args.input_gen_runtime, args.g)
    args.input_run_runtime = precompile_runtime(args.input_run_runtime, args.g)
    print('Done.')

def precompile_runtime(fname, debug):
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

        if args.verbose:
            print('Comp args:', ' '.join(compargs))

        subprocess.run(
            compargs,
            check=True)
        return obj
    else:
        return fname

def handle_single_module(task):
    (i, module) = task

    igm_args['outdir'] = os.path.join(global_outdir, str(i))
    os.makedirs(igm_args['outdir'], exist_ok=True)
    with open(igm_args['outdir'] +"/mod.bc", 'wb') as module_file:
        module_file.write(module['content'])
        module_file.flush()
        igm_args['input_module'] = module_file.name

        igm = input_gen_module.InputGenModule(**igm_args)
        igm.generate_inputs()
        igm.run_all_inputs()

        return igm.get_statistics()

def pretty_print_statistics(stats):
    print('Module statistics:')

    for k, v in stats:
        print(k, v)

if __name__ == '__main__':
    parser = argparse.ArgumentParser('MassInputGen')

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
    parser.add_argument('--use-ray', action='store_true')

    input_gen_module.add_option_args(parser)

    args = parser.parse_args()

    if args.precompile_rts:
        precompile_runtimes(args)

    if args.use_ray:

        ray.init()

        resources = ray.cluster_resources()
        print("Resources:", ray.cluster_resources())

        if args.num_procs is None:
            args.num_procs = int(resources['CPU'])
        else:
            print("WARNING SETTING NUM PROCS WHEN USING RAY NOT RECOMMENDED")
        igm_args = vars(args)
        actors = []
        global_outdir = args.outdir
        igm_args = vars(args)
        for _ in range(args.num_procs):
            actors.append(ModuleHandler.remote(args.dataset, global_outdir, igm_args, args.verbose))
        pool = ActorPool(actors)
        stats = list(pool.map(lambda a, v: a.handle_single_module.remote(v), range(args.start, args.end)))

        empty = input_gen_module.InputGenModule().get_empty_statistics()
        agg_stats = functools.reduce(
            input_gen_module.InputGenModule().add_statistics, stats, empty)

        pretty_print_statistics(list(zip(range(args.start, args.end), stats)))

        print('Statistics: {}'.format(agg_stats))

    else:
        ds = load_dataset(args.dataset, split='train', streaming=True)

        os.makedirs(args.outdir, exist_ok=True)

        print('Will input gen for dataset {} in {}'.format(args.dataset, args.outdir))

        global_outdir = args.outdir
        igm_args = vars(args)

        ds = ds.skip(args.start)
        with multiprocessing.Pool(args.num_procs) as pool:
            tasks = list(zip(range(args.start, args.end), ds))
            stats = pool.imap(handle_single_module, tasks, chunksize=1)
            empty = input_gen_module.InputGenModule().get_empty_statistics()
            stats = list(stats)
            agg_stats = functools.reduce(
                input_gen_module.InputGenModule().add_statistics, stats, empty)

            pretty_print_statistics(list(zip(range(args.start, args.end), stats)))

            print('Statistics: {}'.format(agg_stats))
