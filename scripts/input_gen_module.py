#!/usr/bin/env python3

import tempfile
import subprocess
import argparse
import os
import sys
import time
import json
import copy
import json
from itertools import zip_longest

def add_option_args(parser):
    parser.add_argument('--input-gen-num', type=int, default=1)
    parser.add_argument('--input-gen-num-retries', type=int, default=5)
    parser.add_argument('--input-gen-timeout', type=int, default=5)
    parser.add_argument('--input-run-timeout', type=int, default=5)
    # TODO Pass in an object files here so as not to compile the cpp every time
    parser.add_argument('--input-gen-runtime', default='./input-gen-runtimes/rt-input-gen.cpp')
    parser.add_argument('--input-run-runtime', default='./input-gen-runtimes/rt-run.cpp')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--no-verbose', dest='verbose', action='store_false')
    parser.add_argument('-g', action='store_true')
    parser.set_defaults(verbose=False)
    parser.add_argument('--cleanup', action='store_true')
    parser.add_argument('--coverage-statistics', action='store_true')
    parser.add_argument('--coverage-runtime')

class Function:
    def __init__(self, name, ident, verbose, coverage_statistics):
        self.name = name
        self.ident = ident
        self.verbose = verbose
        self.input_gen_executable = None
        self.input_run_executable = None
        self.inputs_dir = None
        self.tried_seeds = []
        self.succeeded_seeds = []
        self.inputs = []
        self.times = {}
        self.coverage_statistics = coverage_statistics
        self.profile_files = {}

    def get_stderr(self):
        if self.verbose:
            return None
        else:
            return subprocess.DEVNULL

    def get_stdout(self):
        if self.verbose:
            return None
        else:
            return subprocess.DEVNULL

    def run_all_inputs(self, timeout, available_functions_file_name):
        for inpt in self.inputs:
            self.run_input(inpt, timeout, available_functions_file_name)

    def print(self, *args, **kwargs):
        if self.verbose:
            print(*args, **kwargs)

    def run_input(self, inpt, timeout, available_functions_file_name):
        self.print('Running executables for', self.input_run_executable)

        try:
            start_time = time.time()
            igrunargs = [
                    self.input_run_executable,
                    inpt,
                    '--file',
                    available_functions_file_name,
                    self.ident,
                ]
            if self.coverage_statistics:
                env = os.environ.copy()
                profdatafile = os.path.join(self.inputs_dir, inpt + '.profdata')
                env['LLVM_PROFILE_FILE'] = profdatafile
            else:
                env = None
            proc = subprocess.Popen(
                igrunargs,
                stdout=self.get_stdout(),
                stderr=self.get_stderr(),
                env=env)

            self.print('ig args run:', ' '.join(igrunargs))
            out, err = proc.communicate(timeout=timeout)

            end_time = time.time()
            elapsed_time = end_time - start_time

            if proc.returncode != 0:
                self.print('Input run process failed (%i): %s' % (proc.returncode, inpt))
            else:
                if self.coverage_statistics:
                    self.profile_files[inpt] = profdatafile
                if inpt not in self.times:
                    self.times[inpt] = []
                self.times[inpt].append(elapsed_time)

        except subprocess.CalledProcessError as e:
            self.print('Input run process failed: %s' % inpt)
        except subprocess.TimeoutExpired as e:
            self.print("Input run timed out! Terminating... %s" % inpt)
            proc.terminate()
            try:
                proc.communicate(timeout=1)
            except subprocess.TimeoutExpired as e:
                self.print("Termination timed out! Killing... %s" % inpt)
                proc.kill()
                proc.communicate()
                self.print("Killed.")

def my_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return a + b

def aggregate_statistics(stats, to_add):
    for k, v in stats.items():
        if isinstance(to_add[k], list):
            stats[k] = [my_add(a, b) for a, b in zip_longest(to_add[k], stats[k])]
        elif to_add[k] is not None:
            stats[k] = my_add(stats[k], to_add[k])

def add_statistics(a, b):
    c = get_empty_statistics()
    aggregate_statistics(c, a)
    aggregate_statistics(c, b)
    return c

def get_empty_statistics():
    stats = {
        'num_funcs': 0,
        'num_instrumented_funcs': 0,
        'num_input_generated_funcs': 0,
        'num_input_ran_funcs': 0,
        'num_bbs': None,
        'num_bbs_executed': [],
    }
    return stats

class InputGenModule:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)
        self.functions = []

        if kwargs['coverage_statistics'] and not kwargs['coverage_runtime']:
            self.print_err('Must specify coverage runtime when requesting coverage statistics')

    def print(self, *args, **kwargs):
        if self.verbose:
            print(*args, **kwargs)

    def print_err(self, *args, **kwargs):
        print(*args, **kwargs, file=sys.stderr)

    def get_stderr(self):
        if self.verbose:
            return None
        else:
            return subprocess.DEVNULL

    def get_stdout(self):
        if self.verbose:
            return None
        else:
            return subprocess.DEVNULL

    def generate_inputs(self):

        if self.cleanup:
            self.tempdir = tempfile.TemporaryDirectory(dir=self.outdir)
            self.outdir = self.tempdir.name

        try:
            self.generate_inputs_impl()
        except Exception as e:
            # Exception here means that something very wrong (killed by oom etc)
            # happened and we should retry
            self.print_err('Generating inputgen executables for', self.input_module, 'in', self.outdir, 'FAILED, to retry')
            raise e

    def cleanup_outdir(self):
        if self.cleanup:
            assert(self.tempdir is not None)
            self.tempdir.cleanup()

    def generate_inputs_impl(self):

        os.makedirs(self.outdir, exist_ok=True)

        self.print('Generating inputgen executables for', self.input_module, 'in', self.outdir)

        instrumentation_failed = False
        try:

            igargs = [
                'input-gen',
                '--input-gen-runtime', self.input_gen_runtime,
                '--input-run-runtime', self.input_run_runtime,
                '--output-dir', self.outdir,
                self.input_module,
                '--compile-input-gen-executables',
            ]
            if self.g:
                igargs.append('-g')
            if self.coverage_statistics:
                igargs.append('--instrumented-module-for-coverage')
                igargs.append('--profiling-runtime-path')
                igargs.append(self.coverage_runtime)

            self.print("input-gen args:", " ".join(igargs))
            subprocess.run(igargs,
                           check=True,
                           stdout=self.get_stdout(),
                           stderr=self.get_stderr())
        except:
            self.print('Failed to instrument')
            instrumentation_failed = True

        self.available_functions_file_name = os.path.join(self.outdir, 'available_functions')
        try:
            available_functions_file = open(self.available_functions_file_name, 'r')
        except IOError as e:
            self.print("Could not open available functions file:", e)
            self.print("input-gen args:", " ".join(igargs))
            raise e
        else:
            zerosplit = available_functions_file.read().split('\0')
            fids = zerosplit[0:-1:2]
            fnames = zerosplit[1::2]
            for (fid, fname) in zip(fids, fnames, strict=True):
                func = Function(fname, fid, self.verbose, self.coverage_statistics)
                self.functions.append(func)

                if instrumentation_failed:
                    continue

                input_gen_executable = os.path.join(
                    self.outdir, 'input-gen.module.generate.a.out')
                input_run_executable = os.path.join(
                    self.outdir, 'input-gen.module.run.a.out')
                inputs_dir = os.path.join(self.outdir, 'input-gen.' + fid + '.inputs')

                if not os.path.isfile(input_gen_executable):
                    continue
                if not os.path.isfile(input_run_executable):
                    continue

                # Only attach these to the Function if they exist
                os.makedirs(inputs_dir, exist_ok=True)
                func.input_run_executable = input_run_executable
                func.input_gen_executable = input_gen_executable
                func.inputs_dir = inputs_dir

                self.print('Generating inputs for function {} @{}'.format(fid, fname))

                seed = 0
                for _ in range(self.input_gen_num):
                    for _ in range(self.input_gen_num_retries):
                        func.tried_seeds.append(seed)
                        try:
                            start = seed
                            seed += 1
                            end = start + 1
                            iggenargs = [
                                input_gen_executable,
                                inputs_dir,
                                str(start), str(end),
                                '--file',
                                self.available_functions_file_name,
                                fid,
                            ]
                            self.print('ig args generation:', ' '.join(iggenargs))
                            proc = subprocess.Popen(
                                iggenargs,
                                stdout=self.get_stdout(),
                                stderr=self.get_stderr())

                            # TODO With the current implementation one of the input
                            # gens timing out would mean we lose some completed ones.
                            #
                            # We should just move the input-gen loop in here and only do
                            # one output at a time.
                            out, err = proc.communicate(timeout=self.input_gen_timeout)

                            if proc.returncode != 0:
                                self.print('Input gen process failed: {} @{}'.format(fid, fname))
                            else:
                                fins = [os.path.join(inputs_dir,
                                                    '{}.input.{}.{}.bin'.format(
                                                        os.path.basename(input_gen_executable), fid, str(i)))
                                    for i in range(start, end)]
                                succeeded = True
                                for inpt in fins:
                                    # If the input gen process exited
                                    # successfully these _must_ be here
                                    if not os.path.isfile(inpt):
                                        # Something went terribly wrong (for
                                        # example the function we are generating
                                        # input for accidentally overwrote our
                                        # state or did exit(0) or something like
                                        # that. (Happens in
                                        # 12374:_ZN25vnl_symmetric_eigensystemIdE5solveERK10vnl_vectorIdEPS2_)
                                        succeeded = False
                                        break
                                if succeeded:
                                    self.print('Input gen process succeeded: {} @{}'.format(fid, fname))
                                    # Populate the generated inputs
                                    func.succeeded_seeds += list(range(start, end))
                                    func.inputs += fins
                                    break

                        except subprocess.CalledProcessError as e:
                            self.print('Input gen process failed: {} @{}'.format(fid, fname))
                        except subprocess.TimeoutExpired as e:
                            self.print('Input gen timed out! Terminating...: {} @{}'.format(fid, fname))
                            proc.terminate()
                            try:
                                proc.communicate(timeout=1)
                            except subprocess.TimeoutExpired as e:
                                self.print("Termination timed out! Killing...")
                                proc.kill()
                                proc.communicate()
                                self.print("Killed.")
            available_functions_file.close()

        if not self.cleanup:
            available_functions_pickle_file_name = os.path.join(self.outdir, 'available_functions.json')
            with open(available_functions_pickle_file_name, 'w') as available_functions_pickle_file:
                available_functions_pickle_file.write(json.dumps(self.functions, default=vars))

    def run_all_inputs(self):
        for func in self.functions:
            func.run_all_inputs(self.input_run_timeout, self.available_functions_file_name)

    def get_statistics(self):
        stats = get_empty_statistics()
        self.update_statistics(stats)
        return stats

    def merge_profdata(self, outfile, infile):
        try:
            merge_args = [
                'llvm-profdata', 'merge',
                '-o', outfile,
                outfile, infile,
            ]
            subprocess.run(merge_args,
                            check=True,
                            stdout=self.get_stdout(),
                            stderr=self.get_stderr())
        except:
            self.print('Failed to merge profdata')
            self.print(" ".join(merge_args))

    def update_statistics(self, stats):
        with tempfile.NamedTemporaryFile() as temp_profdata:
            for i in range(self.input_gen_num):
                for func in self.functions:
                    if i < len(func.profile_files):
                        self.merge_profdata(temp_profdata.name, list(func.profile_files.values())[i])

                mbb_dict = None
                try:
                    mbb_args = [
                        'mbb-pgo-info',
                        '--bc-path', self.input_module,
                        '--profile-path', temp_profdata.name,
                    ]
                    mbb = subprocess.Popen(mbb_args,
                                   stdout=subprocess.PIPE,
                                   stderr=self.get_stderr())
                    mbb_json = mbb.stdout.read()
                    mbb_dict = json.loads(mbb_json)
                except:
                    self.print('Failed to merge profdata')
                    self.print(" ".join(mbb_args))

                if mbb_dict is not None:
                    num_bbs = 0
                    num_bbs_executed = 0

                    for func in mbb_dict['Functions']:
                        for _, bbs in func.items():
                            num_bbs += bbs['NumBlocks']
                            num_bbs_executed += bbs['NumBlocksExecuted']
                    assert(stats['num_bbs'] is None or stats['num_bbs'] == num_bbs)
                    stats['num_bbs'] = max(num_bbs, stats['num_bbs']) if stats['num_bbs'] is not None else num_bbs
                    stats['num_bbs_executed'].append(num_bbs_executed)

        for func in self.functions:
            stats['num_funcs'] += 1
            if func.input_gen_executable:
                stats['num_instrumented_funcs'] += 1
            if len(func.inputs) != 0:
                stats['num_input_generated_funcs'] += 1
            if len(func.times) != 0:
                stats['num_input_ran_funcs'] += 1

def handle_single_module(task, args):
    (i, module) = task

    global_outdir = args.outdir
    igm_args = copy.deepcopy(vars(args))
    igm_args['outdir'] = os.path.join(global_outdir, str(i))
    os.makedirs(igm_args['outdir'], exist_ok=True)
    with open(igm_args['outdir'] +"/mod.bc", 'wb') as module_file:
        module_file.write(module)
        module_file.flush()
    igm_args['input_module'] = module_file.name

    igm = InputGenModule(**igm_args)
    igm.generate_inputs()
    igm.run_all_inputs()

    statistics = igm.get_statistics()

    igm.cleanup_outdir()
    if args.cleanup:
        try:
            os.remove(igm_args['input_module'])
            os.rmdir(igm_args['outdir'])
        except Exception as e:
            pass

    return statistics

if __name__ == '__main__':
    parser = argparse.ArgumentParser('InputGenModule')

    parser.add_argument('--outdir', required=True)
    parser.add_argument('--input-module', required=True)

    add_option_args(parser)

    args = parser.parse_args()

    IGM = InputGenModule(**vars(args))
    IGM.generate_inputs()
    IGM.run_all_inputs()
    IGM.cleanup_outdir()

    print(IGM.get_statistics())
