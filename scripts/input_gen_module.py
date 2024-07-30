#!/usr/bin/env python3

import tempfile
import re
import subprocess
import argparse
import os
import sys
import time
import json
import copy
import json
import shutil
from itertools import zip_longest

UNREACHABLE_EXIT_STATUS = 111

def add_option_args(parser):
    parser.add_argument('--input-gen-num', type=int, default=5)
    parser.add_argument('--input-gen-timeout', type=int, default=5)
    parser.add_argument('--input-run-timeout', type=int, default=5)
    parser.add_argument('--input-gen-runtime', default='./input-gen-runtimes/rt-input-gen.cpp')
    parser.add_argument('--input-run-runtime', default='./input-gen-runtimes/rt-run.cpp')
    parser.add_argument('--verbose', action='store_true', default=False)
    parser.add_argument('--no-verbose', dest='verbose', action='store_false')
    parser.add_argument('-g', action='store_true', default=False)
    parser.set_defaults(verbose=False)
    parser.add_argument('--cleanup', action='store_true', default=False)
    parser.add_argument('--timing', action='store_true', default=False)
    parser.add_argument('--coverage-statistics', action='store_true', default=False)
    parser.add_argument('--coverage-runtime')
    parser.add_argument('--branch-hints', action='store_true', default=False)
    parser.add_argument('--disable-fp-handling', action='store_true', default=False)
    parser.add_argument('--function', default=None)

class Function:
    def __init__(self, name, ident, verbose, generate_profs, timing):
        self.name = name
        self.ident = ident
        self.verbose = verbose
        self.input_gen_executable = None
        self.input_run_executable = None
        self.inputs_dir = None
        self.tried_seeds = []
        self.succeeded_seeds = []
        self.inputs = []
        self.unreachable_exit_inputs = []
        self.run_times = []
        self.gen_times = []
        self.unreachable_exit_times = []
        self.generate_profs = generate_profs
        self.profile_files = []
        self.timing = timing

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

        succeeded = False
        unreachable_exit = None
        if inpt is not None:
            try:
                igrunargs = [
                        self.input_run_executable,
                        inpt,
                        '--file',
                        available_functions_file_name,
                        self.ident,
                    ]

                env = os.environ.copy()
                if self.generate_profs:
                    profdatafile = os.path.join(self.inputs_dir, inpt + '.profdata')
                    env['LLVM_PROFILE_FILE'] = profdatafile
                if self.timing:
                    env['TIMING'] = '1'
                    stdout = subprocess.PIPE
                else:
                    stdout = self.get_stdout()

                proc = subprocess.Popen(
                    igrunargs,
                    stdout=stdout,
                    stderr=self.get_stderr(),
                    text=True,
                    env=env)

                self.print('ig args run:', ' '.join(igrunargs))
                out, err = proc.communicate(timeout=timeout)

                if self.timing:
                    times = re.findall(r'Time for ([a-zA-Z]+): ([0-9]+)\n', out)
                    self.print(f'times: {times}')
                    self.print(out, file=self.get_stdout())
                else:
                    times = []

                if proc.returncode == 0 or proc.returncode == UNREACHABLE_EXIT_STATUS:
                    unreachable_exit = bool(proc.returncode == UNREACHABLE_EXIT_STATUS)
                    succeeded = True
                else:
                    self.print('Input run process failed (%i): %s' % (proc.returncode, inpt))

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

        if not succeeded:
            profdatafile = None
            unreachable_exit = None
            times = []
        self.run_times.append(times)
        self.unreachable_exit_times.append(unreachable_exit)
        if self.generate_profs:
            self.profile_files.append(profdatafile)
        else:
            self.profile_files.append(None)


def my_add(a, b):
    if isinstance(a, list):
        return []
    if isinstance(b, list):
        return []
    if a is None:
        return b
    if b is None:
        return a
    return a + b

def aggregate_statistics(stats, to_add):
    if 'timing_gen' in stats:
        del stats['timing_gen']
    if 'timing_run' in stats:
        del stats['timing_run']
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
        'timing_run': [],
        'timing_gen': [],
        'input_generated_by_seed': [],
        'input_generated_by_seed_non_unreachable': [],
        'input_ran_by_seed': [],
        'input_ran_by_seed_non_unreachable': [],
    }
    return stats

class InputGenModule:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)
        self.functions = []

        # We do not use a profile for the first run
        self.use_profile_for_instrumentation = False

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

    def generate_and_run_inputs_impl(self):
        os.makedirs(self.outdir, exist_ok=True)

        self.instrumentation_failed = self.instrument()
        self.get_available_functions()

        if self.instrumentation_failed:
            return

        if self.branch_hints:
            for i in range(self.input_gen_num):
                if i != 0:
                    with tempfile.NamedTemporaryFile() as temp_profdata:
                        for j in range(i):
                            for func in self.functions:
                                prof_file = func.profile_files[j]
                                if prof_file is not None:
                                    self.merge_profdata(temp_profdata.name, prof_file)
                        self.instrument(temp_profdata.name)
                self.generate_inputs(1, i != 0)
                self.run_inputs(i)
        else:
            self.generate_inputs(self.input_gen_num)
            self.run_all_inputs()

    def generate_and_run_inputs(self):
        if self.cleanup:
            self.tempdir = tempfile.TemporaryDirectory(dir=self.outdir)
            self.outdir = self.tempdir.name

        try:
            self.generate_and_run_inputs_impl()
        except Exception as e:
            # Exception here means that something very wrong (killed by oom etc)
            # happened and we should retry
            self.print_err('Generating inputgen executables for', self.input_module, 'in', self.outdir, 'FAILED, to retry')
            raise e

    def cleanup_outdir(self):
        if self.cleanup:
            assert(self.tempdir is not None)
            self.tempdir.cleanup()

    def instrument(self, profdata_filename=None):
        instrumentation_failed = False
        try:

            self.ig_instrument_args = [
                'input-gen',
                '--input-gen-runtime', self.input_gen_runtime,
                '--input-run-runtime', self.input_run_runtime,
                '--output-dir', self.outdir,
                self.input_module,
                '--compile-input-gen-executables',
            ]
            if self.g:
                self.ig_instrument_args.append('-g')
            if self.coverage_statistics or profdata_filename:
                self.ig_instrument_args.append('--instrumented-module-for-coverage')
                self.ig_instrument_args.append('--profiling-runtime-path')
                self.ig_instrument_args.append(self.coverage_runtime)
            if profdata_filename:
                self.ig_instrument_args.append('--profile-path')
                self.ig_instrument_args.append(profdata_filename)
            if self.disable_fp_handling:
                self.ig_instrument_args.append("--input-gen-instrument-function-ptrs=false")
            self.ig_instrument_args.append("--input-gen-provide-branch-hints=%s" %  ("true" if self.branch_hints else "false"))

            self.print("input-gen args:", " ".join(self.ig_instrument_args))
            subprocess.run(self.ig_instrument_args,
                           check=True,
                           stdout=self.get_stdout(),
                           stderr=self.get_stderr())
        except:
            self.print('Failed to instrument')
            instrumentation_failed = True
        return instrumentation_failed

    # This should always succeed if we run the instrumentation - else it is a
    # hard failure so we throw
    def get_available_functions(self):
        self.available_functions_file_name = os.path.join(self.outdir, 'available_functions')
        try:
            available_functions_file = open(self.available_functions_file_name, 'r')
        except IOError as e:
            self.print("Could not open available functions file:", e)
            self.print("input-gen args:", " ".join(self.ig_instrument_args))
            raise e
        else:
            zerosplit = available_functions_file.read().split('\0')
            fids = zerosplit[0:-1:2]
            fnames = zerosplit[1::2]
            for (fid, fname) in zip(fids, fnames, strict=True):
                if self.function is None or self.function == fname:
                    func = Function(fname, fid, self.verbose, self.coverage_statistics or self.branch_hints, self.timing)
                    self.functions.append(func)
        available_functions_file.close()

    def generate_inputs(self, input_gen_num, branch_hints=False):
        for func in self.functions:
            fname = func.name
            fid = func.ident

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

            seed = 0 if len(func.tried_seeds) == 0 else func.tried_seeds[-1] + 1
            for _ in range(input_gen_num):
                succeeded = False
                unreachable_exit = None
                try:
                    func.tried_seeds.append(seed)
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
                    env = os.environ.copy()
                    if branch_hints:
                        env = os.environ.copy()
                        if 'INPUT_GEN_DISABLE_BRANCH_HINTS' in env:
                            del env['INPUT_GEN_DISABLE_BRANCH_HINTS']
                    else:
                        env['INPUT_GEN_DISABLE_BRANCH_HINTS'] = '1'
                    if self.timing:
                        env['TIMING'] = '1'
                        stdout = subprocess.PIPE
                    else:
                        stdout = self.get_stdout()
                    proc = subprocess.Popen(
                        iggenargs,
                        stdout=stdout,
                        stderr=self.get_stderr(),
                        text=True,
                        env=env)

                    out, err = proc.communicate(timeout=self.input_gen_timeout)

                    if self.timing:
                        times = re.findall(r'Time for ([a-zA-Z]+): ([0-9]+)\n', out)
                        self.print(f'times: {times}')
                        self.print(out, file=self.get_stdout())
                    else:
                        times = []

                    if proc.returncode == 0 or proc.returncode == UNREACHABLE_EXIT_STATUS:
                        unreachable_exit = bool(proc.returncode == UNREACHABLE_EXIT_STATUS)

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
                    else:
                        self.print('Input gen process failed: {} @{}'.format(fid, fname))

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

                if succeeded:
                    self.print('Input gen process succeeded: {} @{}'.format(fid, fname))
                    # Populate the generated inputs
                    func.succeeded_seeds += list(range(start, end))
                    func.inputs += fins
                    func.gen_times.append(times)
                    assert(len(fins) == 1)
                    func.unreachable_exit_inputs.append(unreachable_exit)
                else:
                    func.inputs += [None for _ in range(start, end)]
                    func.gen_times.append([])
                    func.unreachable_exit_inputs += [None for _ in range(start, end)]

    def run_inputs(self, idx):
        for func in self.functions:
            func.run_input(func.inputs[idx], self.input_run_timeout, self.available_functions_file_name)

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
        for func in self.functions:
            stats['num_funcs'] += 1
            if self.timing:
                stats['timing_run'].append({func.ident: func.run_times})
                stats['timing_gen'].append({func.ident: func.gen_times})
            if func.input_gen_executable:
                stats['num_instrumented_funcs'] += 1
            if len([inpt for inpt in func.inputs if inpt is not None]) != 0:
                stats['num_input_generated_funcs'] += 1
            if len([time for time in func.run_times if time is not None]) != 0:
                stats['num_input_ran_funcs'] += 1

        def ensure_length(l):
            for _ in range(self.input_gen_num - len(l)):
                l.append(None)
        ensure_length(stats['input_generated_by_seed'])
        ensure_length(stats['input_ran_by_seed'])
        ensure_length(stats['input_generated_by_seed_non_unreachable'])
        ensure_length(stats['input_ran_by_seed_non_unreachable'])

        if self.instrumentation_failed:
            return

        generated_funcs = set()
        ran_funcs = set()
        generated_funcs_nu = set()
        ran_funcs_nu = set()
        for i in range(self.input_gen_num):
            for func in self.functions:
                if func.inputs[i]:
                    generated_funcs.add(func.ident)
                    if not func.unreachable_exit_inputs[i]:
                        generated_funcs_nu.add(func.ident)
                if func.run_times[i]:
                    ran_funcs.add(func.ident)
                    if not func.unreachable_exit_times[i]:
                        ran_funcs_nu.add(func.ident)
            stats['input_generated_by_seed'][i] = len(generated_funcs)
            stats['input_ran_by_seed'][i] = len(ran_funcs)
            stats['input_generated_by_seed_non_unreachable'][i] = len(generated_funcs_nu)
            stats['input_ran_by_seed_non_unreachable'][i] = len(ran_funcs_nu)

        if not self.coverage_statistics:
            return

        with tempfile.NamedTemporaryFile() as temp_profdata:
            for i in range(self.input_gen_num):
                for func in self.functions:
                    prof_file = func.profile_files[i]
                    if prof_file is not None:
                        self.merge_profdata(temp_profdata.name, prof_file)

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
                else:
                    # Leave stats['num_bbs'] alone as it is either None or
                    # contains the proper number of BBs

                    if len(stats['num_bbs_executed']) == 0:
                        stats['num_bbs_executed'].append(None)
                    else:
                        # Inherit the last one as we are aggregating them
                        # accumulatively
                        stats['num_bbs_executed'].append(stats['num_bbs_executed'][-1])


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
    igm.generate_and_run_inputs()

    try:
        statistics = igm.get_statistics()
    except Exception as e:
        print(i)
        raise e

    igm.cleanup_outdir()
    if args.cleanup:
        try:
            os.remove(igm_args['input_module'])
            os.rmdir(igm_args['outdir'])
        except Exception as e:
            pass

    return statistics

def main():

    if shutil.which("input-gen") is None:
        print('input-gen executable not found')
        exit(1)

    parser = argparse.ArgumentParser('MassInputGen')
    add_option_args(parser)
    parser.add_argument('--outdir', required=True)
    parser.add_argument('--input-module', required=True)
    args = vars(parser.parse_args())

    igm = InputGenModule(**args)
    igm.generate_and_run_inputs()

    try:
        statistics = igm.get_statistics()
        print(f'statistics: {statistics}')
    except Exception as e:
        raise e

    igm.cleanup_outdir()

if __name__ == '__main__':
    main()
