#!/usr/bin/env python3

import subprocess
import argparse
import os
import sys
import time
import json

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
    parser.set_defaults(verbose=False)

class Function:
    def __init__(self, name, verbose):
        self.name = name
        self.input_gen_executable = None
        self.input_run_executable = None
        self.inputs_dir = None
        self.tried_seeds = []
        self.succeeded_seeds = []
        self.inputs = []
        self.times = {}
        self.verbose = verbose

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

    def run_all_inputs(self, timeout):
        for input in self.inputs:
            self.run_input(input, timeout)

    def print(self, *args, **kwargs):
        if self.verbose:
            print(*args, **kwargs)

    def run_input(self, input, timeout):
        self.print('Running executables for', self.input_run_executable)

        try:
            start_time = time.time()

            proc = subprocess.Popen(
                [
                    self.input_run_executable,
                    input,
                    self.name,
                ],
                stdout=self.get_stdout(),
                stderr=self.get_stderr())
            out, err = proc.communicate(timeout=timeout)

            end_time = time.time()
            elapsed_time = end_time - start_time

            if proc.returncode != 0:
                self.print('Input run process failed (%i): %s' % (proc.returncode, input))
            else:
                if input not in self.times:
                    self.times[input] = []
                self.times[input].append(elapsed_time)

        except subprocess.CalledProcessError as e:
            self.print('Input run process failed: %s' % input)
        except subprocess.TimeoutExpired as e:
            self.print("Input run timed out! Terminating... %s" % input)
            proc.terminate()
            try:
                proc.communicate(timeout=1)
            except subprocess.TimeoutExpired as e:
                self.print("Termination timed out! Killing... %s" % input)
                proc.kill()
                proc.communicate()
                self.print("Killed.")

class InputGenModule:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)
        self.functions = []

    def print(self, *args, **kwargs):
        if self.verbose:
            print(*args, **kwargs)

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

        os.makedirs(self.outdir, exist_ok=True)

        self.print('Generating inputgen executables for', self.input_module, 'in', self.outdir)

        try:

            igargs = [
                'input-gen',
                '--input-gen-runtime', self.input_gen_runtime,
                '--input-run-runtime', self.input_run_runtime,
                '--output-dir', self.outdir,
                self.input_module,
                '--compile-input-gen-executables'
            ]
            subprocess.run(igargs,
                           check=True,
                           stdout=self.get_stdout(),
                           stderr=self.get_stderr())
            self.print("input-gen args:", " ".join(igargs))
        except Exception:
            self.print('Failed to instrument')

        available_functions_file_name = os.path.join(self.outdir, 'available_functions')
        try:
            available_functions_file = open(available_functions_file_name, 'r')
        except IOError as e:
            self.print("Could not open available functions file:", e)
            self.print("input-gen args:", " ".join(igargs))
            raise(e)
        else:
            for fname in available_functions_file.read().splitlines():
                func = Function(fname, self.verbose)
                self.functions.append(func)

                input_gen_executable = os.path.join(
                    self.outdir, 'input-gen.module.generate.a.out')
                input_run_executable = os.path.join(
                    self.outdir, 'input-gen.module.run.a.out')
                inputs_dir = os.path.join(self.outdir, 'input-gen.' + fname + '.inputs')

                if not os.path.isfile(input_gen_executable):
                    continue
                if not os.path.isfile(input_run_executable):
                    continue

                # Only attach these to the Function if they exist
                os.makedirs(inputs_dir, exist_ok=True)
                func.input_run_executable = input_run_executable
                func.input_gen_executable = input_gen_executable
                func.inputs_dir = inputs_dir

                self.print('Generating inputs for function @{}'.format(fname))

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
                                    fname,
                                ]
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
                                self.print('Input gen process failed: @{}'.format(fname))
                                self.print('ig args generation:', ' '.join(iggenargs))
                            else:
                                self.print('Input gen process succeeded: @{}'.format(fname))
                                # Populate the generated inputs
                                fins = [os.path.join(inputs_dir,
                                                    '{}.input.{}.{}.bin'.format(
                                                        os.path.basename(input_gen_executable), fname, str(i)))
                                    for i in range(start, end)]
                                func.inputs += fins
                                for inpt in func.inputs:
                                    # If the input gen process exited successfully these
                                    # _must_ be here
                                    assert(os.path.isfile(inpt))
                                func.succeeded_seeds += list(range(start, end))

                                break

                        except subprocess.CalledProcessError as e:
                            self.print('Input gen process failed: @{}'.format(fname))
                            self.print('ig args generation:', ' '.join(iggenargs))
                        except subprocess.TimeoutExpired as e:
                            self.print('Input gen timed out! Terminating...: @{}'.format(fname))
                            self.print('ig args generation:', ' '.join(iggenargs))
                            proc.terminate()
                            try:
                                proc.communicate(timeout=1)
                            except subprocess.TimeoutExpired as e:
                                self.print("Termination timed out! Killing...")
                                proc.kill()
                                proc.communicate()
                                self.print("Killed.")
            available_functions_file.close()


        available_functions_pickle_file_name = os.path.join(self.outdir, 'available_functions.json')
        with open(available_functions_pickle_file_name, 'w') as available_functions_pickle_file:
            available_functions_pickle_file.write(json.dumps(self.functions, default=vars))

    def run_all_inputs(self):
        for func in self.functions:
            func.run_all_inputs(self.input_run_timeout)

    def get_empty_statistics(self):
        stats = {
            'num_funcs': 0,
            'num_instrumented_funcs': 0,
            'num_input_generated_funcs': 0,
            'num_input_ran_funcs': 0,
        }
        return stats

    def get_statistics(self):
        stats = self.get_empty_statistics()
        self.update_statistics(stats)
        return stats

    def update_statistics(self, stats):
        for func in self.functions:
            stats['num_funcs'] += 1
            if func.input_gen_executable:
                stats['num_instrumented_funcs'] += 1
            if len(func.inputs) != 0:
                stats['num_input_generated_funcs'] += 1
            if len(func.times) != 0:
                stats['num_input_ran_funcs'] += 1

    def aggregate_statistics(self, stats, to_add):
        for k, v in stats.items():
            stats[k] += to_add[k]

    def add_statistics(self, a, b):
        c = self.get_empty_statistics()
        self.aggregate_statistics(c, a)
        self.aggregate_statistics(c, b)
        return c


if __name__ == '__main__':
    parser = argparse.ArgumentParser('InputGenModule')

    parser.add_argument('--outdir', required=True)
    parser.add_argument('--input-module', required=True)

    add_option_args(parser)

    args = parser.parse_args()

    IGM = InputGenModule(**vars(args))
    IGM.generate_inputs()
    IGM.run_all_inputs()
    print(IGM.get_statistics())
