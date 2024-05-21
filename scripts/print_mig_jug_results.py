#!/usr/bin/env python3

import jug
import sys
import os
import functools
jf = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'jugfile.py')
jug.init(jf, jf[:-3] + '.jugdata/')
import mass_input_gen as mig
import jugfile

tasks = [x for x in jugfile.tasks if x.can_load()]

if jugfile.args.invalidate_instrumentation_failures:
    for task in tasks:
        val = jug.task.value(task)
        if val['stats']['num_instrumented_funcs'] == 0:
            print('Invalidating {}'.format(val['idx']))
            task.invalidate()
    sys.exit(0)

stats = jug.task.value(tasks)
config = jug.task.value(jugfile.configuration)
print('{')
print('"Config":')
print(config, end=',')
print()
print('"Results":')
mig.pretty_print_statistics(stats)
print('}')
