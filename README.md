# Input-gen useful commands

``` sh
$ ./scripts/input_gen_module.py --help
```

To generate 5 inputs for `func_name` in `module.bc`:
``` sh
$ ./scripts/input_gen_module.py [--verbose] --function func_name --outdir ./outdir --input-module module.bc
```

To generate 5 inputs for all available functions in `module.bc`:
``` sh
$ ./scripts/input_gen_module.py [--verbose] --outdir ./outdir --input-module module.bc --input-gen-num 5
```

## Mass input gen

To generate inputs:

Single cpu:
``` sh
JUG=run START=0 END=500000 ./scripts/run_local_mass_input_gen.sh
```

Multi-cpu:
``` sh
for i in $(seq 0 40); do
    JUG=run START=0 END=500000 ./scripts/run_local_mass_input_gen.sh &
done
```

Multi-node:
``` sh
JUG=run START=0 END=500000 flux submit -x -N 10 --tasks-per-node 40 -t 5h ./scripts/run_local_mass_input_gen.sh
```

The results are stored in the scripts/*jugdata directory - that needs to be on an NFS for this to work across nodes.

To see the results at any time (even while running or partially completed):
``` sh
JUG=results START=0 END=7000 ./scripts/run_local_mass_input_gen.sh
```

## Debugging/exploring

To test out a single module locally:
``` sh
ADDITIONAL_FLAGS="--verbose -g" NOCLEANUP=1 SINGLE=18450 ./scripts/run_local_mass_input_gen.sh
```

This will print out all intermediate commands ran and what failed, etc.

To debug the input gen/run runtimes use VERBOSE=1, e.g.:
``` sh
VERBOSE=1 /l/ssd/$USER/compile-input-gen-out/12374/input-gen.module.generate.a.out /l/ssd/$USER/compile-input-gen-out/12374/input-gen.32.inputs 3 4 _ZN25vnl_symmetric_eigensystemIdE5solveERK10vnl_vectorIdEPS2_ 32
```


There are some hardcoded paths to the llvm installation dirs etc which need to be edited in the `./scripts/run_local_mass_input_gen.sh` script.
