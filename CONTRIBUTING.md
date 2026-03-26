# contributing

## layout
`tests/`:       pytest tests, make some if you think your code is complex (or don't i don't care)  
`src/dog`:      top level `dog` module, simply imports everything from `doglib`  
`src/doglib`:   where all the important python code goes  
`src/doglib_rs`: doglib features in rust. inside `crates` should be each 'module'  
`src/doglib/data`: important files for modules. always separate by folder.
`src/doglib/commandline`: cli tooling
`docs/`: documentation for complex modules

## adding code
try to find a matching module for your feature. if you can't, add it to misc. if it's a big feature (say, >80 lines), make it its own script. if it's a very big feature, make it its own folder and split into submodules
for any new functions you make, ensure you have it added to `__all__` at the bottom of the module  
and if it's a new module, make sure you import it in `dog/__init__.py`

## rules
ideally this should never use any external libraries other than what `pwntools` already uses. if you need an external library, try to:
- extract the important features of it (if it's not enormous)
- load the library at function run-time, so it's only required if someone tries to use it (see how `doglib/asm.py` does it with `keystone`)
- use a fallback (see how `doglib/pow.py` selects the fastest solver library available)
- worst case, do not add it to `dog/__init__.py` and require explicit import through `doglib`

