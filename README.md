# Secure-PRL-with-LSH

## Plaintext Experiments

The plaintext experiments are done with `PlainPRL.py`. 

### Parameters

The `-t` option specifies either the test uses `bnb_tpl` dataset or `ncvr` dataset.

The `-n` option specifies the number of samples we select for both parties. If not specified, experiments will be done for various number of samples, specified by `n_sample_range` in the `main()` function.

The parameters we varied include: length of the vector of min-hash values, $m$, number of duplicates of each records, $d$, and number of bins per duplicate, $l$. These are set by the variables in the `main()` function.

The length of the vector of min-hash values, $m$, can be set by varying `num_perms_per_hash_range`, which lists the set of values we want to test. 

The number of duplicates of each records, $d$, can be set by varying `num_duplicates_range`, which lists the set of values we want to test. 

The number of bins per duplicate, $l$, can be set by varying `num_bins_per_duplicate`, which lists the set of values we want to test. 

### Files

The input datasets should be in two folders, `bnb_tpl_datasets` and `NCVR`. 

The output files will be in csv format, with columns specifying some of the experiment parameters, and their corresponding number of comparisons required, and resulting accuracy.

## Cryptographic Experiments

### Compilation

We need the ABY framework (https://github.com/encryptogroup/ABY.git) to run our cryptographic experiments.

The folder `my_psi` should be placed in the `ABY/src/examples/` folder. The `CMakeLists.txt` in the same folder needs one extra line `add_subdirectory(my_psi)`.

Then, make the project as instructed in ABY. Copy the `my_psi/common/measure.py` to `ABY/build/bin` and run `python3 measure.py`

### Parameters

On lines $62$ to $65$ of `measure.py` there are some parameters. 

`runs` specifies how many times we should repeat the experiment.

`num_eles_l` is the number of input for both parties.

`num_bins_l` is the number of bins per duplicate, $l$, as in the previous section. 

`num_bits` is the size of a single input. For example, `num_bits = 16` means a record would be a $16$ bit integer.

### Files

The output files will be in csv format, with columns specifying some of the experiment parameters, and their corresponding CPU time used, and number of comparisons done.