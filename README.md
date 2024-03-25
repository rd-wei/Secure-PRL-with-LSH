# Secure-PRL-with-LSH

## Plaintext Experiments

The plaintext experiments are done with `PlainPRL.py`. 

Unzip the [datasets](https://drive.google.com/drive/folders/13-ri16yl0WFEWoSnUtJwYIYiIs8y-03U?usp=sharing) into folders "NCVR" (North Carolina) and "bnb_tpl_datasets"(bnb_tpl), and put them in the same directory as PlainPRL.py

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

Then, make the project as instructed in ABY.

Copy the `my_psi/common/gen.py` to `ABY/build/bin` and run `python3 gen.py`. It generates $2$ files that serve as input datasets to the experiments, `inp0` and `inp1`. The datasets we used were also included in `my_psi/common/inp0` and `my_psi/common/inp1`.

Copy the `my_psi/common/measure.py` to `ABY/build/bin` and run `python3 measure.py`. This will start the experiment measuring the number of comparisons and runtime.

### Parameters

On lines $58$ to $63$ of `measure.py` there are some parameters. 

`run` specifies how many times we should repeat the experiment. Here it is a list of length $3$, so it will be repeated $3$ times.

`num_eles` is the number of input for both parties. Here it is in the range between $500$ to $3500$.

`num_bins` is the number of bins per duplicate. It is fixed to $8$ here.

### Files

The output files will be in csv format, with columns specifying some of the experiment parameters, and their corresponding CPU time used, and number of comparisons done.
