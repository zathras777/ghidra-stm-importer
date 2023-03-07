# ghidra-stm-importer
Small set of python scripts to extract data from STM header files and import to Ghidra

## Usage

To create the data file from STM library include files,

``` shell
$ python3 ./extract_stm_data.py SPIRIT1_data.py ../SPRIT1_LIBRARY/Inc
Created SPIRIT1_data.py
```

Within Ghidra, run the import_stm_data.py script and select the file(s) you have created.

I have used this succesfully to extract data from the STM HAL headers and Spirit1 library headers.

## Why?

The existing SVD-Loader script is a great starting point but I found that I needed additional context while decompiling and a simple way to expand the available types and structures seemed like a good idea.

This allows me to easily add what I need to new Ghidra projects but I will likely try and add the ability to create a simple file with address and types to simplify recreating things.

## Bugs

The uber simple parsing done of the headers means that some manual intervention is needed prior to the generated files being usable :-) Code is intended to be simple as the next time I look at it may be a while...

Pull requests for improvements and corrections welcome.
