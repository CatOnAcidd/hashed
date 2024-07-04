# hashed
Simple scripts aimed monitoring a directory for any changes.

## Create Baseline
The generate.py script can be used to create a baseline of your chosen directory. The script has some basic functionality to show progress when scanning larger directories. The baseline should be securely stored in a read-only location where possible.

### Options
```
**-d**  Path to the directory you want to scan
**-o**  Path and filename for the baseline output
```

### Example Usage
python.exe .\generate.py -d c:\path\to\directory -o c:\hashed\output\baseline.csv

Alternatively, you can simply run the script and it will walk you through providing the required information.

## Compare to Baseline
The compare.py script can then be used to scan the directory and compare it to the baseline that was previously generated. I have not included functionality to send out change notifications as this is varies based on how the scripts are used, the script output the results to a report and print a quick overview to the terminal on completion.

### Options
'''
**-d**  Path to the directory you want to scan
**-b**  Path and baseline filename that you want to compare the results to
**-r**  Path and report filename for the results
'''

### Example Usage
python.exe .\compare.py -d c:\path\to\directory -b \\hashed\baseline.csv -r \\hashed\report\report.csv

Alternatively, you can simply run the script and it will walk you through providing the required information.
