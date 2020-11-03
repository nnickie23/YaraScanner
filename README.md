# YaraScanner

To compile the program print 

$ make

Executive file is called yaraScanner.

The program requires directory name which will be recursively scan for all (*.php) files.

Also program needs the name of file containig Yara rules.

As additional argument output file can be stated.

Example: 

$ ./yaraScanner directory yara_rule_file output_file

If output file is not stated, results will be printed in stdout.
