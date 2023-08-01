![Logo of the project](./logo.png)

# Nginx log analyzer
>It's educational project. Python script for analyze nginx log and create html report

## Installing / Getting started

Clone project or copy it's catalog to working directory

For analyze and create report with default settings:
```shell
python ./LogAnalyzer.py
```

## Command line keys
###  Breifs description utility usage
> --help 

### Updates default parameters from json config file
> --config `json config filename`

### Stores default parameters to json config file (for further edition)
> --config `json config file path`  --export 


## Configuration file specification
### Default settings
```shell
{
  "REPORT_SIZE": 1000,
  "REPORT_DIR": "./data/reports",
  "REPORT_TEMPLATE_PATH": "./data/templates/report.html",
  "REPORT_FILENAME_TEMPLATE": "^report-(?P<file_date>[0-9]{4}\\.[0-9]{2}\\.[0-9]{2})\\.html",
  "LOG_DIR": "./data/logs",
  "LOG_FILENAME_TEMPLATE": "^nginx-access-ui\\.log-(?P<file_date>[0-9]{8})\\.(?:log|gz)",
  "ANALYZER_LOGS_PATH": "./data/analyzer_logs/log_module_${date}.log"
}
```
###  Parameters description
```
REPORT_SIZE - size of report file. Sorting log entries in descending order of request processing time
REPORT_DIR  - directory for store analyze reports
REPORT_TEMPLATE_PATH - report template file path
REPORT_FILENAME_TEMPLATE -report file name template
LOG_DIR - log source path
LOG_FILENAME_TEMPLATE - log file name regular expression 
ANALYZER_LOGS_PATH - path to the utility log
```

## Testing
### Testing of the matching log files generator consist of 
```
test_gen_match_files_matched - check the list of matching files
test_gen_match_files_not_matched -checks the list of mismatched files
test_gen_match_file_dates - check the correctness of the date conversion
```

### Testing of the log generator parser
```
test_log_parsing -checks the correctness of the parsing of the log, which contains some errors.
``` 

## Licensing

"The code in this project is licensed under MIT license."
