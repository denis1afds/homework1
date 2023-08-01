#!/usr/bin/env python
# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

import os
import re
import gzip
import logging
import datetime
from string import Template
from collections import defaultdict
from statistics import median
import json
import argparse


def global_exception_handler(exception_type, value, trace_back):
    logging.exception('uncaught exception')


excepthook = global_exception_handler

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./data/reports",
    "REPORT_TEMPLATE_PATH": "./data/templates/report.html",
    "REPORT_FILENAME_TEMPLATE": r"^report-(?P<file_date>[0-9]{4}\.[0-9]{2}\.[0-9]{2})\.html",
    "LOG_DIR": "./data/logs",
    "LOG_FILENAME_TEMPLATE": r"^nginx-access-ui\.log-(?P<file_date>[0-9]{8})\.(?:log|gz)",
    "ANALYZER_LOGS_PATH": "./data/analyzer_logs/log_module_${date}.log"
}


def main(config_dict):
    parser_cli = argparse.ArgumentParser(description='parse last nginx log and create report ')
    parser_cli.add_argument('--config', dest='config_filename', help='config file path (optional)', action='store',
                            default=None)
    parser_cli.add_argument('--export', help='store default config to path', dest='is_export_config',
                            action='store_true', default=False)

    args = parser_cli.parse_args()
    if args.config_filename is not None:
        if args.is_export_config:
            print('export config to {}'.format(args.config_filename))
            with open(args.config_filename, mode='wt', encoding='utf-8') as cfg_file:
                json.dump(config_dict, cfg_file, indent=2)
        else:
            try:
                with open(args.config_filename, mode='rt', encoding='utf-8') as cfg_file:
                    config_ext_dict = json.load(cfg_file)
                    for config_key in config_dict:
                        config_dict[config_key] = config_ext_dict.get(config_key, config_dict[config_key])
            except FileNotFoundError as e:
                print('File with config not found')
                raise
            except json.JSONDecodeError:
                print('Config file decode error')
                raise

    log_parser_regexp_expr = r'^(?P<remote_addr>\S+)\s+(?P<remote_user>\S+)\s+(?P<http_x_real_ip>\S+)\s+\[' \
                             r'(?P<time_local>[^\]]+)\]\s+\"(?P<request>[^\"]+)\"\s+(?P<status>\d+)\s+' \
                             r'(?P<body_bytes_sent>\d+)\s+\"(?P<http_referer>[^\"]+)\"\s+\"' \
                             r'(?P<http_user_agent>[^\"]+)\"\s+\"(?P<http_x_forwarded_for>[^\"]+)\"\s+\"' \
                             r'(?P<http_x_request_id>[^\"]+)\"\s+\"(?P<http_rb_user>[^\"]+)\"\s+(?P<request_time>\S+)'

    log_parser_regexp = re.compile(log_parser_regexp_expr)
    logging_filename = Template(config_dict['ANALYZER_LOGS_PATH']).safe_substitute(
        date=datetime.datetime.strftime(datetime.date.today(), '%Y-%m-%d'))
    logging.basicConfig(level=logging.INFO,
                        filename=logging_filename,
                        filemode="w",
                        format="%(asctime)s %(levelname)s %(message)s")
    log_filename_regexp = re.compile(config_dict['LOG_FILENAME_TEMPLATE'])
    report_filename_regexp = re.compile(config_dict['REPORT_FILENAME_TEMPLATE'])

    try:
        log_filename, log_file_date = sorted(
            ((log_file[0], log_file[1]) for log_file in
             gen_match_files(config_dict['LOG_DIR'], log_filename_regexp, '%Y%m%d')), key=lambda log_file: log_file[1],
            reverse=True)[0]
    except IndexError:
        log_file_date = None
        log_filename = None
        logging.info('no logs in storage')

    try:
        report_filename, report_file_date = sorted(
            ((report_file[0], report_file[1]) for report_file in
             gen_match_files(config_dict['REPORT_DIR'], report_filename_regexp, '%Y.%m.%d')),
            key=lambda report_file: report_file[1],
            reverse=True)[0]
    except IndexError:
        report_file_date = None
        logging.info('no reports in storage')

    if log_file_date is not None and (report_file_date is not None and log_file_date > report_file_date
                                      or report_file_date is None):
        log_file_opener = gzip.open if log_filename.endswith('.gz') else open
        with log_file_opener(log_filename, mode='rt', encoding='utf-8') as f_log:
            log_json = json.dumps(sorted(render_report(LogFileGenerator(f_log, log_parser_regexp)),
                                         key=lambda log_record: log_record['time_sum'],
                                         reverse=True)[:config_dict['REPORT_SIZE']])
            create_report(log_json, config_dict['REPORT_TEMPLATE_PATH'],
                          os.path.abspath(os.path.join(config_dict['REPORT_DIR'], 'report-'
                                                       + log_file_date.strftime('%Y.%m.%d') + '.html')))

        logging.info('parsing lines:{}, parsings error count:{} ({:.3%})'
                     .format(LogFileGenerator.lines_count, LogFileGenerator.parse_errors_count, LogFileGenerator.parse_errors_count
                             / LogFileGenerator.lines_count))


def create_report(log_json, report_template_path, report_filename):
    with open(report_template_path, mode='r', encoding='utf-8') as rtf:
        with open(report_filename, mode='w', encoding='utf-8') as rof:
            for data in rtf:
                rof.write(Template(data).safe_substitute(table_json=log_json))


def render_report(gen_log_parsing):
    total_request_qty = 0
    total_request_time = 0
    url_request_time = defaultdict(list)

    for log_dict in gen_log_parsing:
        url_list = log_dict['request'].split(' ')
        url_line = url_list[1] if len(url_list) > 1 else None
        total_request_qty += 1
        total_request_time += log_dict['request_time']
        url_request_time[url_line].append(log_dict['request_time'])

    url_statistic_list = list()

    for url_line in url_request_time:
        time_sum = sum(url_request_time[url_line])
        url_statistic_list.append({
            'url': url_line,
            'count': len(url_request_time[url_line]),
            'count_perc': '{:.3%}'.format(len(url_request_time[url_line]) / total_request_qty),
            'time_sum': round(time_sum, 3),
            'time_perc': '{:.3%}'.format(time_sum / total_request_time),
            'time_avg': '{:.3f}'.format(time_sum / len(url_request_time[url_line])),
            'time_max': '{:.3f}'.format(max(url_request_time[url_line])),
            'time_med': '{:.3f}'.format(median(url_request_time[url_line]))
        })
    return url_statistic_list


def gen_match_files(file_path, filename_regexp, date_format):
    for path, _, file_list in os.walk(file_path):
        for filename in file_list:
            file_match = filename_regexp.search(filename)
            if file_match is not None:
                try:
                    file_date = datetime.datetime.strptime(file_match.group('file_date'), date_format).date()
                except ValueError:
                    logging.error('File date parsing error:' + filename)
                else:
                    yield os.path.abspath(os.path.join(path, filename)), file_date


class LogFileGenerator:
    lines_count = 0
    parse_errors_count = 0
    parse_errors_lines_no = list()

    def __init__(self,  file_descr, log_parser_regexp):
        LogFileGenerator.lines_count = 0
        LogFileGenerator.parse_errors_count = 0
        LogFileGenerator.parse_errors_lines_no.clear()
        self.file_descr = file_descr
        self.log_parser_regexp = log_parser_regexp

    def __iter__(self):
        return self

    def __next__(self):
        while True:
            line = self.file_descr.readline()
            if len(line) == 0:
                raise StopIteration
            LogFileGenerator.lines_count += 1
            try:
                fields = re.search(self.log_parser_regexp, line).groupdict()
                fields['request_time'] = float(fields['request_time'])
                return fields
            except ValueError:
                LogFileGenerator.parse_errors_count += 1
                LogFileGenerator.parse_errors_lines_no.append(LogFileGenerator.lines_count)
            except AttributeError:
                LogFileGenerator.parse_errors_count += 1
                LogFileGenerator.parse_errors_lines_no.append(LogFileGenerator.lines_count)


if __name__ == "__main__":
    main(config)

