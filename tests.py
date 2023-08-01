import unittest
import LogAnalyzer
import os
import re
import shutil
import datetime


class MatchedFileGenerator(unittest.TestCase):
    path_tests_dataset = None
    match_files = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.match_files = {'nginx-access-ui.log-20230701.gz': (True, datetime.date(2023, 7, 1)),
                           'nginx-access-ui.log-20210702.txt': (False, datetime.date(2021, 7, 2)),
                           'nginx-access-ui.log-20210703.gz': (True, datetime.date(2021, 7, 3)),
                           'nginx-accesc-ui.log-20220704.gz': (False, datetime.date(2022, 7, 4)),
                           'nginx-access-ui.log-20210705.gz': (True, datetime.date(2021, 7, 5)),
                           'nginx-access-ui,log-20210706.gz': (False, datetime.date(2021, 7, 6)),
                           'nginx-access-ui.log-20210707.log': (True, datetime.date(2021, 7, 7)),
                           'nginx-access-ui.log-2f210708.gz': (False, datetime.date(2021, 7, 8)),
                           'nginx-access-ui.log-20210709.gz': (True, datetime.date(2021, 7, 9)),
                           'nginx-access-ui.log-20210710.zip': (False, datetime.date(2021, 7, 10)),
                           'nginx-access-ui-20210711.gz': (False, datetime.date(2021, 7, 11)),
                           'nginx-access-ui.log-20210712.bz2': (False, datetime.date(2021, 7, 12)),
                           'nginx-access-ui-20210713.gz': (False, datetime.date(2021, 7, 13)),
                           'nginx-access-ui.log-20210714.gz': (True, datetime.date(2021, 7, 14))}

        cls.path_tests_dataset = os.path.abspath(os.path.join(os.path.curdir, 'test_dataset'))
        if not os.path.isdir(cls.path_tests_dataset):
            os.mkdir(cls.path_tests_dataset)
        else:
            shutil.rmtree(cls.path_tests_dataset)
            os.mkdir(cls.path_tests_dataset)
        for filename in cls.match_files:
            with open(os.path.join(cls.path_tests_dataset, filename), mode='wt') as file_descriptor:
                pass

    @classmethod
    def tearDownClass(cls) -> None:
        if os.path.isdir(cls.path_tests_dataset):
            shutil.rmtree(cls.path_tests_dataset)

    def test_gen_match_files_matched(self):
        log_filename_regexp = r"^nginx-access-ui\.log-(?P<file_date>[0-9]{8})\.(?:log|gz)";
        log_filename_regexp_obj = re.compile(log_filename_regexp)
        for filename, filedate in LogAnalyzer.gen_match_files \
                    (MatchedFileGenerator.path_tests_dataset, log_filename_regexp_obj, '%Y%m%d'):
            try:
                self.assertTrue(self.match_files[os.path.split(filename)[1]][0], msg='error matching line')
            except KeyError:
                print('error')
                self.assertTrue(False, msg='error prepare test. Fixture not created this file:{}'.format(filename))

    def test_gen_match_files_not_matched(self):
        log_filename_regexp = r"^nginx-access-ui\.log-(?P<file_date>[0-9]{8})\.(?:log|gz)";
        log_filename_regexp_obj = re.compile(log_filename_regexp)
        found_filenames = {os.path.split(filename)[1] for filename, _ in
                           LogAnalyzer.gen_match_files(MatchedFileGenerator.path_tests_dataset,
                                                       log_filename_regexp_obj, '%Y%m%d')}
        not_matched_filenames = set(MatchedFileGenerator.match_files) - found_filenames
        for filename in not_matched_filenames:
            self.assertFalse(self.match_files[filename][0])

    def test_gen_match_file_dates(self):
        log_filename_regexp = r"^nginx-access-ui\.log-(?P<file_date>[0-9]{8})\.(?:log|gz)";
        log_filename_regexp_obj = re.compile(log_filename_regexp)
        for filename, filedate in LogAnalyzer.gen_match_files(MatchedFileGenerator.path_tests_dataset,
                                                              log_filename_regexp_obj, '%Y%m%d'):
            self.assertTrue(MatchedFileGenerator.match_files[os.path.split(filename)[1]][1] == filedate,
                            msg='error parse date')

    def test_log_parsing(self):
        log_parser_regexp_expr = r'^(?P<remote_addr>\S+)\s+(?P<remote_user>\S+)\s+(?P<http_x_real_ip>\S+)\s+\[' \
                                 r'(?P<time_local>[^\]]+)\]\s+\"(?P<request>[^\"]+)\"\s+(?P<status>\d+)\s+' \
                                 r'(?P<body_bytes_sent>\d+)\s+\"(?P<http_referer>[^\"]+)\"\s+\"' \
                                 r'(?P<http_user_agent>[^\"]+)\"\s+\"(?P<http_x_forwarded_for>[^\"]+)\"\s+\"' \
                                 r'(?P<http_x_request_id>[^\"]+)\"\s+\"(?P<http_rb_user>[^\"]+)\"\s+'\
                                 r'(?P<request_time>\S+)'
        log_parser_regexp = re.compile(log_parser_regexp_expr)

        with(open('./data/tests/nginx-access-ui.log-20170630.log', 'rt')) as f_test_log:
            for line in LogAnalyzer.LogFileGenerator(f_test_log, log_parser_regexp):
                pass
        self.assertListEqual(LogAnalyzer.LogFileGenerator.parse_errors_lines_no, [7, 11])


if __name__ == '__main__':
    unittest.main()
