__author__ = "Moath Maharmeh"
__version__ = "1.0"
__email__ = "moath@vegalayer.com"
__created__ = "20/Apr/2019"
__modified__ = "20/Apr/2019"
__project_page__ = "https://github.com/iomoath/web-log-analyzer"


import re
import apache_log_parser


apache_log_line_parser = None


pattern = re.compile(r"""(?x)^
    (?P<remote_host>\S+)            \s+         # host %h
    \S+                             \s+         # indent %l (unused)
    (?P<remote_user>\S+)            \s+         # user %u
    \[(?P<time_received>.*?)\]      \s+         # time %t
    "(?P<request>.*?)"              \s+         # request "%r"
    (?P<status>[0-9]+)              \s+         # status %>s
    (?P<response_bytes_clf>\S+)     (?:\s+      # size %b (careful, can be '-')
    "(?P<referrer>.*?)"   \s+         # referrer "%{Referer}i"
    "(?P<user_agent>.*?)"           (?:\s+      # user agent "%{User-agent}i"
    "[^"]*"                         )?)?        # optional argument (unused)
$""")


def build_from_apache_custom_format(log_dict):
    return {'remote_host': log_dict['remote_host'],
             'request': log_dict['request_first_line'],
             'status': log_dict['status'],
             'user_agent': log_dict['request_header_user_agent'],
             #'referer': log_dict['request_header_referer'],
             'time_received': log_dict['time_received_datetimeobj']}


def build_from_regex_result(log_dict):
    return {'remote_host': log_dict['remote_host'],
             'request': log_dict['request'],
             'status': log_dict['status'],
             'user_agent': log_dict['user_agent'],
             #'referer': log_dict['referrer'],
            'time_received': log_dict['time_received']}


def init_log_parser(log_format):
    global apache_log_line_parser
    apache_log_line_parser = apache_log_parser.make_parser(log_format)


def get_structured_access_log(access_log):
    """
    Uses regex to parse access log line.
    :param access_log: access log line
    :return: structured access log dictionary
    """
    if access_log == '':
        return None
    match_dict = pattern.match(access_log).groupdict()
    return build_from_regex_result(match_dict)




def get_structured_apache_access_log(access_log):
    """
    Uses apache_log_parser lib to parse access log line. init_log_parser(log_format) function must be called first
    :param access_log: access log line
    :return: structured access log dictionary
    """
    global apache_log_line_parser
    d = apache_log_line_parser(access_log)
    return build_from_apache_custom_format(d)

