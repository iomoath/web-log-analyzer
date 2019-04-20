__author__ = "Moath Maharmeh"
__version__ = "1.0"
__email__ = "moath@vegalayer.com"
__created__ = "20/Apr/2019"
__modified__ = "20/Apr/2019"
__project_page__ = "https://github.com/iomoath/web-log-analyzer"


import os
import datetime
import log_parser


ip_report  = {}
ip_requests_datetime = {}


def read_file_lines(file_path):
    with open(file_path) as fp:
        return fp.readlines()


def get_avg_requests_per_hour_dict():
    global ip_requests_datetime
    result = {}

    for k in ip_requests_datetime.keys():
       try:
           ref = ip_requests_datetime[k][0]
           counter = []
           c = 1
           for h in range(1, len(ip_requests_datetime[k])):
               if (ip_requests_datetime[k][h] - ref).total_seconds() / 3600 < 1.0:
                   c = c + 1
               else:
                   counter.append(c)
                   c = 1
                   ref = ip_requests_datetime[k][h]
                   if h == len(ip_requests_datetime[k]) - 1:
                       counter.append(c)
           result[k] = round(float(c) if len(counter) == 0 else float(sum(counter)) / len(counter))
       except Exception as e:
           print('[-] ERROR: get_avg_requests_per_hour_dict() {}'.format(e))

    return result



def convert_to_datetime(text):
    return datetime.datetime.strptime(text, '%d/%b/%Y:%H:%M:%S %z')


def add_remote_host_dict_key(remote_host):
    global ip_report

    if not remote_host in ip_report.keys():
        ip_report[remote_host] = {}


def sort_dict_by_value(input_dict):
    return dict(sorted(input_dict.items(), key=lambda t: t[1], reverse=True))


def sort_report_by_request_count():
    """
    descending sort ip_report[remote_host]['requests']
    :return:
    """
    global ip_report
    for remote_host in ip_report.keys():
        ip_report[remote_host]['requests'] = dict(sorted(ip_report[remote_host]['requests'].items(), key=lambda t: t[1]['request_count'], reverse=True))


def sort_report_by_total_request_count():
    """
    descending sort ip_report['total_request_count']
    :return:
    """
    global ip_report
    ip_report = dict(sorted(ip_report.items(), key=lambda t: t[1]['total_request_count'], reverse=True))


def add_request_rate_to_report(request_rate_report):
    global ip_report

    if request_rate_report is None:
        return

    for key, value in request_rate_report.items():
        if key in ip_report.keys():
            ip_report[key]['request_rate'] = value

def increment_remote_host_request_count(remote_host, request):
    global ip_report

    if 'request_count' in ip_report[remote_host]['requests'][request].keys():
        ip_report[remote_host]['requests'][request]['request_count'] += 1
    else:
        ip_report[remote_host]['requests'][request]['request_count'] = 1


def increment_remote_host_total_request_count(remote_host):
    global ip_report

    if 'total_request_count' in ip_report[remote_host].keys():
        ip_report[remote_host]['total_request_count'] += 1
    else:
        ip_report[remote_host]['total_request_count'] = 1


def add_request_info(remote_host, request, response_status_code, user_agent):
    global ip_report

    if not 'requests' in ip_report[remote_host].keys():
        ip_report[remote_host]['requests'] = {}

    if not request in ip_report[remote_host]['requests'].keys():
        ip_report[remote_host]['requests'][request] = {}

    ip_report[remote_host]['requests'][request]['status'] = response_status_code
    ip_report[remote_host]['requests'][request]['user_agent'] = user_agent


def add_request_datetime(remote_host, datetime_received):
    global ip_requests_datetime

    if type(datetime_received) is str:
        datetime_received = convert_to_datetime(datetime_received)

    if not remote_host in ip_requests_datetime.keys():
        ip_requests_datetime[remote_host] = []

    ip_requests_datetime[remote_host].append(datetime_received)


def process(log_dict):
    if log_dict is None:
        return

    remote_host = log_dict['remote_host']
    add_remote_host_dict_key(remote_host)
    add_request_info(remote_host, log_dict['request'], log_dict['status'], log_dict['user_agent'])
    increment_remote_host_request_count(remote_host, log_dict['request'])
    increment_remote_host_total_request_count(remote_host)
    add_request_datetime(remote_host, log_dict['time_received'])



def update_take_x_ip_requests(limit):
    """
    take first x items from ip_report['requests'] and replace it ip_report['requests']
    :param limit: how many to take from ip_report['requests'] dict
    :return:
    """
    global ip_report

    for remote_host, record in ip_report.items():
        ip_report[remote_host]['requests'] = {k: ip_report[remote_host]['requests'][k] for k in list(ip_report[remote_host]['requests'])[:limit]}


def analyze_access_log_file_apache_parser(access_logs_lines, log_format):

    log_parser.init_log_parser(log_format)

    for line in access_logs_lines:
        try:
            line = line.strip()
            if line is None or len(line) <= 0:
                continue

            log = log_parser.get_structured_apache_access_log(line)
            process(log)
        except Exception as e:
            print('[-] ERROR: Could not process the line "{}". {}'.format(line, e))
            #print('[-] ERROR: analyze_access_log_file_apache_parser(): {}'.format(e))


def analyze_access_log_file_regex_parser(access_log_lines):
    global ip_report

    for line in access_log_lines:
        try:
            line = line.strip()
            if line is None or len(line) <= 0:
                continue

            log = log_parser.get_structured_access_log(line)

            process(log)
        except Exception as e:
            print('[-] ERROR: Could not process the line "{}". {}'.format(line, e))
            #print('[-] ERROR: analyze_access_log_file_apache_parser(): {}'.format(e))


def analyze_access_log_file(file_path, custom_log_format=None):
    global ip_report
    if file_path is None or not os.path.isfile(file_path):
        print('[-] ERROR: The provided path "{}" is invalid.'.format(file_path))
        return None

    try:
        file_path = file_path.strip()

        # analyze => fills 'ip_report' dict
        ip_report = {}
        access_logs_lines = read_file_lines(file_path)
        if custom_log_format is not None:
            custom_log_format = custom_log_format.strip()
            analyze_access_log_file_apache_parser(access_logs_lines, custom_log_format)
        else:
            analyze_access_log_file_regex_parser(access_logs_lines)

        # get average requests per hour for each remote host
        requests_rate = get_avg_requests_per_hour_dict()
        add_request_rate_to_report(requests_rate)

        # sort
        sort_report_by_request_count()
        sort_report_by_total_request_count()

        # take first X requests (top X requests) for each remote_host
        update_take_x_ip_requests(10)


        return ip_report
    except IOError as e:
        print('[-] ERROR: Unable to read file "{}" {}'.format(file_path, e))
        return None
    except Exception as e:
        print('[-] ERROR: "{}"'.format(e))
        return None

