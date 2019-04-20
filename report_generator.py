__author__ = "Moath Maharmeh"
__version__ = "1.0"
__email__ = "moath@vegalayer.com"
__created__ = "20/Apr/2019"
__modified__ = "20/Apr/2019"
__project_page__ = "https://github.com/iomoath/web-log-analyzer"


from datetime import datetime


ip_score_url = 'http://www.ip-score.com/checkip/'


def get_datetime():
    return datetime.now().strftime('%Y-%B-%d %H:%M:%S')


report_element = """
<tr>
    <td rowspan="%ROSPAN_NUM%">%INDEX%</td>
    <td rowspan="%ROSPAN_NUM%">%REMOTE_HOST%</td>
    <td rowspan="%ROSPAN_NUM%">%TOTAL_REQUESTS%</td>
    <td rowspan="%ROSPAN_NUM%">%RATE%</td>
    <td class="center weight-6">Request</td>
    <td class="center weight-6">Status</td>
    <td class="center weight-6">Hits</td>
    <td class="center weight-6">User-Agent</td>
</tr>
"""
request_table_tr = """
<tr>
    <td>%REQUEST%</td>
    <td>%STATUS%</td>
    <td>%REQUEST_COUNT%</td>
    <td>%USER_AGENT%</td>

</tr>
"""
report_template = """
<html>
<head>
    <title>%REPORT_TITLE% - %REPORT_DATE_TIME%</title>
    <style>
        table {
            border: 1px solid green;
            border-collapse: collapse;
            width: 100%;
        }
        
        table td {
             border: 1px solid green;
             border-left: 1px solid green;       
             border-top: 1px solid green;         
             border-bottom:none;    
             border-right:none;
             max-width: 550px;
            word-wrap: break-word;
        }
        
        table td.shrink {
            white-space: nowrap
        }
        
        table th {
            color: #FFFFFF;
            background-color: #808080;
        }
        
        table td.expand {
            width: 99%
        }
        td.center, th { text-align: center;}
        td.weight-6 {font-weight: 600;}
    </style>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>

<body>
    <table border="1">
        <thead>
            <tr>
                <th></th>
                <th>Remote Host</th>
                <th>Total Requests</th>
                <th>Requests Per Hour</th>
                <th colspan="4">Top 10 Requests</th>
            </tr>
        </thead>
        <tbody>
           %TABLE_CONTENT%
    </table>
</body>
</html>
"""

def get_link_to_ip_score(ip):
    link = '<a href="{}{}">{}</a>'.format(ip_score_url, ip, ip)
    return link



def generate_report(results_dict):
    """
      Generates an html report for files that has a match with Yara-Rules
      :param results_dict: list of dictionaries containing match details for each file. example {"file": file_path, "yara_rules_file": rule_path, "match_list": matches}
      :return: list of dictionaries containing match details for each file
      """
    report_title = 'Web Log Analyzer Report'
    report_datetime = get_datetime()

    report_html = report_template.replace('%REPORT_TITLE%', report_title)
    report_html = report_html.replace('%REPORT_DATE_TIME%', report_datetime)

    table_content = ""

    index = 1
    for remote_host, report in results_dict.items():
        if report is None:
            continue

        element = report_element.replace('%INDEX%', str(index))
        element = element.replace('%REMOTE_HOST%', get_link_to_ip_score(remote_host))
        element = element.replace('%TOTAL_REQUESTS%', str(report['total_request_count']))
        element = element.replace('%RATE%', str(report['request_rate']))
        element = element.replace('%ROSPAN_NUM%', str(len(report['requests'])+ 1))

        requests_tr = ""
        for request, info in results_dict[remote_host]['requests'].items():
            request_tr = request_table_tr.replace('%REQUEST%', request)
            request_tr = request_tr.replace('%STATUS%', str(info['status']))
            request_tr = request_tr.replace('%REQUEST_COUNT%', str(info['request_count']))
            request_tr = request_tr.replace('%USER_AGENT%', str(info['user_agent']))

            requests_tr += request_tr

        table_content += element
        table_content += requests_tr
        index += 1

    report_html = report_html.replace('%TABLE_CONTENT%', table_content)
    return report_html
