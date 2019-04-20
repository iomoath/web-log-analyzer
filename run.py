__author__ = "Moath Maharmeh"
__version__ = "1.0"
__email__ = "moath@vegalayer.com"
__created__ = "20/Apr/2019"
__modified__ = "20/Apr/2019"
__project_page__ = "https://github.com/iomoath/web-log-analyzer"


import argparse
from report_generator import generate_report
from analyzer import analyze_access_log_file

arg_parser = None


def write_to_file(file_path, content):
    with open(file_path, mode='w') as file:
        file.write(content)



def run(args):
    print('[+] Analyzing "{}" .. This may take some time.'.format(args["log_file"]))
    result = analyze_access_log_file(args["log_file"], args["log_format"])
    try:
        print('[+] Generating report..')
        report = generate_report(result)
        save_path = str(args["out"].strip())
        write_to_file(save_path, report)
        print('[+] Report saved to "{}"'.format(save_path))

    except Exception as e:
        print("[-] An error has occurred while writing the report. {}".format(e))



def generate_argparser():
    header_txt = """
        Web access log analyzer
        Project page: https://github.com/iomoath/web-log-analyzer
        """
    ap = argparse.ArgumentParser(header_txt)

    ap.add_argument("-i", "--log-file", action='store', type=str, required=True,
                    help="Log file path.")

    ap.add_argument("-o","--out", action='store', type=str, required=True,
                    help="Report output path.")

    ap.add_argument("-f", "--log-format", action='store', type=str,
                    help="Custom Apache log format. If not set, then will try parse logs using Regex.")

    ap.add_argument("--version", action="version", version='Yara-Scanner Version 1.0')
    return ap


def main():
    global arg_parser
    arg_parser = generate_argparser()
    args = vars(arg_parser.parse_args())
    run(args)


if __name__ == "__main__":
    main()