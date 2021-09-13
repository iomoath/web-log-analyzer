# web-log-analyzer
Web access logs analyzer - provides an insight on how remote hosts behave. 

Example scenarios where this tool can be helpful:
* Finding IP addresses that performs brute force attack(s).
* Finding IP addresses that send abnormal number requests.

When the analyzing process is complete, a report contains the following information will be generated.

* Total requests received from each remote host.
* Number of requests received from each remote host per hour.
* Top X requests from each remote host.
* Request method, status, user agent and number of hits.


### Prerequisites
* Python 3

## Usage example
* Default, Parsing logs using Regex
```
web-log-analyzer $python3 run.py -i "/var/log/httpd/access_log.log" -o "report.html"
[+] Analyzing "/var/log/httpd/access_log.log" .. This may take some time.
[+] Generating report..
[+] Report saved to "report.html"
web-log-analyzer $
```
* Cusomt log format
```
web-log-analyzer $python3 run.py -i "/var/log/httpd/access_log.log" -o "report.html" -f "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\" %{Host}i%U%q"
[+] Analyzing "/var/log/httpd/access_log.log" .. This may take some time.
[+] Generating report..
[+] Report saved to "report.html"
web-log-analyzer $
```

### Tests
Tested against various types of log files including Nginx and Apache. However, if you have a custom Apache log format you can provide it using the parameter ```"--log-format"```


# Command Line Args
```
web-log-analyzer $python3 run.py --help
usage: 
        Web access log analyzer
        Project page: https://github.com/iomoath/web-log-analyzer
        
       [-h] -i LOG_FILE -o OUT [-f LOG_FORMAT] [--version]

optional arguments:
  -h, --help            show this help message and exit
  -i LOG_FILE, --log-file LOG_FILE
                        Log file path.
  -o OUT, --out OUT     Report output path.
  -f LOG_FORMAT, --log-format LOG_FORMAT
                        Custom Apache log format. If not set, then will try
                        parse logs using Regex.
  --version             show program's version number and exit
```

# Report sample
![Report_Sample](report_sample.png?raw=true "Report Sample")

