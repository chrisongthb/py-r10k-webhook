#!/usr/bin/env python3

import http, os, json, re, sys, syslog, configparser, socket, ssl, base64
from http.server import HTTPServer, SimpleHTTPRequestHandler

#######################################################################
## functions
#######################################################################
# loggers for syslog local0 and stdout/stderr
def logger_error(log_text):
    syslog.syslog(syslog.LOG_LOCAL0 | syslog.LOG_ERR, log_text)
    print('E: ' + log_text, file=sys.stderr)

def logger_warning(log_text):
    syslog.syslog(syslog.LOG_LOCAL0 | syslog.LOG_WARNING, log_text)
    print('W: ' + log_text,file=sys.stderr)

def logger_info(log_text):
    syslog.syslog(syslog.LOG_LOCAL0 | syslog.LOG_INFO, log_text)
    print('I: ' + log_text)

def logger_debug(log_text):
    syslog.syslog(syslog.LOG_LOCAL0 | syslog.LOG_DEBUG, log_text)
    print('D: ' + log_text)

# config parser
def get_r10kwebhook_config(config, section, option, default_value=None):
    if config.has_option(section, option):
        logger_debug('Found value for [' + section + ']/[' + option + '] in config file: "' + config.get(section, option) + '"')
        return config.get(section, option)

    elif default_value != None:
        logger_debug('Using pre-defined value for [' + section + ']/[' + option + '], as no config is given in config file: "' + default_value + '"')
        return default_value

    else:
        logger_warning('Key [' + section + ']/[' + option + '] not found in config file.')
        raise configparser.NoOptionError(option, section)

# socket config parser
def get_r10kwebhook_socket(config, httpd):
    if config.has_section('ssl'):

        # get mandatory SSL params
        ssl_cert = get_r10kwebhook_config(config, 'ssl', 'ssl_cert')
        ssl_key = get_r10kwebhook_config(config, 'ssl', 'ssl_key')

        # get optional SSL CA param
        try:
            ssl_ca = get_r10kwebhook_config(config, 'ssl', 'ssl_ca')
            logger_debug('Configuring HTTPS with ssl_cert, ssl_key, ssl_ca')
            return ssl.wrap_socket(httpd.socket, certfile=ssl_cert, keyfile=ssl_key, ca_certs=ssl_ca, server_side=True)

        except configparser.NoOptionError:
            logger_warning('Could not configure ssl_ca for https socket. Using weak SSL (only ssl_cert + ssl_key).')
            return ssl.wrap_socket(httpd.socket, certfile=ssl_cert, keyfile=ssl_key, server_side=True)

    else:
        logger_warning('Section "ssl" is not configured in ' + config_file + '. Falling back to HTTP - only')
        return httpd.socket

#######################################################################
## Method Overriding of SimpleHTTPRequestHandler
#######################################################################
class R10kwebhook(SimpleHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'Method not supported.\n')
        return

    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'Method not supported.\n')
        return

    def do_POST(self):

        # read payload
        payload = self.rfile.read(int(self.headers.get('Content-Length', 0)))

        # set response after reading content
        # see also https://docs.gitlab.com/ee/user/project/integrations/webhooks.html#webhook-endpoint-tips
        #   * "Your endpoint should send its HTTP response as fast as possible"
        #   * "Your endpoint should ALWAYS return a valid HTTP response"
        #   * "GitLab ignores the HTTP status code returned by your endpoint."
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

        # check headers
        # for gitlab request header see
        # https://docs.gitlab.com/ee/user/project/integrations/webhooks.html#push-events
        if not self.headers.get_content_type() == 'application/json':
            logger_warning('Ignoring request. Expected content type "application/json" not found.')

        elif not 'X-Gitlab-Event' in str(self.headers):
            logger_warning('Ignoring Request. Expected header "X-Gitlab-Event" not found.')

        elif not 'Push Hook' in str(self.headers):
            logger_warning('Ignoring Request. Expected X-Gitlab-Event: "Push Hook" not found in headers.')

        elif base64key != None and not ('Authorization' in str(self.headers) and str('Basic ' + base64key) in str(self.headers)):
            logger_warning('Ignoring Request. Authorization failed.')

        # all header checks passed
        # continuing with path check
        # for example payload see
        # https://docs.gitlab.com/ee/user/project/integrations/webhooks.html#push-events
        else:
            try:
                payload_json = json.loads(payload.decode('utf8'))
                if self.path == '/api/v1/r10k/environment/':
                    # split: e.g. take 'dev' out of 'refs/heads/dev'
                    r10k_environment = payload_json["ref"].split("/")[-1]
                    logger_info('Triggering r10k environment deployment for env "' + r10k_environment + '"...')
                    os.environ['R10KENV'] = r10k_environment
                    os.system(r10k_environment_command)
                elif self.path == '/api/v1/r10k/module/':
                    # split: take the string behind the last '-' to support common Puppet module names
                    r10k_modulename = payload_json["project"]["name"].split("-")[-1]
                    logger_info('Triggering r10k module deployment for mod "' + r10k_modulename + '"...')
                    os.environ['R10KMODULE'] = r10k_modulename
                    os.system(r10k_module_command)
                else:
                    logger_warning('Ignoring path "' + self.path + '".')
            except KeyError as key_xcpt:
                logger_warning('Could not find key in payload: ' + str(key_xcpt))
            except json.decoder.JSONDecodeError as json_xcpt:
                logger_warning('Could not decode json payload: ' + str(json_xcpt))
        return

# provide ipv6 server
class HTTPServerV6(HTTPServer):
    address_family = socket.AF_INET6

#######################################################################
## main
#######################################################################
# load the config file which is the first param
try:
    config_file = sys.argv[1]

except IndexError:
    logger_error('Missing config file in params. Syntax: "' + sys.argv[0] + ' /path/to/<config.ini>"')
    exit(1)

# read the config file into the configparser
with open(config_file, 'r', encoding='utf-8') as f:
    config = configparser.ConfigParser()
    config.read_file(f)

#########################
# parse configs
logger_info('Parsing configs from "' + config_file + '"...')

# for ssl params see function get_r10kwebhook_socket
listen_addr              = get_r10kwebhook_config(config, 'main', 'listen_addr')
listen_port              = get_r10kwebhook_config(config, 'main', 'listen_port')
r10k_module_command      = get_r10kwebhook_config(config, 'r10k', 'r10k_module_command', 'r10k deploy environment "$R10KENV" -v -p')
r10k_environment_command = get_r10kwebhook_config(config, 'r10k', 'r10k_environment_command', 'r10k deploy module "$R10KMODULE" -v')

# prepare basic auth
try:
    basic_auth_user = get_r10kwebhook_config(config, 'auth', 'user')
    basic_auth_pass = get_r10kwebhook_config(config, 'auth', 'pass')
    # encode user:pass string
    logger_info('Configuring basic auth...')
    base64key       = base64.b64encode(bytes(basic_auth_user + ':' + basic_auth_pass, 'utf-8')).decode("utf-8")

except configparser.NoOptionError:
    base64key = None
    logger_warning('Not using basic authentication.')


#########################
# Build HTTPServer, depending on configured listen_address
try:
    httpd = HTTPServer((listen_addr, int(listen_port)), R10kwebhook)
    logger_info('Bound address "' + listen_addr + '", port "' + listen_port + '" (ipv4 - only)')
except socket.gaierror:
    logger_info('Could not bind address "' + listen_addr + '". Trying ipv6...')
    httpd = HTTPServerV6((listen_addr, int(listen_port)), R10kwebhook)
    logger_info('Bound address "' + listen_addr + '", port "' + listen_port + '" (ipv6 + ipv4)')

# The webhook provides both http and https sockets
# For https, there's at least ssl_key and ssl_cert required. Param ssl_ca is optional.
# If there is no ssl section in the config file, the webhook uses http as fallback.
httpd.socket = get_r10kwebhook_socket(config, httpd)

#########################
# start http server
logger_info('r10k webhook started.')
httpd.serve_forever()
