#!/usr/bin/python3

# ////////////////////////////////////////////////////////////////////////////////
# ////////////              Integration Details START              ///////////////

###############################################################
##       Confidential Document © Cybecs Solutions LTD        ##
###############################################################
##  File     | Sophos-Wazuh API Integration                  ##
##  Author   | Mike Lasriness                                ##
##  Date     | 13-11-2023                                    ##
##  Version  | 02                                            ##
##  API Docs | https://developer.sophos.com/docs/common-v1/1 ##
###############################################################

# /////////////              Integration Details END              ////////////////
# ////////////////////////////////////////////////////////////////////////////////

# ////////////////////////////////////////////////////////////////////////////////
# ////////////              Imports & Constants START              ///////////////

import requests
import logging
import json
import sys
import base64 as bsf
import shutil
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from urllib.parse import urlencode
from socket import socket

PLATFORM = sys.platform
LINUX_PLAT = "linux"
_IS_LINUX = bool(PLATFORM.lower() == LINUX_PLAT.lower())
if _IS_LINUX: from socket import AF_UNIX, SOCK_DGRAM

ON,OFF = True,False
COLS_IX,ROWS_IX = 0,1
 
# /////////////              Imports & Constants END              ////////////////
# ////////////////////////////////////////////////////////////////////////////////

# /////////////////////////////////////////////////////////////////////////////
# ///////////////                Classes & Enums                ///////////////
# /////////////////////////////////////////////////////////////////////////////

class Cfg:

    DEBUG = ON
    INTEGRATION_PLATFORM_NAME = "Sophos"
    
    CLIENT_ID =     "ZjljY2YxYTQtMzFlZi00ZTY5LWI5MTMtYTQ3YzA5N2ExYTM3"
    TENANT_ID =     "NGUxNjE1MTktYzNkMC00ZjZiLWE1YTgtZjQyZDZlMDQzMTJm"
    CLIENT_SECRET = "ZTU4N2NiMjg4ZThhZDE4ZDRkNWYzNzYzZjQxNTA2MzAxODJhNmFkODNiMWI1ZDQ3Mjg2YTVlZmNmNGJkZThkOWY5ZTA5NDQ1YjFlZTNhZjgxNTM0NmE3NGM0NjM1OGE4OTkxOA=="

    SEND_DATA   = ON
    LOG_DATA    = OFF
    LOG_PATH    = ""
    
    GLOBAL_FILTER_HOURS = 1
    GLOBAL_FILTER_MINUTES = 0
    GLOBAL_FILTER_SECONDS = 0

    IS_LINUX = _IS_LINUX

class Keys:
    TO              = "to"
    VAL             = "value"
    B64             = "base64"
    JWT             = "JWT"
    FROM            = "from"
    MAIN            = "__main__"
    DONE            = "Done"
    ROLES           = "Roles"
    ERROR           = "ERROR"
    EMPTY           = ""
    QUERY           = "query"
    SCOPE           = "scope"
    SCORE           = "score"
    HOURS           = "hours"
    SOPHOS          = "Sophos"
    FILTER          = "filter"
    ENABLED         = "enabled"
    MINUTES         = "minutes"
    SECONDS         = "seconds"
    RESOURCE        = "resource"
    CLIENT_ID       = "client_id"
    GRANT_TYPE      = "grant_type"
    ACCESS_TOKEN    = "access_token"
    CONTENT_TYPE    = "Content-Type"
    CLIENT_SECRET   = "client_secret"

class Filter:
    ALERTS = {
        Keys.ENABLED: ON,
        Keys.VAL: {
            Keys.HOURS: Cfg.GLOBAL_FILTER_HOURS,
            Keys.MINUTES: Cfg.GLOBAL_FILTER_MINUTES,
            Keys.SECONDS: Cfg.GLOBAL_FILTER_SECONDS
        }
    }
class FilterObject(ABC):
    def __init__(self) -> None:
        super().__init__()
        self.enabled: bool = True
    
    def set_enabled(self, isEnabled: bool = True) -> None:
        self.enabled = isEnabled

    @abstractmethod
    def to_query_params(self) -> str:
        pass

    @abstractmethod
    def build_params_dict(self) -> dict:
        pass

    def __str__(self) -> str:
        return f"\tEnabled: {self.enabled}"

class TimeFrame:
    def __init__(self, seconds:int = 0, minutes:int = 0, hours:int = 0) -> None:
        self.seconds: int = seconds
        self.minutes: int = minutes
        self.hours:   int = hours

    def get_seconds(self) -> int: return self.seconds
    def get_minutes(self) -> int: return self.minutes
    def get_hours(self)   -> int: return self.hours

    def to_time_delta(self) -> timedelta:
        return timedelta(hours=self.hours, minutes=self.minutes, seconds=self.seconds)
    def __str__(self) -> str:
        return f"\tTime Frame:\n\t\tSeconds: {self.seconds}\n\t\tMinutes: {self.minutes}\n\t\tHours: {self.hours}"
class TimeFilter(FilterObject):

    def __init__(self, timeframe: TimeFrame = None, startKeyword=Keys.FROM, endKeyword=Keys.TO) -> None:
        super().__init__()

        self.start: str = None
        self.end:   str = None

        self.frame: TimeFrame = None
        self.format = "%Y-%m-%dT%H:%M:%SZ"
        
        self.set_start_keyword(startKeyword)
        self.set_end_keyword(endKeyword)

        if timeframe is None: timeframe = TimeFrame()
        self.set_time_frame(timeframe)

    def set_time_frame(self, timeframe: TimeFrame) -> None: self.frame = timeframe
    def set_time_format(self, format: str) -> None: self.format = format

    def set_start_keyword(self, keyword) -> None: self.start = keyword
    def set_end_keyword(self, keyword)   -> None: self.end   = keyword

    def build_params_dict(self) -> dict:
        end_time: datetime = datetime.now()
        start_time: datetime = end_time - self.frame.to_time_delta()
        end_time = end_time.strftime(self.format)
        start_time = start_time.strftime(self.format)
        return dict({ self.start: start_time, self.end: end_time })
    
    def to_query_params(self) -> str:
        params_dict = self.build_params_dict()
        return urlencode(params_dict)

    def  s(self) -> str:
        params_dict = self.build_params_dict()
        return urlencode(params_dict)
    
    def __str__(self) -> str:
        super_str = super().__str__()
        return f"Time Filter:\n{super_str}\n{str(self.frame)}\n\tStart Keyword: \"{self.start}\"\n\tEnd Keyword: \"{self.end}\"\n"

class CodecType:
    B64 = Keys.B64
    DEFAULT = B64
class Codec:
    
    def __init__(self, type=CodecType.B64) -> None:
        self.type = type

    @staticmethod
    def b64_encode(data):
        return bsf.b64encode(data.encode('utf-8')).decode()
    
    @staticmethod
    def b64_decode(data):
        return bsf.b64decode(f"{data}").decode()
    
    def encode(self, data):
        if self.type == CodecType.B64: return self.b64_encode(data)
    
    def decode(self, data):
        if self.type == CodecType.B64: return self.b64_decode(data)

class Creds:
    TENANT_ID = Codec.b64_decode(Cfg.TENANT_ID)
    CLIENT_ID = Codec.b64_decode(Cfg.CLIENT_ID)
    CLIENT_SECRET = Codec.b64_decode(Cfg.CLIENT_SECRET)

class HeaderKey:
    CONTENT_TYPE = "Content-Type"
    ACCEPT = 'Accept'
    AUTHORIZATION = 'Authorization'
    ACCEPT_ENCODING = 'Accept-Encoding'
    GRANT_TYPE = "grant_type"
    CLIENT_ID = "client_id"
    CLIENT_SECRET = "client_secret"
    SCOPE = "scope"
    TENANT_ID = "X-Tenant-ID"
class HeaderVal:
    APP_JSON = "application/json"
    G_ZIP = "gzip"
    BASIC = "Basic"
    BEARER = "Bearer"
    TOKEN = "token"
    CLIENT_CREDS = "client_credentials"

class DataRegion:
    US = "us01" # United States
    EU = "eu01" # Europe
    CA = "ca01" # Canada
    AU = "au01" # Australia
    AS = "ap01" # Asia
class EndPoint:
    SOCK_ADDR = '/var/ossec/queue/sockets/queue'                      # Wazuh manager analisysd socket address
    SCHEMA = "https"
    BASE = "https://api.securitycenter.microsoft.com"                 # Azure AD API base url
    SCOPE = "token"                                                   # The scope for the authentication token
    API = f"https://api-{DataRegion.CA}.central.sophos.com/common/v1" # the URL for API endpoints

    # OAuth2 authentication endpoint
    AUTH_VER = "v2"   
    AUTH_METHOD = "oauth2"                                                      # Authenrication method
    AUTH_URL = f"{SCHEMA}://id.sophos.com/api/{AUTH_VER}/{AUTH_METHOD}/{SCOPE}" # Authentication URL
    
    REGION = DataRegion.EU
    RESOURCE_API_VER = "v1"

class ResourceUrl:
    ALERTS = f"{EndPoint.SCHEMA}://api-{EndPoint.REGION}.central.sophos.com/common/{EndPoint.RESOURCE_API_VER}/alerts"
    ADMINS = f"{EndPoint.SCHEMA}://api-{EndPoint.REGION}.central.sophos.com/common/{EndPoint.RESOURCE_API_VER}/admins"
    ROLES  = f"{EndPoint.SCHEMA}://api-{EndPoint.REGION}.central.sophos.com/common/{EndPoint.RESOURCE_API_VER}/roles"
class BlockName:
    ALERTS = "alerts"
    ADMINS = "admins"
    ROLES  = "roles"

# /////////////////////////////////////////////////////////////////////////////
# //////////////               Functions & Lambdas               //////////////
# /////////////////////////////////////////////////////////////////////////////

# lambdas
get_terminal_size = lambda: shutil.get_terminal_size()
get_terminal_width = lambda: get_terminal_size()[COLS_IX]
get_terminal_height = lambda: get_terminal_size()[ROWS_IX]
json_print = lambda d: print(json.dumps(d, indent=2))

# logging functions
def write_to_log(path, data, mode='a'):
    """ Writes data to a file """
    with open(path, mode) as file:
        if isinstance(data, str):
            file.write(data + '\n')
        elif isinstance(data, dict):
            json.dump(data, file)
            file.write('\n')
        else: raise ValueError(f"Writing data of type {type(data)} to file is not supported. Expected str/dict")
def send_event(msg):
    """" Sends a single event 'msg' to the UNIX socket ADDR """
    logging.debug('Sending {} to {} socket.'.format(msg, EndPoint.SOCK_ADDR))
    string = f"1:{Cfg.INTEGRATION_PLATFORM_NAME.lower()}:{msg}"
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(EndPoint.SOCK_ADDR)
    sock.send(string.encode())
    sock.close()
def send_events_from_json(jsonObj, tag, dataField="items"):
    """" Sends multiple events from a JSON object to the UNIX socket ADDR """
    if not isinstance(jsonObj, dict): return
    if not len(jsonObj[dataField]):
        if Cfg.DEBUG: print(f"No items for {tag}")
        return
    for alert in jsonObj[dataField]:
        evt = {}
        evt[Cfg.INTEGRATION_PLATFORM_NAME.lower()] = alert
        evt[Keys.QUERY] = tag
        data = json.dumps(evt)
        if Cfg.LOG_DATA: write_to_log(Cfg.LOG_PATH, data)
        print(data)
        if Cfg.SEND_DATA and Cfg.IS_LINUX: send_event(data)
def delimeter(content="", symbol="-"):
    """ Prints a delimiter line on console CMD with 'content' message in the middle of the line """
    if not Cfg.DEBUG: return
    if len(content)==0: 
        print(symbol*get_terminal_width())
        return
    content = f" {content} "
    side_count = int((get_terminal_width()-len(content))/2)
    side_str = symbol*side_count
    print(f"{side_str}{content}{side_str}")

# auth functions
def get_jwt():
    """ Retrieves the Json Web Token for authorizatrion """
    try:
        if Cfg.DEBUG: delimeter("JWT")
        response = requests.post(EndPoint.AUTH_URL, get_auth_body(), get_auth_headers())
        jwt = response.json()[Keys.ACCESS_TOKEN]
        if Cfg.DEBUG: 
            json_print({Keys.JWT:jwt})
            delimeter("JWT Obtained")
        return jwt
    except Exception as e:
        print(f"{Keys.ERROR} - get_jwt: {get_jwt.__name__} - {str(e)}")
        exit(1)
def get_auth_body():
    """" Retrieves dictionary object to represent the message body of a POST authentication request """
    body = {
        HeaderKey.SCOPE         : HeaderVal.TOKEN,
        HeaderKey.CLIENT_ID     : Creds.CLIENT_ID,
        HeaderKey.GRANT_TYPE    : HeaderVal.CLIENT_CREDS,
        HeaderKey.CLIENT_SECRET : Creds.CLIENT_SECRET
    }
    return body
def get_auth_headers(): 
    """" Retrieves dictionary object to represent the headers of a POST authentication request """
    headers = { HeaderKey.CONTENT_TYPE: HeaderVal.APP_JSON }
    return headers
def get_resource_headers(token):
    """" Retrieves dictionary object to represent the headers of a GET resource request """
    return {
        HeaderKey.AUTHORIZATION: f"{HeaderVal.BEARER} {token}",
        HeaderKey.ACCEPT       : HeaderVal.APP_JSON,
        HeaderKey.TENANT_ID    : Creds.TENANT_ID
    }

# assistance functions
def create_query_params_time_filter(hours=1,minutes=0,seconds=0):
    """ Generates the URL's query params for time-based filtering """
    print("A")
    timefilter = TimeFilter()
    print("B")
    timefilter.set_time_frame(TimeFrame(hours=hours, minutes=minutes, seconds=seconds))
    return timefilter.to_query_params()

# resources functinos
def get_alerts(token):
    """ Retrieves the "Alerts" resource type from the API center """
    try:
        if Cfg.DEBUG: delimeter("Get Alerts")

        url = ResourceUrl.ALERTS
        addition = Keys.EMPTY

        if Filter.ALERTS[Keys.ENABLED]:
            addition = "?" + create_query_params_time_filter(
                hours   = Filter.ALERTS[Keys.VAL][Keys.HOURS],
                minutes = Filter.ALERTS[Keys.VAL][Keys.MINUTES],
                seconds = Filter.ALERTS[Keys.VAL][Keys.SECONDS]
            )
            url += addition
            if Cfg.DEBUG: json_print({"Url":url})

        response = requests.get(
            url=url,
            headers=get_resource_headers(token)
        )

        if Cfg.DEBUG: 
            json_print(response.json())
            delimeter("Alerts Obtained")

        return response.json()
    
    except Exception as e:
        print(f"{Keys.ERROR}: {get_alerts.__name__} - {str(e)}")
        exit(1)
def get_admins(token):
    """ Retrieves the "Admins" resource type from the API center """
    try:
        if Cfg.DEBUG: delimeter("Get Admins")
        response = requests.get(
            url=ResourceUrl.ADMINS,
            headers=get_resource_headers(token)
        )
        if Cfg.DEBUG:
            json_print(response.json())
            delimeter("Admins Obtained")
        return response.json()
    
    except Exception as e:
        print(f"{Keys.ERROR}: {get_admins.__name__} - {str(e)}")
        exit(1)
def get_roles(token):
    """ Retrieves the "Roles" resource type from the API center """
    try:
        if Cfg.DEBUG: delimeter("Get Roles")
        response = requests.get(
            url=ResourceUrl.ROLES,
            headers=get_resource_headers(token)
        )
        if Cfg.DEBUG:
            json_print(response.json())
            delimeter("Roles Obtained")
        return response.json()
    
    except Exception as e:
        print(f"{Keys.ERROR}: {get_admins.__name__} - {str(e)}")
        exit(1)

# /////////////////////////////////////////////////////////////////////////////
# /////////////              Script's Core Functions              /////////////
# /////////////////////////////////////////////////////////////////////////////

def main():
    """ Core function """
    jwt = get_jwt()
    
    send_events_from_json(get_alerts(jwt), BlockName.ALERTS)
    send_events_from_json(get_admins(jwt), BlockName.ADMINS)
    send_events_from_json(get_roles(jwt), BlockName.ROLES)

if __name__ == Keys.MAIN:
    main()
    print(Keys.DONE)
