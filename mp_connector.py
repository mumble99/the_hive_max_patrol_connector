from thehive4py.api import TheHiveApi
from thehive4py.models import Case, CaseTask, CustomFieldHelper
from dateutil import parser
import datetime
import requests
import json
import copy
import os

requests.packages.urllib3.disable_warnings()
last_incident_time_file_path = "last_incident_time"


def write_last_incident_time(time):
    with open(last_incident_time_file_path, "w") as f:
        f.write(time)


def get_last_incident_time():
    if os.path.exists(last_incident_time_file_path):
        with open(last_incident_time_file_path) as f:
            return f.read() + "Z"
    return None


def prepare_template_string(template, event):
    template_name = template.get("name")
    template_args = template.get("args", [])
    if not template_name:
        return None
    temp_args = []
    for arg in template_args:
        temp_args.append(event.get(arg))
    if len(temp_args):
        template_name = template_name.format(*temp_args)
    return template_name


def custom_fields_append(conf_custom_fields, event):
    if not len(conf_custom_fields):
        return None
    custom_fields = CustomFieldHelper()
    for cf in conf_custom_fields:
        cf_type = cf.get("type")
        if cf_type == "string":
            if not cf.get("value"):
                custom_fields.add_string(cf.get("hive_name"), event.get(cf.get("siem_name")))
            else:
                custom_fields.add_string(cf.get("hive_name"), cf.get("value"))
        elif cf_type == "date":
            if not cf.get("value"):
                temp_date = event.get(cf.get("siem_name"))
                if isinstance(temp_date, int):
                    custom_fields.add_date(cf.get("hive_name"), temp_date * 1000)
                else:
                    try:
                        temp_date = int(
                            (parser.parse(temp_date)).timestamp()) * 1000
                    except Exception:
                        temp_date = int(datetime.datetime.now().timestamp()) * 1000
                    finally:
                        custom_fields.add_date(cf.get("hive_name"), temp_date)
            else:
                temp_date = cf.get("value")
                if temp_date(isinstance(temp_date, int)):
                    custom_fields.add_date(temp_date * 1000)
                else:
                    try:
                        temp_date = int(
                            (parser.parse(temp_date)).timestamp()) * 1000
                    except Exception:
                        temp_date = int(datetime.datetime.now().timestamp()) * 1000
                    finally:
                        custom_fields.add_date(cf.get("hive_name"), temp_date)

        elif cf_type == "boolean":
            if not cf.get("value"):
                custom_fields.add_boolean(cf.get("hive_name"), event.get(cf.get("siem_name")))
            else:
                custom_fields.add_boolean(cf.get("hive_name"), cf.get("value"))
        elif cf_type == "integer":
            if not cf.get("value"):
                custom_fields.add_integer(cf.get("hive_name"), event.get(cf.get("siem_name")))
            else:
                custom_fields.add_integer(cf.get("hive_name"), cf.get("value"))
        elif cf_type == "float":
            if not cf.get("value"):
                custom_fields.add_float(cf.get("hive_name"), event.get(cf.get("siem_name")))
            else:
                custom_fields.add_float(cf.get("hive_name"), cf.get("value"))
    return custom_fields


class UnauthenticatedError(Exception):
    pass


class ArgumentError(Exception):
    pass


class CreateCaseError(Exception):
    pass


class CreateTaskError(Exception):
    pass


class ConfigNotFoundError(Exception):
    pass


class ConfigInvalidFormat(Exception):
    pass


class Logging:
    PATH = "log"
    TIME_FORMAT = "%H:%M:%S %d.%m.%Y"

    @staticmethod
    def info(msg):
        with open(Logging.PATH, "a") as f:
            f.write("[INFO] %s %s\n" % (datetime.datetime.now().strftime(Logging.TIME_FORMAT), msg))

    @staticmethod
    def warning(msg):
        with open(Logging.PATH, "a") as f:
            f.write("[WARNING] %s %s\n" % (datetime.datetime.now().strftime(Logging.TIME_FORMAT), msg))

    @staticmethod
    def critical(msg):
        with open(Logging.PATH, "a") as f:
            f.write("[CRITICAL] %s %s\n" % (datetime.datetime.now().strftime(Logging.TIME_FORMAT), msg))


class Config:
    def __init__(self, config):
        self.__config = config
        self.inc_name = self.__config.get("inc_name")
        self.siem_filter_row = self.__config.get("siem_filter_row")
        self.custom_fields = self.__config.get("custom_fields")
        self.case_description_template = self.__config.get("case_description_template")
        self.case_template = self.__config.get("case_template")
        self.case_name_template = self.__config.get("case_name_template")
        self.case_tags = self.__config.get("case_tags")
        self.task_name_template = self.__config.get("task_name_template")
        self.analyst_email = self.__config.get("analyst_email")
        self.event_filter_template = {
            "filter": {
                "select": self.siem_filter_row,
                "where": "uuid = \"%s\"",
                "orderBy": [
                    {
                        "field": "time",
                        "sortOrder": "ascending"
                    }
                ],
                "groupBy": [],
                "aggregateBy": [],
                "distributeBy": [],
                "aliases": {},
                "searchType": "local",
                "searchSources": [],
                "localSources": [],
                "groupByOrder": [],
                "showNullGroups": False
            },
            "groupValues": [
                None
            ],
            "timeFrom": 0,
            "timeTo": None
        }

    def get_event_filter(self, event_uuid, time_from):
        ev_filter = copy.deepcopy(self.event_filter_template)
        ev_filter["filter"]["where"] = ev_filter["filter"]["where"] % event_uuid
        ev_filter["timeFrom"] = time_from
        return ev_filter


class HiveCase:
    def __init__(self, conf, event):
        self.hive_api_key = os.environ.get("THE_HIVE_API_KEY")
        self.hive_url = os.environ.get("hive_url") or "http://127.0.0.1:9000"
        self.conf = conf
        self.event = event
        self.conf_custom_fields = self.conf.custom_fields
        self.case_description = prepare_template_string(self.conf.case_description_template, self.event)
        self.conf_case_template = self.conf.case_template
        self.conf_case_name_template = self.conf.case_name_template
        self.conf_task_name_template = self.conf.task_name_template
        self.case_tags = self.conf.case_tags
        self.analyst_email = self.conf.analyst_email
        self.case_template = prepare_template_string(self.conf_case_template, event)
        self.case_name_template = prepare_template_string(self.conf_case_name_template, event)
        self.task_name_template = prepare_template_string(self.conf_task_name_template, event)

        if self.case_template:
            self.custom_fields = custom_fields_append(self.conf_custom_fields, self.event)

        if not self.hive_api_key:
            raise AttributeError("hive_api_key cannot be empty")

        if not self.analyst_email:
            raise AttributeError("analyst_email cannot be empty")

        if not self.case_name_template:
            raise AttributeError("case_name_template cannot be empty")

        if not self.task_name_template:
            raise AttributeError("task_name_template cannot be empty")

        self.api = TheHiveApi(self.hive_url, self.hive_api_key, cert=False)

    def add_to_hive(self):
        self.__create_task(self.__create_case())

    def __create_case(self):
        if self.case_template:
            case = Case(
                title=self.case_name_template,
                tlp=2,
                flag=True,
                owner=self.analyst_email,
                tags=self.case_tags,
                description=self.case_description if self.case_description else '',
                template=self.case_template,
                customFields=self.custom_fields.build()
            )
        else:
            case = Case(
                title=self.case_name_template,
                tlp=2,
                flag=True,
                owner=self.analyst_email,
                tags=self.case_tags,
                description=self.case_description if self.case_description else ''
            )
        create_case_response = self.api.create_case(case)
        if create_case_response.status_code == 201:
            Logging.info("case with name %s created" % self.case_name_template)
            return create_case_response.json().get("id")
        else:
            raise CreateCaseError("cannot create case with name %s" % self.case_name)

    def __create_task(self, case_id):
        create_task_response = self.api.create_case_task(case_id, CaseTask(
            title=self.task_name_template,
            owner=self.analyst_email,
            description="test",
            status="InProgress",
            flag=False,
            startDate=int(datetime.datetime.now().timestamp()) * 1000
        ))
        if create_task_response.status_code == 201:
            Logging.info("task with case id %s created" % case_id)
        else:
            raise CreateTaskError("error while create task with case id %s" % case_id)


class SiemApi:
    def __init__(self, siem_host, client_secret):
        self.host = siem_host
        self.client_secret = client_secret
        self.auth_url = "https://%s:3334/connect/token" % self.host
        self.incident_url = "https://%s/api/v2/incidents" % self.host
        self.events_url = "https://%s/api/events/v2/events" % self.host
        self.events_uuid_url = "https://{}/api/incidents/%s/events?limit=1".format(self.host)
        self.now = datetime.datetime.now()
        self.timestamp_str = get_last_incident_time() or str(
            datetime.datetime(self.now.year, self.now.month, self.now.day, 0, 0, 0).isoformat()) + "Z"
        self.access_token = None
        self.sess = requests.session()
        self.sess.verify = False
        self.incidents_filter = {
            "offset": 0,
            "limit": 50,
            "groups": {
                "filterType": "no_filter"
            },
            "timeFrom": self.timestamp_str,
            "timeTo": None,
            "filterTimeType": "creation",
            "filter": {
                "select": [
                    "key",
                    "name",
                    "category",
                    "type",
                    "status",
                    "created",
                    "assigned"
                ],
                "where": "status != \"Closed\"",
                "orderby": [
                    {
                        "field": "created",
                        "sortOrder": "descending"
                    },
                    {
                        "field": "status",
                        "sortOrder": "ascending"
                    },
                    {
                        "field": "severity",
                        "sortOrder": "descending"
                    }
                ]
            },
            "queryIds": [
                "all_incidents"
            ]
        }

        self.__get_auth_token()
        if self.access_token:
            self.sess.headers.update({"Authorization": "Bearer %s" % self.access_token})
        else:
            raise UnauthenticatedError("cannot authorize")

    def __get_auth_token(self):
        auth_data = {
            "client_id": "mpx",
            "client_secret": self.client_secret,
            "scope": "mpx.api",
            "response_type": "code token",
            "grant_type": "client_credentials"
        }
        auth_request = self.sess.post(self.auth_url, data=auth_data)
        auth_response = auth_request.json()
        self.access_token = auth_response.get("access_token")

    def get_all_incidents(self):
        incident_request = self.sess.post(self.incident_url, json=self.incidents_filter)
        if incident_request.status_code == 200:
            Logging.info("get all incidents")
            incident_response = incident_request.json()
            incidents = incident_response.get("incidents")
            if incidents and len(incidents):
                latest_incident_time_utc = parser.parse(incidents[0].get("created"))
                latest_incident_time = latest_incident_time_utc + datetime.timedelta(hours=3)
                write_last_incident_time(str(latest_incident_time.isoformat()))
                incidents_info = []
                for incident in incidents:
                    incident_uuid = incident.get("id")
                    incident_name = incident.get("name")
                    event_stat = self.__get_event_of_incident_by_uuid(incident_uuid)
                    event_uuid = event_stat.get("uuid")
                    event_date = event_stat.get("date")
                    if event_uuid and event_date:
                        incidents_info.append({
                            "incident_name": incident_name,
                            "event_uuid": event_uuid,
                            "event_date": event_date
                        })
                return incidents_info

            return []
        else:
            Logging.warning("error get all incidents %s" % incident_request.text)
            return []

    def __get_event_of_incident_by_uuid(self, uid):
        events_request = self.sess.get(self.events_uuid_url % uid)
        event_stat = {
            "uuid": "",
            "date": 0
        }
        if events_request.status_code == 200:
            Logging.info("get events of incident by uuid %s" % uid)
            events_response = events_request.json()
            for event in events_response:
                event_stat["uuid"] = event.get("id")
                date_of_event = parser.parse(event.get("date"))
                event_stat["date"] = int(date_of_event.timestamp())
                return event_stat
            return event_stat
        else:
            Logging.warning("error get events of incident by uuid %s" % events_request.text)
            return event_stat

    def get_event_by_uuid(self, uid, date, event_filter, selected_fields):
        event_request = self.sess.post(self.events_url, json=event_filter)
        if event_request.status_code == 200:
            event_response = event_request.json()
            if event_response.get("errors") is None and len(event_response.get("events")):
                Logging.info("get event by uuid %s" % uid)
                event_raw = event_response.get("events")[0]
                event = {"date": date * 1000}
                for k in selected_fields:
                    event[k] = event_raw.get(k)
                return event
            else:
                return {}
        else:
            Logging.warning("error get event by uuid %s" % event_request.text)
            return {}


if __name__ == "__main__":
    try:
        api_secret = os.environ.get("client_secret")
        siem_host = os.environ.get("siem_host")
        file_path = os.environ.get("conf_path") or "config.json"

        if not api_secret:
            raise ArgumentError("api_secret must be specified")
        if not siem_host:
            raise ArgumentError("siem_host must be specified")

        os.environ.setdefault("no_proxy", siem_host)

        if not os.path.exists(file_path):
            raise ConfigNotFoundError("file %s doesnt exists" % file_path)

        with open(file_path, encoding="utf-8") as f:
            raw_conf = f.read()
        try:
            raw_conf_list = json.loads(raw_conf)
        except json.JSONDecodeError:
            raise ConfigInvalidFormat("invalid config format. should be json")

        configs = []
        for rc in raw_conf_list:
            configs.append(Config(rc))

        sa = SiemApi(siem_host, api_secret)
        all_incidents = sa.get_all_incidents()
        to_hive = []
        for inc in all_incidents:
            for c in configs:
                if inc.get("incident_name") == c.inc_name:
                    uid = inc.get("event_uuid")
                    timestamp = inc.get("event_date")
                    event_filter = c.get_event_filter(uid, timestamp)
                    event = sa.get_event_by_uuid(uid, timestamp, event_filter, c.siem_filter_row)
                    to_hive.append(HiveCase(c, event))

        for hc in to_hive:
            hc.add_to_hive()

    except Exception as e:
        Logging.critical(e)
