import json
import time
import requests
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('proofpoint-tap')


class ProofpointTAP:
    def __init__(self, config):
        self.base_url = config.get('server').strip()
        if not self.base_url.startswith('https://'):
            self.base_url = 'https://' + self.base_url
        self.password = config.get('password')
        self.username = config.get('username')
        self.verify_ssl = config.get('verify_ssl')
        self.test_url = '/v2/siem/all'
        self.api_path_campaign = '/v2/campaign/{}'
        self.api_path_forensics = '/v2/forensics'

    def get_epoch(self, start_date):
        try:
            pattern = '%Y-%m-%dT%H:%M:%S.%fZ'
            return int(time.mktime(time.strptime(start_date, pattern)))
        except Exception as Err:
            logger.exception('get_epoch: Exception occurred [{0}]'.format(str(Err)))
            raise ConnectorError('get_epoch: Exception occurred [{0}]'.format(str(Err)))

    def make_rest_call(self, endpoint, params={}):
        url = '{0}{1}'.format(self.base_url, endpoint)
        logger.info('Request URL {}'.format(url))
        try:
            response = requests.get(url, params=params, auth=(self.username, self.password), verify=self.verify_ssl)
            if response.ok:
                return json.loads(response.content.decode('utf-8'))
            response.raise_for_status()
        except Exception as err:
            logger.exception('{}'.format(err))
            raise ConnectorError('{}'.format(err))

    def threat_status_endpoint(self, threat_status):
        endpoint = ''
        for each_status in threat_status:
            endpoint += '&threatStatus=' + each_status.lower()
        return endpoint

    def threat_type_endpoint(self, threat_type):
        endpoint = ''
        for each_type in threat_type:
            endpoint += '&threatType=' + each_type.lower()
        return endpoint


def get_events(config, param, endpoint):
    proofpoint = ProofpointTAP(config)
    out_format = param.get('format').lower()
    interval = param.get('interval')
    if interval == 'Seconds':
        interval_type = 'sinceSeconds={since_seconds}'.format(since_seconds=param.get('sinceSeconds'))
    elif interval == "Interval":
        interval_type = 'interval=' + param.get('intervalTime')
    else:
        interval_type = 'sinceTime={since_time}'.format(since_time=param.get('sinceTime'))
    threat_status = proofpoint.threat_status_endpoint(param.get('threat_status'))
    threat_type = proofpoint.threat_type_endpoint(param.get('threat_type'))
    request_url = '{endpoint}?format={format}&{interval}{threat_type}' \
                  '{threat_status}'.format(endpoint=endpoint,
                                           format=out_format,
                                           interval=interval_type,
                                           threat_type=threat_type,
                                           threat_status=threat_status)
    return proofpoint.make_rest_call(request_url)


def _check_health(config):
    proofpoint = ProofpointTAP(config)
    payload = {'format': 'json', 'sinceSeconds': 3600}
    try:
        response = proofpoint.make_rest_call(proofpoint.test_url, payload)
        if response:
            return True
    except Exception as err:
        raise ConnectorError('Invalid URL/login credential')


def get_campaign_details(config, param):
    proofpoint = ProofpointTAP(config)
    campaign_url = proofpoint.api_path_campaign.format(param.get('campaign_id'))
    return proofpoint.make_rest_call(campaign_url)


def get_forensic(config, param):
    proofpoint = ProofpointTAP(config)
    _id = param.get('id')
    endpoint = '/v2/forensics?'
    include_campaign_forensics = param.get('include_campaign_forensics', False)
    value = param.get('value')
    if _id == 'Campaign ID':
        endpoint += 'campaignId={0}'.format(value)
    else:
        endpoint += 'threatId={0}&includeCampaignForensics={1}'.format(value, include_campaign_forensics)
    return proofpoint.make_rest_call(endpoint)


def get_clicks_blocked_event(config, params):
    endpoint = '/v2/siem/clicks/blocked'
    return get_events(config, params, endpoint)


def get_clicks_permitted_event(config, params):
    endpoint = '/v2/siem/clicks/permitted'
    return get_events(config, params, endpoint)


def get_messages_blocked_event(config, params):
    endpoint = '/v2/siem/messages/blocked'
    return get_events(config, params, endpoint)


def get_clicks_delivered_event(config, params):
    endpoint = '/v2/siem/messages/delivered'
    return get_events(config, params, endpoint)


def get_all_events(config, params):
    endpoint = '/v2/siem/all'
    return get_events(config, params, endpoint)


def get_issues_event(config, params):
    endpoint = '/v2/siem/issues'
    return get_events(config, params, endpoint)


operations = {
    'get_clicks_blocked_event': get_clicks_blocked_event,
    'get_clicks_permitted_event': get_clicks_permitted_event,
    'get_messages_blocked_event': get_messages_blocked_event,
    'get_clicks_delivered_event': get_clicks_delivered_event,
    'get_all_events': get_all_events,
    'get_issues_event': get_issues_event,
    'get_campaign_details': get_campaign_details,
    'get_forensic': get_forensic
}
