from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations, _check_health

logger = get_logger('proofpoint-tap')


class ProofpointTAP(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            logger.info('In execute() Operation:[{0}]'.format(operation))
            action = operations.get(operation)
            return action(config, params)
        except Exception as e:
            logger.error(e)
            raise ConnectorError(e)

    def check_health(self, config):
        try:
            _check_health(config)
        except Exception as e:
            logger.exception("An exception occurred in check_health {0}".format(e))
            raise ConnectorError(e)
