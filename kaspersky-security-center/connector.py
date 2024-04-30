"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""
from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations, _check_health

logger = get_logger('kaspersky-security-center')


class KasperskySecurityCenter(Connector):
    def execute(self, config, operation, operation_params, **kwargs):
        try:
            operation = operations.get(operation)
            return operation(config, operation_params)
        except Exception as err:
            logger.error('{0}'.format(err))
            raise ConnectorError('{0}'.format(err))

    def check_health(self, config):
        try:
            _check_health(config)
        except Exception as e:
            raise ConnectorError(e)
