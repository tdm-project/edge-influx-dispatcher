#!/usr/bin/env python
#
#  Copyright 2021, CRS4 - Center for Advanced Studies, Research and Development
#  in Sardinia
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

"""
Edge Gateway Remote Dispatcher microservice for InfluxDB.
"""

import re
import sys
import signal
import json
import logging
import influxdb
import argparse
import configparser
import requests
import paho.mqtt.client as mqtt

from contextlib import contextmanager


MQTT_LOCAL_HOST = "localhost"  # Local MQTT Broker address
MQTT_LOCAL_PORT = 1883         # Local MQTT Broker port

INFLUXDB_REMOTE_HOST = ""             # Remote InfluxDB address
INFLUXDB_REMOTE_PORT = 8086           # Remote InfluxDB port
INFLUXDB_REMOTE_DB = ""               # Remote InfluxDB database
INFLUXDB_REMOTE_USER = ""             # Remote InfluxDB username
INFLUXDB_REMOTE_PASS = ""             # Remote InfluxDB password

APPLICATION_NAME = 'influxdb_dispatcher'


TOPIC_LIST = [
    'WeatherObserved',
#    'EnergyMonitor',
#    'DeviceStatus'
]

def edge_serial():
    """Retrieves the serial number from the hardware platform."""
    _serial = None
    with open('/proc/cpuinfo', 'r') as _fp:
       for _line in _fp:
            _match = re.search(r'Serial\s+:\s+0+(?P<serial>\w+)$', _line)
            if _match:
                _serial = _match.group('serial').upper()
                break

    return _serial


def try_cast_to_float(value):
    try:
        return float(value)
    except ValueError:
        return value


@contextmanager
def influxdb_connection(host, port, database, username, password, logger):
    _client = influxdb.InfluxDBClient(
        host=host,
        port=port,
        database=database,
        username=username,
        password=password
    )

    try:
        _dbs = _client.get_list_database()
        if database not in [_d['name'] for _d in _dbs]:
            logger.info(
                "InfluxDB database '{:s}' not found. Creating a new one.".
                format(database))
            _client.create_database(database)

        yield _client
    except:
        yield _client
    finally:
        _client.close()


class MQTTConnection():
    """Helper class for MQTT connection handling"""

    def __init__(self, host='localhost', port=1883, keepalive=60, logger=None,
                 userdata=None):
        # pylint: disable=too-many-arguments
        self._host = host
        self._port = port
        self._keepalive = keepalive
        self._userdata = userdata

        self._logger = logger
        if self._logger is None:
            self._logger = logger.getLoger()

        self._local_client = mqtt.Client(userdata=self._userdata)
        self._local_client.on_connect = self._on_connect
        self._local_client.on_message = self._on_message
        self._local_client.on_disconnect = self._on_disconnect

        if self._userdata['INFLUXDB_REMOTE_HOST']:
            self._remote_relay_enabled = True
        else:
            self._remote_relay_enabled = False

    def connect(self):
        self._logger.debug("Connecting to Local MQTT broker '{:s}:{:d}'".
                           format(self._host, self._port))
        try:
            self._local_client.connect(self._host, self._port, self._keepalive)
        except Exception as ex:
            self._logger.fatal(
                "Connection to Local MQTT broker '{:s}:{:d}' failed. "
                "Error was: {:s}.".format(self._host, self._port, str(ex)))
            self._logger.fatal("Exiting.")
            sys.exit(-1)

        if self._remote_relay_enabled:
            self._logger.info(
                "InfluxDB remote host is set: remote data transmission is enabled")
        else:
            self._logger.info(
                "InfluxDB remote host is empty: remote data transmission is disabled")

        self._local_client.loop_forever()

    def signal_handler(self, signal, frame):
        self._logger.info("Got signal '{:d}': exiting.".format(signal))
        self._local_client.disconnect()

    def _on_connect(self, client, userdata, flags, rc):
        # pylint: disable=unused-argument,invalid-name
        self._logger.info(
            "Connected to MQTT broker '{:s}:{:d}' with result code {:d}".
            format(self._host, self._port, rc))

        for _topic in TOPIC_LIST:
            _topic += '/#'

            self._logger.debug("Subscribing to {:s}".format(_topic))

            (result, _) = client.subscribe(_topic)
            if result == mqtt.MQTT_ERR_SUCCESS:
                self._logger.info("Subscribed to {:s}".format(_topic))

    def _on_disconnect(self, client, userdata, rc):
        # pylint: disable=unused-argument,invalid-name
        self._logger.info("Disconnected with result code {:d}".format(rc))

    def _on_message(self, client, userdata, msg):
        # pylint: disable=unused-argument
        _message = msg.payload.decode()
        self._logger.debug(
            "Received message -  topic:\'{:s}\', message:\'{:s}\'".
            format(msg.topic, _message))

        if self._remote_relay_enabled:
            _topic, _, _signal_id = msg.topic.partition('/')
            _station_id, _, _sensor_id = _signal_id.partition('.')

            fields = json.loads(_message)
            timestamp = fields.pop('timestamp')
            data_points = [{
                "measurement": _topic,
                "tags": {
                    "edge": userdata['EDGE_ID'].lower(),
                    "station": _station_id,
                    "sensor": _sensor_id
                },
                "fields": {
                    k: try_cast_to_float(v) for k, v in fields.items()
                    },
                "time": timestamp
            }]

            with influxdb_connection(
                    userdata['INFLUXDB_REMOTE_HOST'],
                    userdata['INFLUXDB_REMOTE_PORT'],
                    userdata['INFLUXDB_REMOTE_DB'],
                    userdata['INFLUXDB_REMOTE_USER'],
                    userdata['INFLUXDB_REMOTE_PASS'],
                    self._logger) as _remote_client:
                try:
                    self._logger.debug(f"Writing to remote InfluxDB: {data_points}")
                    _remote_client.write_points(data_points, time_precision='s')
                except (
                    influxdb.exceptions.InfluxDBClientError,
                    influxdb.exceptions.InfluxDBServerError,
                    requests.exceptions.ConnectionError) as ex:
                    self._logger.error(ex)
                    # self._logger.exception(ex)
        else:
            self._logger.debug(
                "InfluxDB remote host is empty: remote data transmission is disabled")

def configuration_parser(p_args=None):
    pre_parser = argparse.ArgumentParser(add_help=False)

    pre_parser.add_argument(
        '-c', '--config-file', dest='config_file', action='store',
        type=str, metavar='FILE',
        help='specifies the path of the configuration file')

    args, remaining_args = pre_parser.parse_known_args(p_args)

    v_general_config_defaults = {
        'mqtt_local_host' : MQTT_LOCAL_HOST,
        'mqtt_local_port' : MQTT_LOCAL_PORT,
        'logging_level'   : logging.INFO,
    }

    v_specific_config_defaults = {
        'influxdb_remote_host' : INFLUXDB_REMOTE_HOST,
        'influxdb_remote_port' : INFLUXDB_REMOTE_PORT,
        'influxdb_remote_db' : INFLUXDB_REMOTE_DB,
        'influxdb_remote_user' : INFLUXDB_REMOTE_USER,
        'influxdb_remote_pass' : INFLUXDB_REMOTE_PASS,
    }

    v_config_section_defaults = {
        'GENERAL': v_general_config_defaults,
        APPLICATION_NAME: v_specific_config_defaults
    }

    # Default config values initialization
    v_config_defaults = {}
    v_config_defaults.update(v_general_config_defaults)
    v_config_defaults.update(v_specific_config_defaults)

    if args.config_file:
        _config = configparser.ConfigParser()
        _config.read_dict(v_config_section_defaults)
        _config.read(args.config_file)

        # Filter out GENERAL options not listed in v_general_config_defaults
        _general_defaults = {_key: _config.get('GENERAL', _key) for _key in
                             _config.options('GENERAL') if _key in
                             v_general_config_defaults}

        # Updates the defaults dictionary with general and application specific
        # options
        v_config_defaults.update(_general_defaults)
        v_config_defaults.update(_config.items(APPLICATION_NAME))

    parser = argparse.ArgumentParser(
        parents=[pre_parser],
        description=('Collects data from other sensors and '
                     'send them to a remote InfluxDB server.'),
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.set_defaults(**v_config_defaults)

    parser.add_argument(
        '-l', '--logging-level', dest='logging_level', action='store',
        type=int,
        help='threshold level for log messages (default: {})'.
        format(logging.INFO))
    parser.add_argument(
        '--local-broker', dest='mqtt_local_host', action='store',
        type=str,
        help='hostname or address of the local broker (default: {})'.
        format(MQTT_LOCAL_HOST))
    parser.add_argument(
        '--local-port', dest='mqtt_local_port', action='store',
        type=int,
        help='port of the local broker (default: {})'.format(MQTT_LOCAL_PORT))
    parser.add_argument(
        '--edge-id', dest='edge_id', action='store',
        type=str,
        help='id of the edge gateway (default: the board serial number)')
    parser.add_argument(
        '--remote-host', dest='influxdb_remote_host', action='store',
        type=str,
        help='hostname or address of the remote Influx database (default: {})'
             .format(INFLUXDB_REMOTE_HOST))
    parser.add_argument(
        '--remote-port', dest='influxdb_remote_port', action='store',
        type=int,
        help='port of the remote Influx database (default: {})'.format(INFLUXDB_REMOTE_PORT))
    parser.add_argument(
        '--remote-db', dest='influxdb_remote_db', action='store',
        type=str,
        help='database on the remote Influx server (default: lower-case Edge ID)')
    parser.add_argument(
        '--remote-user', dest='influxdb_remote_user', action='store',
        type=str,
        help='username to use for the remote InfluxDB server (default: {})'.format(INFLUXDB_REMOTE_USER))
    parser.add_argument(
        '--remote-password', dest='influxdb_remote_pass', action='store',
        type=str,
        help='password to use for the remote InfluxDB server (default: {})'.format(INFLUXDB_REMOTE_PASS))

    args = parser.parse_args(remaining_args)
    return args


def main():
    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt="%Y-%m-%d %H:%M:%S",
        level=logging.INFO)
    logger = logging.getLogger(APPLICATION_NAME)

    # Checks the Python Interpeter version
    if sys.version_info < (3, 0):
        logger.fatal("This software requires Python version >= 3.0: exiting.")
        sys.exit(-1)

    v_serial = edge_serial()

    args = configuration_parser()

    logger.setLevel(args.logging_level)
    logger.info("Starting {:s}".format(APPLICATION_NAME))
    logger.debug(vars(args))

    if not args.edge_id:
        if not v_serial:
            logger.fatal(
                "No EDGE ID specified. Specify in command line with "
                "'--edge-id' or in config file option 'edge_id'")
            sys.exit(-1)
        else:
            args.edge_id = "Edge-{}".format(v_serial)

    if not args.influxdb_remote_db:
        args.influxdb_remote_db = args.edge_id.lower()

    _userdata = {
        'EDGE_ID': args.edge_id,
        'INFLUXDB_REMOTE_HOST': args.influxdb_remote_host,
        'INFLUXDB_REMOTE_PORT': args.influxdb_remote_port,
        'INFLUXDB_REMOTE_DB': args.influxdb_remote_db,
        'INFLUXDB_REMOTE_USER': args.influxdb_remote_user,
        'INFLUXDB_REMOTE_PASS': args.influxdb_remote_pass
    }

    connection = MQTTConnection(args.mqtt_local_host, args.mqtt_local_port,
                                logger=logger, userdata=_userdata)
    signal.signal(signal.SIGINT, connection.signal_handler)

    connection.connect()


if __name__ == "__main__":
    main()

# vim:ts=4:expandtab
