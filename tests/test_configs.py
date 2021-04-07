#!/usr/bin/env python
#
#  Copyright 2021 CRS4 - Center for Advanced Studies, Research and Development
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
This module tests:
    * that the GENERAL options defined for all the TDM modules are defined and
    work as expected;
    * the specific section overrides the GENERAL one;
    * the specific options work as expected;
    * the command line options override the configuration file.
"""

import os
import logging
import unittest

from unittest.mock import Mock
from edge_influxdb_dispatcher import configuration_parser
from edge_influxdb_dispatcher import APPLICATION_NAME
from edge_influxdb_dispatcher import (
    MQTT_LOCAL_HOST,
    MQTT_LOCAL_PORT,
    INFLUXDB_REMOTE_HOST,
    INFLUXDB_REMOTE_PORT,
    INFLUXDB_REMOTE_DB,
    INFLUXDB_REMOTE_USER,
    INFLUXDB_REMOTE_PASS)


COMMANDLINE_PARAMETERS = {
    'mqtt_local_host': {
        'cmdline': '--local-broker', 'default': MQTT_LOCAL_HOST},
    'mqtt_local_port': {
        'cmdline': '--local-port', 'default': MQTT_LOCAL_PORT},
    'logging_level': {
        'cmdline': '--logging-level', 'default': logging.INFO},
    #'edge_id': {
    #    'cmdline': '--edge-id',
    #    help='id of the edge gateway (default: the board serial number)')
    'influxdb_remote_host': {
        'cmdline': '--influxdb-remote-host', 'default': INFLUXDB_REMOTE_HOST},
    'influxdb_remote_port': {
        'cmdline': '--influxdb-remote-port', 'default': INFLUXDB_REMOTE_PORT},
    #'influxdb_remote_db': {
    #        'cmdline': '--influxdb-remote-db', 'default':
    #    help='database on the remote Influx server (default: lower-case Edge ID)')
    'influxdb_remote_user': {
        'cmdline': '--influxdb-remote-user', 'default': INFLUXDB_REMOTE_USER},
    'influxdb_remote_pass': {
        'cmdline': '--influxdb-remote-password', 'default': INFLUXDB_REMOTE_PASS}
}


class TestCommandLineParser(unittest.TestCase):
    """
    Tests if the command line options override the settings in the
    configuration file.
    """

    def setUp(self):
        self._test_options = Mock()
        self._test_options.mqtt_local_host = 'mqtt_local_host_option'
        self._test_options.mqtt_local_port = MQTT_LOCAL_PORT + 10
        self._test_options.logging_level = 10

        self._test_options.edge_id = 'edge_id_option'
        self._test_options.influxdb_remote_host = 'influxdb_remote_host_option'
        self._test_options.influxdb_remote_port = INFLUXDB_REMOTE_PORT + 10
        self._test_options.influxdb_remote_db = 'influxdb_remote_db_option'
        self._test_options.influxdb_remote_user = 'influxdb_remote_user_option'
        self._test_options.influxdb_remote_pass = 'influxdb_remote_pass_option'

        self._test_configuration = Mock()
        self._test_configuration.mqtt_local_host = (
            'mqtt_local_host_configuration')
        self._test_configuration.mqtt_local_port = MQTT_LOCAL_PORT + 20
        self._test_configuration.logging_level = 50

        self._test_configuration.edge_id = 'edge_id_option'
        self._test_configuration.influxdb_remote_host = 'influxdb_remote_host_configuration'
        self._test_configuration.influxdb_remote_port = INFLUXDB_REMOTE_PORT + 20
        self._test_configuration.influxdb_remote_db = 'influxdb_remote_db_configuration'
        self._test_configuration.influxdb_remote_user = 'influxdb_remote_user_configuration'
        self._test_configuration.influxdb_remote_pass = 'influxdb_remote_pass_configuration'

        self._config_file = '/tmp/config.ini'

        _f = open(self._config_file, "w")
        _f.write("[{:s}]\n".format(APPLICATION_NAME))
        _f.write(
            "mqtt_local_host = {}\n".
            format(self._test_configuration.mqtt_local_host))
        _f.write(
            "mqtt_local_port = {}\n".
            format(self._test_configuration.mqtt_local_port))
        _f.write("logging_level = {}\n".format(
            self._test_configuration.logging_level))
        _f.write("edge_id = {}\n".format(
            self._test_configuration.edge_id))
        _f.write("influxdb_remote_host = {}\n".format(
            self._test_configuration.influxdb_remote_host))
        _f.write("influxdb_remote_port = {}\n".format(
            self._test_configuration.influxdb_remote_port))
        _f.write("influxdb_remote_user = {}\n".format(
            self._test_configuration.influxdb_remote_user))
        _f.write("influxdb_remote_pass = {}\n".format(
            self._test_configuration.influxdb_remote_pass))
        _f.close()

    def test_command_line_long(self):
        """
        Tests if the command line options are parsed.
        """
        _cmd_line = []

        _cmd_line.extend(['--config-file', None])
        _cmd_line.extend(
            ['--local-broker', str(self._test_options.mqtt_local_host)])
        _cmd_line.extend(
            ['--local-port', str(self._test_options.mqtt_local_port)])
        _cmd_line.extend(
            ['--logging-level', str(self._test_options.logging_level)])
        _cmd_line.extend(
            ['--edge-id', str(self._test_options.edge_id)])
        _cmd_line.extend(
            ['--influxdb-remote-host', str(self._test_options.influxdb_remote_host)])
        _cmd_line.extend(
            ['--influxdb-remote-port', str(self._test_options.influxdb_remote_port)])
        _cmd_line.extend(
            ['--influxdb-remote-user', str(self._test_options.influxdb_remote_user)])
        _cmd_line.extend(
            ['--influxdb-remote-pass', str(self._test_options.influxdb_remote_pass)])

        _args = configuration_parser(_cmd_line)

        self.assertEqual(
            self._test_options.mqtt_local_host, _args.mqtt_local_host)
        self.assertEqual(
            self._test_options.mqtt_local_port, _args.mqtt_local_port)
        self.assertEqual(
            self._test_options.logging_level, _args.logging_level)
        self.assertEqual(
            self._test_options.edge_id, _args.edge_id)
        self.assertEqual(
            self._test_options.influxdb_remote_host, _args.influxdb_remote_host)
        self.assertEqual(
            self._test_options.influxdb_remote_port, _args.influxdb_remote_port)
        self.assertEqual(
            self._test_options.influxdb_remote_user, _args.influxdb_remote_user)
        self.assertEqual(
            self._test_options.influxdb_remote_pass, _args.influxdb_remote_pass)

    def test_command_line_long_override(self):
        """
        Tests if the command line options override the settings in the
        configuration file (long options).
        """
        _cmd_line = []

        _cmd_line.extend(
            ['--config-file', str(self._config_file)])
        _cmd_line.extend(
            ['--local-broker', str(self._test_options.mqtt_local_host)])
        _cmd_line.extend(
            ['--local-port', str(self._test_options.mqtt_local_port)])
        _cmd_line.extend(
            ['--logging-level', str(self._test_options.logging_level)])

        _cmd_line.extend(
            ['--influxdb-remote-host', str(self._test_options.influxdb_remote_host)])
        _cmd_line.extend(
            ['--influxdb-remote-port', str(self._test_options.influxdb_remote_port)])
        _cmd_line.extend(
            ['--influxdb-remote-user', str(self._test_options.influxdb_remote_user)])
        _cmd_line.extend(
            ['--influxdb-remote-pass', str(self._test_options.influxdb_remote_pass)])

        _args = configuration_parser(_cmd_line)

        self.assertEqual(
            self._test_options.mqtt_local_host, _args.mqtt_local_host)
        self.assertEqual(
            self._test_options.mqtt_local_port, _args.mqtt_local_port)
        self.assertEqual(
            self._test_options.logging_level, _args.logging_level)
        self.assertEqual(
            self._test_options.edge_id, _args.edge_id)
        self.assertEqual(
            self._test_options.influxdb_remote_host, _args.influxdb_remote_host)
        self.assertEqual(
            self._test_options.influxdb_remote_port, _args.influxdb_remote_port)
        self.assertEqual(
            self._test_options.influxdb_remote_user, _args.influxdb_remote_user)
        self.assertEqual(
            self._test_options.influxdb_remote_pass, _args.influxdb_remote_pass)

    def test_command_line_long_partial_override(self):
        """
        Tests if the command line options override the settings in the
        configuration file (long options).
        """
        for _opt, _par in COMMANDLINE_PARAMETERS.items():
            _cmd_line = ['--config-file', str(self._config_file)]
            _cmd_line.extend([
                _par['cmdline'],
                str(getattr(self._test_options, _opt))])

            _args = configuration_parser(_cmd_line)

            self.assertEqual(
                getattr(_args, _opt),
                getattr(self._test_options, _opt))

            for _cfg, _val in COMMANDLINE_PARAMETERS.items():
                if _cfg == _opt:
                    continue
                self.assertEqual(
                    getattr(_args, _cfg),
                    getattr(self._test_configuration, _cfg))

    def tearDown(self):
        os.remove(self._config_file)


class TestGeneralSectionConfigFileParser(unittest.TestCase):
    """
    Checks if the GENERAL section options are present in the parser, their
    default values are defined and the GENERAL SECTION of configuration file is
    read and parsed.
    """

    def setUp(self):
        self._default = Mock()
        self._default.mqtt_local_host = MQTT_LOCAL_HOST
        self._default.mqtt_local_port = MQTT_LOCAL_PORT
        self._default.logging_level = logging.INFO

        self._test = Mock()
        self._test.mqtt_local_host = 'mqtt_local_host_test'
        self._test.mqtt_local_port = MQTT_LOCAL_PORT + 100
        self._test.logging_level = logging.INFO + 10

        self._override = Mock()
        self._override.mqtt_local_host = 'mqtt_local_host_override'
        self._override.mqtt_local_port = MQTT_LOCAL_PORT + 200
        self._override.logging_level = logging.INFO + 20

        self._config_file = '/tmp/config.ini'
        _f = open(self._config_file, "w")
        _f.write("[GENERAL]\n")
        _f.write("mqtt_local_host = {}\n".format(self._test.mqtt_local_host))
        _f.write("mqtt_local_port = {}\n".format(self._test.mqtt_local_port))
        _f.write("logging_level = {}\n".format(self._test.logging_level))
        _f.close()

    def test_general_arguments(self):
        """
        Checks the presence of the GENERAL section in the parser.
        """
        _cmd_line = []
        _args = configuration_parser(_cmd_line)

        self.assertIn('mqtt_local_host', _args)
        self.assertIn('mqtt_local_port', _args)
        self.assertIn('logging_level', _args)

    def test_general_default(self):
        """
        Checks the defaults of the GENERAL section in the parser.
        """
        _cmd_line = []
        _args = configuration_parser(_cmd_line)

        self.assertEqual(self._default.mqtt_local_host, _args.mqtt_local_host)
        self.assertEqual(self._default.mqtt_local_port, _args.mqtt_local_port)
        self.assertEqual(self._default.logging_level, _args.logging_level)

    def test_general_options(self):
        """
        Tests the parsing of the options in the GENERAL section.
        """

        _cmd_line = ['-c', self._config_file]
        _args = configuration_parser(_cmd_line)

        self.assertEqual(self._test.mqtt_local_host, _args.mqtt_local_host)
        self.assertEqual(self._test.mqtt_local_port, _args.mqtt_local_port)
        self.assertEqual(self._test.logging_level, _args.logging_level)

        self.assertNotEqual(
            _args.mqtt_local_host,
            self._default.mqtt_local_host)
        self.assertNotEqual(
            _args.mqtt_local_port,
            self._default.mqtt_local_port)
        self.assertNotEqual(
            _args.logging_level,
            self._default.logging_level)

    def test_general_override_options(self):
        """
        Tests if the options in the GENERAL section are overridden by the same
        options in the specific section.
        """
        _config_specific_override_file = '/tmp/override_config.ini'

        _f = open(_config_specific_override_file, "w")
        _f.write("[GENERAL]\n")
        _f.write("mqtt_local_host = {}\n".format(self._test.mqtt_local_host))
        _f.write("mqtt_local_port = {}\n".format(self._test.mqtt_local_port))
        _f.write("logging_level = {}\n".format(self._test.logging_level))
        _f.write("[{:s}]\n".format(APPLICATION_NAME))
        _f.write(
            "mqtt_local_host = {}\n".format(self._override.mqtt_local_host))
        _f.write(
            "mqtt_local_port = {}\n".format(self._override.mqtt_local_port))
        _f.write(
            "logging_level = {}\n".format(self._override.logging_level))
        _f.close()

        _cmd_line = ['-c', _config_specific_override_file]
        _args = configuration_parser(_cmd_line)

        self.assertEqual(self._override.mqtt_local_host, _args.mqtt_local_host)
        self.assertEqual(self._override.mqtt_local_port, _args.mqtt_local_port)
        self.assertEqual(self._override.logging_level, _args.logging_level)

        os.remove(_config_specific_override_file)

    def tearDown(self):
        os.remove(self._config_file)


class TestSpecificOptions(unittest.TestCase):
    """
    Checks if the specific options are present in the parser and their
    default values are defined
    """

    def setUp(self):
        self._default = Mock()
        self._default.influxdb_remote_host = INFLUXDB_REMOTE_HOST
        self._default.influxdb_remote_port = INFLUXDB_REMOTE_PORT
        self._default.influxdb_remote_user = INFLUXDB_REMOTE_USER
        self._default.influxdb_remote_pass = INFLUXDB_REMOTE_PASS
#        # self._default.edge_id =

        self._test = Mock()
        self._test.influxdb_remote_host = 'test_server'
        self._test.influxdb_remote_port = 9119
        self._test.influxdb_remote_user = 'a_non_default_user'
        self._test.influxdb_remote_pass = 'a_non_default_pass'

        self._config_file = '/tmp/config.ini'

        _f = open(self._config_file, "w")
        _f.write("[{:s}]\n".format(APPLICATION_NAME))
        _f.write("influxdb_remote_host = {}\n"
                 .format(self._test.influxdb_remote_host))
        _f.write("influxdb_remote_port = {}\n"
                 .format(self._test.influxdb_remote_port))
        _f.write("influxdb_remote_user = {}\n"
                 .format(self._test.influxdb_remote_user))
        _f.write("influxdb_remote_pass = {}\n"
                 .format(self._test.influxdb_remote_pass))
        _f.close()

    def test_specific_arguments(self):
        """
        Checks the presence of the specific options in the parser.
        """
        _cmd_line = []
        _args = configuration_parser(_cmd_line)

        self.assertIn('influxdb_remote_host', _args)
        self.assertIn('influxdb_remote_port', _args)
        self.assertIn('influxdb_remote_user', _args)
        self.assertIn('influxdb_remote_pass', _args)
        self.assertIn('edge_id', _args)

    def test_specific_default(self):
        """
        Checks the default values of the specific options in the parser.
        """
        _cmd_line = []
        _args = configuration_parser(_cmd_line)

        self.assertEqual(self._default.influxdb_remote_host,
                         _args.influxdb_remote_host)
        self.assertEqual(self._default.influxdb_remote_port,
                         _args.influxdb_remote_port)
        self.assertEqual(self._default.influxdb_remote_user,
                         _args.influxdb_remote_user)
        self.assertEqual(self._default.influxdb_remote_pass,
                         _args.influxdb_remote_pass)
#        self.assertEqual(self._default.edge_id, _args)

    def test_specific_options(self):
        """
        Tests the parsing of the options in the specific section.
        """
        _cmd_line = ['-c', self._config_file]
        _args = configuration_parser(_cmd_line)

        self.assertEqual(self._test.influxdb_remote_host,
                         _args.influxdb_remote_host)
        self.assertEqual(self._test.influxdb_remote_port,
                         _args.influxdb_remote_port)
        self.assertEqual(self._test.influxdb_remote_user,
                         _args.influxdb_remote_user)
        self.assertEqual(self._test.influxdb_remote_pass,
                         _args.influxdb_remote_pass)

    def tearDown(self):
        os.remove(self._config_file)


if __name__ == '__main__':
    unittest.main()
