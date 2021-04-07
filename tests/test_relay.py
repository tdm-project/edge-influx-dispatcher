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
    * that MQTT messages with the correct topic are successfully written to the
      InfluxDB remote database
    * that MQTT messages with the wrong topic are simply ignored
    * that MQTT malformed messages are ignored
    * that the dispatcher can use both authenticated and not authenticated
      InfluxDB servers
"""

from  influxdb import InfluxDBClient
import json
import paho.mqtt.publish as publish
import time
import unittest


MQTT_MESSAGES = {
    'WrongTopic': {
        'WrongMessages': [
            {
                'topic': 'WrongTopic/device_1',
                'payload': json.dumps({})
            }, {
                'topic': 'WrongTopic/device_2',
                'payload': json.dumps({
                    'lorem': 'ipsum', 'dolor': 517, 'amet': 3.5
                    })
            }, {
                'topic': 'WrongTopic/device_3',
                'payload': json.dumps({
                    'consectetur': 'adipiscing', 'elit': 'sed', 'do': 'eiusmod'
                    })
            }
        ],
        'CorrectMessages': [
            {
                'topic': 'WrongTopic/device_1',
                'payload': json.dumps({
                    "temperature": 24.00, "barometricPressure": 101352.00,
                    "relativeHumidity": 40.00,
                    "dateObserved": "2021-04-02T12:58:12+00:00",
                    "latitude": 0.0, "longitude": 0.0
                })
            }, {
                'topic': 'WrongTopic/device_2',
                'payload': json.dumps({
                    "temperature": 24.00, "barometricPressure": 101352.00,
                    "relativeHumidity": 40.00,
                    "dateObserved": "2021-04-02T12:58:12+00:00",
                    "latitude": 0.0, "longitude": 0.0
                })
            }, {
                'topic': 'WrongTopic/device_3',
                'payload': json.dumps({
                    "temperature": 24.00, "barometricPressure": 101352.00,
                    "relativeHumidity": 40.00,
                    "dateObserved": "2021-04-02T12:58:12+00:00",
                    "latitude": 0.0, "longitude": 0.0
                })
            }
        ],
    },
    'CorrectTopic': {
        'WrongMessages': [
            {
                'topic': 'WeatherObserved/device_1',
                'payload': json.dumps({})
            }, {
                'topic': 'WeatherObserved/device_2',
                'payload': json.dumps({
                    'lorem': 'ipsum', 'dolor': 517, 'amet': 3.5
                    })
            }, {
                'topic': 'WeatherObserved/device_3',
                'payload': json.dumps({
                    'consectetur': 'adipiscing', 'elit': 'sed', 'do': 'eiusmod'
                    })
            }
        ],
        'CorrectMessages': [
            {
                'topic': 'WeatherObserved/device_1',
                'payload': json.dumps({
                    "temperature": 24.00, "barometricPressure": 101352.00,
                    "relativeHumidity": 40.00,
                    "dateObserved": "2021-04-02T12:58:12+00:00",
                    "latitude": 0.0, "longitude": 0.0
                })
            }, {
                'topic': 'WeatherObserved/device_2',
                'payload': json.dumps({
                    "temperature": 24.00, "barometricPressure": 101352.00,
                    "relativeHumidity": 40.00,
                    "dateObserved": "2021-04-02T12:58:12+00:00",
                    "latitude": 0.0, "longitude": 0.0
                })
            }, {
                'topic': 'WeatherObserved/device_3',
                'payload': json.dumps({
                    "temperature": 24.00, "barometricPressure": 101352.00,
                    "relativeHumidity": 40.00,
                    "dateObserved": "2021-04-02T12:58:12+00:00",
                    "latitude": 0.0, "longitude": 0.0
                })
            }
        ],
    }
}


class TestMessagesNoAuth(unittest.TestCase):
    """"
    Tests if MQTT messages with the correct topic are successfully written on
    the InfluxDB remote database and malformeed messages or messagges published
    to the wrong topic are dropped.
    """

    def setUp(self):
        self.mqtt_host = "mosquitto_test"
        self.influxdb_host = "influxdb_test"
        self.influxdb_port = 8086
        self.influxdb_db = "edge_test_db"
        self.influxdb_user = ""
        self.influxdb_pass = ""

        self.influxdb_client = InfluxDBClient(
            host=self.influxdb_host,
            port=self.influxdb_port)

        self.influxdb_client.switch_database(self.influxdb_db)

    def test_publish_to_correct_topic(self):
        """
        Sends well-formed messages to the correct topic.
        """

        time.sleep(2)
        publish.multiple(
            MQTT_MESSAGES['CorrectTopic']['CorrectMessages'],
            hostname=self.mqtt_host)

        # waits 1 seconds 
        time.sleep(1)
        for _m in MQTT_MESSAGES['CorrectTopic']['CorrectMessages']:
            _measurements = [
                d['name'] for d in self.influxdb_client.get_list_measurements()
            ]
            _measurement, _station = _m['topic'].split('/')
            _payload = json.loads(_m['payload'])

            self.assertIn(_measurement, _measurements)

            results = self.influxdb_client.query(
                f'SELECT * FROM "{_measurement}" WHERE time > now() - 2s')
            points = list(results.get_points(
                measurement=f"{_measurement}",
                tags={"station": _station}))

            self.assertEqual(
                len(points), 1, "wrong number of records read/written")

            for _f in _payload.items():
                self.assertIn(_f[0], points[0].keys())
                self.assertEqual(_f[1], points[0][_f[0]])

    def test_publish_to_wrong_topic(self):
        """
        Sends well-formed messages to the wrong topic.
        """

        time.sleep(2)
        publish.multiple(
            MQTT_MESSAGES['WrongTopic']['CorrectMessages'],
            hostname=self.mqtt_host)

        # waits 1 seconds 
        time.sleep(1)
        for _m in MQTT_MESSAGES['WrongTopic']['CorrectMessages']:
            _measurements = [
                d['name'] for d in self.influxdb_client.get_list_measurements()
            ]
            _measurement, _station = _m['topic'].split('/')
            _payload = json.loads(_m['payload'])

            self.assertNotIn(_measurement, _measurements)

            results = self.influxdb_client.query(
                f'SELECT * FROM "{_measurement}" WHERE time > now() - 2s')
            points = list(results.get_points(
                measurement="WeatherObserved",
                tags={"station": _station}))

            self.assertEqual(
                len(points), 0, "wrong number of records read/written")

    def test_publish_wrong_messages(self):
        """
        Sends ill-formed messages to the correct topic.
        """

        time.sleep(2)
        publish.multiple(
            MQTT_MESSAGES['CorrectTopic']['WrongMessages'],
            hostname=self.mqtt_host)

        # waits 1 seconds 
        time.sleep(1)
        for _m in MQTT_MESSAGES['CorrectTopic']['WrongMessages']:
            _measurement, _station = _m['topic'].split('/')
            _payload = json.loads(_m['payload'])

            results = self.influxdb_client.query(
                f'SELECT * FROM "{_measurement}" WHERE time > now() - 2s')
            points = list(results.get_points(
                measurement="WeatherObserved",
                tags={"station": _station}))

            if _payload:
                self.assertEqual(
                    len(points), 1, "wrong number of records read/written")

                for _f in _payload.items():
                    self.assertIn(_f[0], points[0].keys())
                    self.assertEqual(_f[1], points[0][_f[0]])
            else:
                self.assertEqual(
                    len(points), 0, "wrong number of records read/written")

    def test_publish_wrong_messages_wrong_topic(self):
        """
        Sends ill-formed messages to the wrong topic.
        """

        time.sleep(2)
        publish.multiple(
            MQTT_MESSAGES['WrongTopic']['WrongMessages'],
            hostname=self.mqtt_host)

        # waits 1 seconds 
        time.sleep(1)
        for _m in MQTT_MESSAGES['WrongTopic']['WrongMessages']:
            _measurement, _station = _m['topic'].split('/')
            _payload = json.loads(_m['payload'])

            results = self.influxdb_client.query(
                f'SELECT * FROM "{_measurement}" WHERE time > now() - 2s')
            points = list(results.get_points(
                measurement="WeatherObserved",
                tags={"station": _station}))

            self.assertEqual(
                len(points), 0, "wrong number of records read/written")

    def tearDown(self):
        self.influxdb_client.close()


if __name__ == '__main__':
    unittest.main()
