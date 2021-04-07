DOCKER_IMAGE_VERSION=1.0
DOCKER_IMAGE_NAME=tdmproject/edge-influx-dispatcher
DOCKER_IMAGE_TAGNAME=$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_VERSION)
DOCKER_IMAGE_LATEST=$(DOCKER_IMAGE_NAME):latest
DOCKER_IMAGE_TESTING=$(DOCKER_IMAGE_NAME):test

default: build-final

build-final:
	docker build --target=final -f docker/Dockerfile -t $(DOCKER_IMAGE_TAGNAME) .
	docker tag $(DOCKER_IMAGE_TAGNAME) $(DOCKER_IMAGE_LATEST)

push:
	docker push $(DOCKER_IMAGE_TAGNAME)
	docker push $(DOCKER_IMAGE_LATEST)

test:
	docker build --target=test -f docker/Dockerfile -t $(DOCKER_IMAGE_TESTING) .
	docker-compose -f tests/docker-compose.yaml up -d
	docker-compose -f tests/docker-compose.yaml exec influxdb-dispatcher_test tests/entrypoint.sh -v test_configs
	docker-compose -f tests/docker-compose.yaml exec influxdb-dispatcher_test tests/entrypoint.sh -v test_relay
	docker-compose -f tests/docker-compose.yaml down
	docker-compose -f tests/docker-compose-auth.yaml up -d
	docker-compose -f tests/docker-compose-auth.yaml exec influxdb-dispatcher_test tests/entrypoint.sh -v test_relay_auth
	docker-compose -f tests/docker-compose-auth.yaml down

