#
# Copyright 2020 IBM All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

base_dir := $(PWD)

go_dir := $(base_dir)/pkg
node_dir := $(base_dir)/node
java_dir := $(base_dir)/java
scenario_dir := $(base_dir)/scenario

# PEER_IMAGE_PULL is where to pull peer image from, it can be set by external env variable
# In fabric-gateway main branch it should reflect the location of the latest fabric main branch image
PEER_IMAGE_PULL ?= hyperledger-fabric.jfrog.io/fabric-peer:amd64-2.5-stable

# PEER_IMAGE_TAG is what to tag the pulled peer image as, it will also be used in docker-compose to reference the image
# In fabric-gateway main branch this version tag should correspond to the version in the fabric main branch
PEER_IMAGE_TAG ?= 3.0

# TWO_DIGIT_VERSION specifies which chaincode images to pull, they will be tagged to be consistent with PEER_IMAGE_TAG
# In fabric-gateway main branch it should typically be the latest released chaincode version available in dockerhub.
TWO_DIGIT_VERSION ?= 2.4

.PHONEY: build
build: build-node build-java

.PHONEY: build-node
build-node:
	cd "$(node_dir)" && \
		npm install && \
		npm run build && \
		rm -f fabric-gateway-dev.tgz && \
		mv $$(npm pack) fabric-gateway-dev.tgz

.PHONEY: build-java
build-java:
	cd "$(java_dir)" && \
		mvn install -DskipTests

.PHONEY: unit-test
unit-test: generate unit-test-go unit-test-node unit-test-java

.PHONEY: unit-test-go
unit-test-go: lint
	go test -timeout 10s -coverprofile="$(base_dir)/cover.out" "$(go_dir)/..."

.PHONEY: unit-test-go-pkcs11
unit-test-go-pkcs11: lint
	SOFTHSM2_CONF="$${HOME}/softhsm2.conf" go test -tags pkcs11 -timeout 10s -coverprofile="$(base_dir)/cover.out" "$(go_dir)/..."

.PHONEY: unit-test-node
unit-test-node: build-node
	cd "$(node_dir)" && \
		npm test

.PHONEY: unit-test-java
unit-test-java:
	cd "$(java_dir)" && \
		mvn test

.PHONEY: lint
lint:
	"$(base_dir)/ci/check_gofmt.sh" "$(go_dir)" "$(scenario_dir)/go"
	go install honnef.co/go/tools/cmd/staticcheck@latest
	staticcheck -f stylish -tags="pkcs11" "$(go_dir)/..." "$(scenario_dir)/go"
	go vet -tags pkcs11 "$(go_dir)/..." "$(scenario_dir)/go"
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	gosec -tags pkcs11 -exclude-generated "$(go_dir)/..."

.PHONEY: scan
scan: scan-go scan-node scan-java

.PHONEY: scan-go
scan-go: scan-go-govulncheck scan-go-nancy

.PHONEY: scan-go-govulncheck
scan-go-govulncheck:
	go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck "$(go_dir)/..."

.PHONEY: scan-go-nancy
scan-go-nancy:
	go install github.com/sonatype-nexus-community/nancy@latest
	go list -json -deps "$(go_dir)/..." | nancy sleuth

.PHONEY: scan-node
scan-node:
	cd "$(node_dir)" && \
		npm install --package-lock-only && \
		npm audit --omit=dev

.PHONEY: scan-java
scan-java:
	cd "$(java_dir)" && \
		mvn dependency-check:check -P owasp

.PHONEY: generate
generate:
	go install github.com/golang/mock/mockgen@v1.6
	go generate "$(go_dir)/..."

.PHONEY: vendor-chaincode
vendor-chaincode:
	cd "$(scenario_dir)/fixtures/chaincode/golang/basic" && \
		GO111MODULE=on go mod vendor
	cd "$(scenario_dir)/fixtures/chaincode/golang/private" && \
		GO111MODULE=on go mod vendor

.PHONEY: scenario-test-go
scenario-test-go: vendor-chaincode
	go install github.com/cucumber/godog/cmd/godog@v0.12
	cd $(scenario_dir)/go && \
		SOFTHSM2_CONF="$${HOME}/softhsm2.conf" go test -tags pkcs11 -v -args "$(scenario_dir)/features/"

.PHONEY: scenario-test-node
scenario-test-node: vendor-chaincode build-node
	go install -tags pkcs11 github.com/hyperledger/fabric-ca/cmd/fabric-ca-client@latest
	cd "$(scenario_dir)/node" && \
		rm -rf package-lock.json node_modules && \
		npm install && \
		SOFTHSM2_CONF="$${HOME}/softhsm2.conf" npm test

.PHONEY: scenario-test-java
scenario-test-java: vendor-chaincode build-java
	cd "$(java_dir)" && \
		mvn verify

.PHONEY: scenario-test
scenario-test: scenario-test-go scenario-test-node scenario-test-java

.PHONEY: generate-docs-node
generate-docs-node: build-node
	cd "$(node_dir)" && \
		npm run generate-apidoc

.PHONEY: generate-docs-java
generate-docs-java:
	cd "$(java_dir)" && \
		mvn javadoc:javadoc

.PHONEY: test
test: unit-test scenario-test

.PHONEY: all
all: test

.PHONEY: pull-latest-peer
pull-latest-peer:
	#docker pull $(PEER_IMAGE_PULL)
	#docker tag $(PEER_IMAGE_PULL) hyperledger/fabric-peer:$(PEER_IMAGE_TAG)
	# also need to retag the following images for the chaincode builder
	for IMAGE in baseos ccenv javaenv nodeenv; do \
		docker pull hyperledger/fabric-$${IMAGE}:$(TWO_DIGIT_VERSION); \
		docker tag hyperledger/fabric-$${IMAGE}:$(TWO_DIGIT_VERSION) hyperledger/fabric-$$IMAGE:$(PEER_IMAGE_TAG); \
	done

.PHONEY: clean
clean: clean-generated clean-node clean-java

.PHONEY: clean-node
clean-node:
	rm -rf "$(node_dir)/package-lock.json" "$(node_dir)/node_modules"

.PHONEY: clean-java
clean-java:
	cd "$(java_dir)" && mvn clean

.PHONEY: clean-generated
clean-generated:
	find "$(go_dir)" -name '*_mock_test.go' -delete
