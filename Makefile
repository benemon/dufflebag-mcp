# Build and delivery for dufflebag-mcp. CI only ever picks targets from this
# file, so a green pipeline is reproducible locally — the same convention as
# the dufflebag repository.

IMAGE         ?= quay.io/benjamin_holmes/dufflebag-mcp
IMAGE_TAG     ?= dev
IMAGE_EXPIRES ?= 2w

.PHONY: build
build: ## Build the server binary
	go build -o dufflebag-mcp .

.PHONY: test
test: ## Run the tests
	go test ./...

.PHONY: lint
lint: ## Vet and formatting gate
	go vet ./...
	@fmt=$$(gofmt -l .); if [ -n "$$fmt" ]; then \
		echo "$$fmt"; \
		echo "FAIL: gofmt — run gofmt -w on the files above"; \
		exit 1; \
	fi

.PHONY: check-markers
# The dufflebag tree was cleaned of AI-tooling markers once and they crept
# back; the gate, not the sweep, is what keeps a tree clean. The vendor names
# are assembled from fragments so this recipe never contains the strings it
# hunts — which means the Makefile is scanned like every other tracked file.
check-markers: ## Fail on AI-tooling markers in tracked files
	@p="cla""ude|anthro""pic|co""dex|open""ai|chat""gpt|gpt-[0-9o]|copi""lot|gem""ini|wind""surf|ai-gen""erated|co-auth""ored-by"; \
	if hits=$$(git grep -n -i -E "$$p" -- .); then \
		echo "$$hits"; \
		echo "FAIL: AI-tooling markers in tracked files — remove them"; \
		exit 1; \
	fi; \
	true

.PHONY: image
image: ## Build the container image locally
	docker build -f Containerfile -t $(IMAGE):$(IMAGE_TAG) .

# --provenance=false --sbom=false are NOT optional: buildx attestations
# otherwise wrap the push in an OCI index that hides the labels below, and an
# RC tag never expires. Single-platform for the same reason — a manifest list
# buries per-image labels exactly the way attestations do.
.PHONY: image-push-rc
image-push-rc: ## Build and push an expiring release-candidate image
	docker buildx build -f Containerfile --platform linux/amd64 \
		--provenance=false --sbom=false \
		--label quay.expires-after=$(IMAGE_EXPIRES) \
		-t $(IMAGE):$(IMAGE_TAG) --push .

.PHONY: image-push-release
image-push-release: ## Build and push a release image (no expiry)
	docker buildx build -f Containerfile --platform linux/amd64 \
		--provenance=false --sbom=false \
		-t $(IMAGE):$(IMAGE_TAG) --push .
