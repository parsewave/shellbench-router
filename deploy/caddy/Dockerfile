# Caddy v2.11.7 plus the reader-only backport of upstream PR #8178.
# Build the default production image with docker compose build caddy.
# baseline-unit-tests deliberately fails the new regressions on unmodified Caddy.
FROM golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS source
ENV CGO_ENABLED=0 GOTOOLCHAIN=local \
    GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org \
    GOMAXPROCS=2 GOFLAGS=-p=2 GOMEMLIMIT=2GiB
WORKDIR /src
# The module proxy and checksum database authenticate immutable module bytes.
# Preserve the download cache and patch only a separate writable source copy.
RUN go mod download -json github.com/caddyserver/caddy/v2@v2.11.7 > /tmp/caddy-module.json && \
    grep -F '"Sum": "h1:yj0Y4fYZGPkSvibBJ1sTWE33xC0fxztVyXEW5iIdUT4="' /tmp/caddy-module.json && \
    grep -F '"GoModSum": "h1:Hy0hh5OTFu/INfBPyvkzImXF4wh6O91jyrZLWeB0fx0="' /tmp/caddy-module.json && \
    cp -a /go/pkg/mod/github.com/caddyserver/caddy/v2@v2.11.7 /src/caddy && \
    chmod -R u+w /src/caddy
COPY deploy/caddy/upload-deadline.patch /proof/upload-deadline.patch
COPY deploy/caddy/upload_fixture.go /proof/caddy-upload-fixture.go
RUN printf '%s  %s\n' \
    '02db202462e609ea4ad7b55127d702208b08246492a09cf6c904ccc1ef8a79e9' '/proof/upload-deadline.patch' \
    '75f8c0708a9e3d531867426b22a305eddfe26dc2941ae5c59879950a7b3238be' '/proof/caddy-upload-fixture.go' \
    '965f263280dc22d81a5b9baac4ecdb3eae2a136cd5475ec60b8dbd65ee708f9d' '/src/caddy/modules/caddyhttp/idletimeout.go' \
    '310f2cfc892c4517a9f60a9544b33713b44268fd6ca5bd9a44684f2800136cb0' '/src/caddy/modules/caddyhttp/idletimeout_test.go' | sha256sum -c -
WORKDIR /src/caddy
# Fetch the existing graph before offline tests/builds; do not tidy or upgrade.
RUN sha256sum go.mod go.sum > /proof/module-inputs.sha256 && \
    go mod download && go mod verify && \
    sha256sum -c /proof/module-inputs.sha256
# The pinned Alpine Go image does not include the patch utility.
RUN apk add --no-cache patch=2.8-r0

FROM source AS baseline-unit-tests
# Apply the exact tests but restore the original owner for before-fix proof.
RUN cp modules/caddyhttp/idletimeout.go /tmp/original-idletimeout.go && \
    patch -p1 < /proof/upload-deadline.patch && \
    cp /tmp/original-idletimeout.go modules/caddyhttp/idletimeout.go
# Expected failure is an assertion in the two named tests, not compilation,
# missing dependencies, or an unrelated test. Inspect the build output.
RUN --network=none --mount=type=cache,target=/root/.cache/go-build \
    GOPROXY=off GOSUMDB=off go test -mod=readonly -count=1 \
    -run '^TestIdleTimeoutReader(TerminalError|TimeoutDeadlineCleanup)$' ./modules/caddyhttp

FROM source AS patched-source
RUN patch -p1 < /proof/upload-deadline.patch && \
    printf '%s  %s\n' \
    '5f66f8bcbec32d500127d1166492f5a0efd04ba99e25d086225039566841fd92' 'modules/caddyhttp/idletimeout.go' \
    '99737238ba76c2f9dcd7ffe9b5f342a542cfcdcc18be7efa7c7f3c1241bd700f' 'modules/caddyhttp/idletimeout_test.go' | sha256sum -c - && \
    sha256sum -c /proof/module-inputs.sha256

FROM patched-source AS patched-unit-tests
RUN --network=none --mount=type=cache,target=/root/.cache/go-build \
    GOPROXY=off GOSUMDB=off go test -mod=readonly -count=1 \
    -run '^TestIdleTimeoutReader' ./modules/caddyhttp && \
    sha256sum -c /proof/module-inputs.sha256

FROM patched-unit-tests AS build
# Stock cmd/caddy imports time/tzdata and modules/standard unchanged.
# Explicit custom provenance also preserves the unchanged fixture version gate.
RUN --network=none --mount=type=cache,target=/root/.cache/go-build \
    GOPROXY=off GOSUMDB=off go build -mod=readonly -trimpath -buildvcs=false \
    -ldflags="-s -w -X 'github.com/caddyserver/caddy/v2.CustomVersion=v2.11.7 shellbench-upload-deadline-c31d9a71'" \
    -o /out/caddy ./cmd/caddy && \
    sha256sum -c /proof/module-inputs.sha256

FROM build AS fixture-build
RUN --network=none --mount=type=cache,target=/root/.cache/go-build \
    GOPROXY=off GOSUMDB=off go build -trimpath -ldflags="-s -w" \
    -o /out/fixture /proof/caddy-upload-fixture.go

FROM caddy:2.11-alpine@sha256:e70b164da81ef698b3ad19af799ea6086ce6d9e48ed4079eb9fe26f6fbf14ee5 AS stock

FROM stock AS production
COPY --from=build /out/caddy /usr/bin/caddy
# Preserve the official image's low-port capability and runtime defaults.
RUN setcap cap_net_bind_service=+ep /usr/bin/caddy

FROM stock AS test-runtime
# High loopback ports need no capability; keep the test runtime fully restricted.
RUN setcap -r /usr/bin/caddy
COPY --from=fixture-build /out/fixture /fixture
ENV HOME=/tmp XDG_CONFIG_HOME=/tmp/config XDG_DATA_HOME=/tmp/data GOMAXPROCS=2
USER 65532:65532
ENTRYPOINT ["/fixture"]
CMD []

FROM test-runtime AS stock-upload-test

FROM test-runtime AS upload-test
COPY --from=build /out/caddy /usr/bin/caddy

FROM production
