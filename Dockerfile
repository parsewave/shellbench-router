# syntax=docker/dockerfile:1
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
COPY tools/mockupstream ./tools/mockupstream
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/oaiproxy ./cmd/oaiproxy \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mockupstream ./tools/mockupstream \
 && mkdir -p /out/config

# distroless/static: no shell or package manager; includes CA certificates.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/oaiproxy /oaiproxy
COPY --from=build /out/mockupstream /mockupstream
# Owned by the nonroot user so a named volume mounted here is writable by
# `oaiproxy token ...` without any host-side chown.
COPY --from=build --chown=65532:65532 /out/config /config
ENV TOKENS_FILE=/config/tokens.json \
    LISTEN_ADDR=:8080
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/oaiproxy"]
CMD ["serve"]
