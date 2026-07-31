# Sentinel RAG log ingestor.
#
# Two stages, and the final image is FROM scratch. The ingestor is dependency-free
# Go, so a static binary needs no libc, no shell, and no package manager — which
# means the container has no attack surface beyond the binary itself. That matters
# more than usual here: this is the process that reads attacker-controlled input.

# ---- build ---------------------------------------------------------------
FROM golang:1.22-alpine AS build

WORKDIR /src

# Copy the module files first so `go mod download` is cached independently of
# source changes. (This project has no external dependencies, so the download is
# a no-op today — the layer is here so it stays correct if one is ever added.)
COPY go.mod ./
RUN go mod download

COPY . .

ARG VERSION=dev
# CGO_ENABLED=0 is what makes the scratch stage possible.
# -trimpath removes build-machine paths from the binary.
# -s -w drop the symbol table and DWARF data.
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/sentinel-ingestor \
      ./cmd/sentinel-ingestor

# Verify the binary actually runs before we ship it.
RUN /out/sentinel-ingestor -version

# ---- runtime -------------------------------------------------------------
FROM scratch

COPY --from=build /out/sentinel-ingestor /sentinel-ingestor

# UID 65532 is the conventional "nonroot" user. There is no /etc/passwd in a
# scratch image, so the numeric form is required.
USER 65532:65532

ENTRYPOINT ["/sentinel-ingestor"]
CMD ["-in", "/data/syslog", "-out", "/data/events.jsonl", "-follow", "-stats"]
