FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /prosa-server ./cmd/prosa-server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /prosa-server /prosa-server
ENV PROSA_LISTEN_ADDR=:8080 \
    PROSA_BLOB_DIR=/data/blobs
VOLUME /data
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/prosa-server"]
