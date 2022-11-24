FROM golang:1.19.3-buster

WORKDIR /build
COPY main.go go.mod go.sum ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o keycloak-httpdump

FROM scratch

COPY --from=0 /build/keycloak-httpdump .
EXPOSE 8080
CMD ["./keycloak-httpdump"]

