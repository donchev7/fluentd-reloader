FROM golang:1.20-bullseye as build

WORKDIR /go/src/app
COPY . ./

RUN go mod tidy \
  && go build -ldflags="-s -w" -o /go/bin/fluentd-reloader -v . 

FROM gcr.io/distroless/base-debian11

COPY --from=build /go/bin/fluentd-reloader /usr/local/bin/fluentd-reloader

CMD ["fluentd-reloader"]
