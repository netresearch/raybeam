FROM golang:1.20-alpine AS builder
WORKDIR /build
RUN apk add git

COPY . /build

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /raybeam

FROM alpine:3.17 AS runner

COPY --from=builder /raybeam /bin/raybeam

CMD [ "/bin/raybeam" ]
