FROM golang:1.24-alpine AS builder
WORKDIR /build
RUN apk add git

COPY ./go.mod /build
COPY ./go.sum /build
RUN go mod download

COPY . /build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /raybeam

FROM alpine:3.22 AS runner

COPY --from=builder /raybeam /bin/raybeam

CMD [ "/bin/raybeam" ]
