FROM golang:1.19-alpine AS builder

WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o auth-service .

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/docs ./docs
COPY --from=builder /app/auth-service .
COPY --from=builder /app/migrations /migrations
EXPOSE 8080
CMD ["./auth-service"]