FROM golang:1.21.5-alpine3.19

RUN ln -sf /usr/share/zoneinfo/Asia/Jakarta /etc/localtime && \
    echo "Asia/Jakarta" > /etc/timezone

WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN export GOPROXY=https://proxy.golang.org && \
    go mod tidy

COPY . .

RUN go build -o main .

RUN rm -rf go.mod go.sum

EXPOSE 8081

CMD ["./main"]
