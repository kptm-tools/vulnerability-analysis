FROM golang:1.23.3

WORKDIR /app

RUN apt-get update

RUN apt-get install nmap -y

COPY go.mod go.sum ./

RUN go mod download

COPY cmd/ ./cmd

COPY pkg/ ./pkg

RUN CGO_ENABLED=0 GOOS=linux go build -o ./bin/vulnerability-analysis ./cmd/main.go

EXPOSE 8002

CMD [ "./bin/vulnerability-analysis" ]
