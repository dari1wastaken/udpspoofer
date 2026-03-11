FROM golang:1.25.4

WORKDIR /app

COPY .. .

RUN go mod download

RUN apt update
RUN apt install -y libpcap-dev

RUN CGO_ENABLED=1 go build -o godocker ./cmd/udpspoofer/

CMD [ "sleep", "1" ]