# Specifies a parent image
FROM golang:1.25.4
 
# Creates an app directory to hold your app’s source code
WORKDIR /app
 
# Copies everything from your root directory into /app
COPY . .
 
# Installs Go dependencies
RUN go mod download

RUN apt update
RUN apt install -y libpcap-dev
 
# Builds your app with optional configuration
RUN CGO_ENABLED=1 go build -o godocker ./cmd/udpspoofer/
 
# Tells Docker which network port your container listens on
# EXPOSE 8080
 
# Specifies the executable command that runs when the container starts
CMD [ “” ]