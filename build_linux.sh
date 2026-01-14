docker build --rm -t ackspoofer_database:latest .
docker image prune -f
echo "----- START RUNNING CONTAINER -----"
docker run -it --name ackspoofer_database ackspoofer_database
echo "----- STOP RUNNING CONTAINER -----"
mkdir bin
docker cp ackspoofer_database:/app/godocker bin/ackspoofer_database
docker stop ackspoofer_database
docker rm ackspoofer_database