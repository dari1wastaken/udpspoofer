docker build --rm --no-cache -t udpspoofer_database:latest .
docker image prune -f
echo "----- START RUNNING CONTAINER -----"
docker run -it --name udpspoofer_database udpspoofer_database
echo "----- STOP RUNNING CONTAINER -----"
mkdir -p bin
docker cp udpspoofer_database:/app/godocker bin/udpspoofer_database
docker stop udpspoofer_database
docker rm udpspoofer_database
