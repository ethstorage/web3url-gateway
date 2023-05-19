all:
	go build -v -ldflags="-X 'main.commitInfo=`git describe --always`'" -o server ./cmd/server
test:
	go test -v ./cmd/server