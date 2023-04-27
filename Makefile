GOCMD=go
GOBUILD=$(GOCMD) build
GOMOD=$(GOCMD) mod
BINARY=aes
GOHOME?=~/go
MAINFILE=cmd/aes/aes.go

all: clean tidy build

build:
	env $(GOBUILD) -v -ldflags="-extldflags=-static" -o ${BINARY} ${MAINFILE}


build-linux:
	env GOOS=linux $(GOBUILD) -v -ldflags="-extldflags=-static" -o ${BINARY} ${MAINFILE}

move-bin-linux: 
	mv ${BINARY} ${GOHOME}/bin/${BINARY}

tidy:
	$(GOMOD) tidy

clean:
	rm -f ${BINARY}

