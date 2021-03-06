PROG_NAME := "pkiauth"
IMAGE_NAME := "pschou/pkiauth"
VERSION = 0.1.$(shell date +%Y%m%d.%H%M)
FLAGS := "-s -w -X main.version=${VERSION}"

VERSION := "0.1"


build:
	GOOS=linux GOARCH=386 CGO_ENABLED=0 go build -ldflags=${FLAGS} -o ${PROG_NAME}_linux32 .
	upx --lzma ${PROG_NAME}_linux32
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags=${FLAGS} -o ${PROG_NAME}_linux64 .
	upx --lzma ${PROG_NAME}_linux64
	GOOS=linux GOARCH=arm CGO_ENABLED=0 go build -ldflags=${FLAGS} -o ${PROG_NAME}_arm .
	upx --lzma ${PROG_NAME}_arm
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags=${FLAGS} -o ${PROG_NAME}_arm64 .
	upx --lzma ${PROG_NAME}_arm64
	GOOS=linux GOARCH=mips CGO_ENABLED=0 go build -ldflags=${FLAGS} -o ${PROG_NAME}_mips .
	upx --lzma ${PROG_NAME}_mips
	GOOS=linux GOARCH=mipsle CGO_ENABLED=0 go build -ldflags=${FLAGS} -o ${PROG_NAME}_mipsle .
	upx --lzma ${PROG_NAME}_mipsle
	GOOS=windows GOARCH=386 CGO_ENABLED=0 go build -ldflags=${FLAGS} -o ${PROG_NAME}_win32.exe .
	upx --lzma ${PROG_NAME}_win32.exe
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags=${FLAGS} -o ${PROG_NAME}_win64.exe .
	upx --lzma ${PROG_NAME}_win64.exe

l:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags=${FLAGS} -o ${PROG_NAME}_linux64 .
	#upx --lzma ${PROG_NAME}_linux64

docker:
	docker build -f Dockerfile --tag ${IMAGE_NAME}:${VERSION} .
	docker push ${IMAGE_NAME}:${VERSION}; \
	docker save -o pschou_${PROG_NAME}.tar ${IMAGE_NAME}:${VERSION}

clean:
	rm pkiauth_*{64,32}*
