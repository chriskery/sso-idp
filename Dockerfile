FROM golang:1.18-stretch as build
ARG PROG=sso-idp
ARG HOME=/home/${PROG}
ARG LOG_DIR=${HOME}/log
WORKDIR ${HOME}
COPY . ${HOME}

RUN go env -w GO111MODULE="on" \
    && go env -w GOPROXY="https://goproxy.cn,direct" \
    && cd ${HOME} \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o=./build/${PROG} ./main.go

FROM centos:7
ARG PROG=sso-idp
ARG HOME=/home/${PROG}
WORKDIR ${HOME}
RUN yum install -y \
   wget \
   net-tools \
   lsof \
   vim \
   less \
   openssh-server;

RUN ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
COPY --from=build ${HOME}/build/${PROG} ${HOME}
COPY --from=build ${HOME}/ui/static ${HOME}/ui/static

