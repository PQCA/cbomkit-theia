# Copyright 2024 IBM
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.23.4-alpine3.21 as builder

WORKDIR /app

LABEL version="v1.0.0"

# Install ca-certificates and git
RUN sed -i 's/https:/http:/g' /etc/apk/repositories && apk update && apk add --no-cache ca-certificates git && update-ca-certificates

# Set environment variables to bypass SSL verification
ENV GIT_SSL_NO_VERIFY=true
ENV GOPROXY=direct
ENV GOINSECURE=*
ENV GONOSUMDB=*

COPY go.mod go.sum ./
RUN go mod download
RUN go mod tidy

COPY . ./

RUN CGO_ENABLED=0 GOOS=linux go build -o ./cbomkit-theia

FROM alpine:3.21.2

WORKDIR /app

COPY --from=builder /app/cbomkit-theia /app

ENTRYPOINT ["/app/cbomkit-theia"]

EXPOSE 8080

CMD [ "server" ]