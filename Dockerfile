FROM golang:1.23-alpine

WORKDIR /app


RUN apk add --no-cache git gcc musl-dev


COPY go.mod go.sum ./

RUN go mod download

COPY . .


RUN CGO_ENABLED=1 go build -o todo-api ./main || CGO_ENABLED=1 go build -o todo-api .

EXPOSE 8080
CMD ["./todo-api"]