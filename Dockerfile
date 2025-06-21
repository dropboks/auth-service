FROM gcr.io/distroless/static-debian12
ARG BIN_NAME
ADD ./bin/dist/${BIN_NAME} /
COPY ./config.yaml /
