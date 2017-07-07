#!/bin/sh
python -m grpc_tools.protoc -Iloggregator-api/v2 --python_out=. --grpc_python_out=. loggregator-api/v2/ingress.proto loggregator-api/v2/envelope.proto
