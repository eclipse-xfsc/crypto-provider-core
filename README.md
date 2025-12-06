# Crypto Core

## Introduction

This package is a library to abstract crypto providers for go. It uses GRPC to connect to an crypto plugin container. The container must run next to the container which is using this library. For example: 

```
    vaultPlugin:
        image: node-654e3bca7fbeeed18f81d7c7.ps-xaas.io/tsa/crypto-provider-hashicorp-vault-plugin:v2.0.5
        networks: 
          - internal
        ports:
          - 50051:50051
        environment:
          - VAULT_ADRESS=http://vault:8200
          - VAULT_TOKEN=test
          - CRYPTO_GRPC_ADDR=0.0.0.0:50051

```
