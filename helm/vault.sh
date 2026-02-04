#!/bin/bash

helm install vault hashicorp/vault -n vault --create-namespace -f vault.yaml