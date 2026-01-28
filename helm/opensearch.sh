#!/bin/bash

helm repo add opensearch https://opensearch-project.github.io/helm-charts/
helm repo update

helm install opensearch opensearch/opensearch -f opensearch.yaml -f opensearch-secret.yaml

kubectl exec -it opensearch-cluster-master-0 -- curl -X PUT -u "admin:${OPENSEARCH_ADMIN_PASSWORD}" "https://localhost:9200/langflow" -H 'Content-Type: application/json' --insecure -d'
{
  "settings": {
    "index": {
      "knn": true,
      "knn.algo_param.ef_search": 512
    }
  },
  "mappings": {
    "properties": {
      "chunk_embedding": {
        "type": "knn_vector",
        "dimension": 384
      }
    }
  }
}'