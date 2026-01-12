#!/bin/bash

# Wait for OpenSearch to be ready
echo "Waiting for OpenSearch to start..."
until curl -s http://localhost:9200/_cluster/health > /dev/null; do
    sleep 2
done

echo "OpenSearch is ready. Creating 'langflow' index..."

# Create the langflow index with vector search configuration
curl -X PUT "http://localhost:9200/langflow" -H 'Content-Type: application/json' -d'
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
}
'

echo ""
echo "Index 'langflow' created successfully!"

# Made with Bob
