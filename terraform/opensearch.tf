# OpenSearch Serverless Collection using aws-ia module
module "opensearch_serverless" {
  source              = "aws-ia/opensearch-serverless/aws"
  version             = "0.0.5"
  create_vector_index = true
  vector_index_mappings = jsonencode({
    properties = {
      chunk_embedding = {
        type      = "knn_vector",
        dimension = 384
      }
    }
  })
}