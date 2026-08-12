resource "kubernetes_namespace_v1" "summarizer" {
  metadata {
    name = var.kubernetes_namespace_summarizer
  }
}
