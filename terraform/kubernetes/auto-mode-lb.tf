resource "kubernetes_manifest" "ingressclassparams_alb" {
  manifest = {
    "apiVersion" = "eks.amazonaws.com/v1"
    "kind"       = "IngressClassParams"
    "metadata" = {
      "name" = "alb"
    }
    "spec" = {
      "scheme" = "internet-facing"
    }
  }
}

resource "kubernetes_ingress_class_v1" "alb" {
  metadata {
    name = "alb"
    annotations = {
      "ingressclass.kubernetes.io/is-default-class" = "true"
    }
  }

  spec {
    controller = "eks.amazonaws.com/alb"
    parameters {
      api_group = "eks.amazonaws.com"
      kind      = "IngressClassParams"
      name      = "alb"
    }
  }
}