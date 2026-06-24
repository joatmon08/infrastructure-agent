import {
  to = module.kubernetes.aws_cloudwatch_log_group.eks_cluster
  id = "/aws/eks/infra-agent/cluster"
}

import {
  to = module.kubernetes.aws_cloudwatch_log_group.vpc_flow_logs[0]
  id = "/aws/vpc/infra-agent"
}
