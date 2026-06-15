import {
  to = module.kubernetes.aws_cloudwatch_log_group.vpc_flow_logs[0]
  id = "/aws/vpc/infra-agent"
}

import {
  to = module.kubernetes.module.eks.aws_cloudwatch_log_group.this[0]
  id = "/aws/eks/infra-agent/cluster"
}