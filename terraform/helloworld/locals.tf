locals {
  helloworld_agent_name = "helloworld-server"
  # helloworld_agent_image = "${data.terraform_remote_state.base.outputs.helloworld_agent_ecr_repository_url}@${data.aws_ecr_image.helloworld_agent_latest.image_digest}"
  # helloworld_agent_port  = 9999

  test_client_name  = "test-client"
  test_client_image = "${data.terraform_remote_state.base.outputs.test_client_ecr_repository_url}@${data.aws_ecr_image.test_client_latest.image_digest}"
  test_client_port  = 9000
}