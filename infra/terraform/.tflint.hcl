# Bundled Terraform ruleset only for now. Lab 05 adds the AWS ruleset (pinned).
plugin "terraform" {
  enabled = true
  preset  = "recommended"
}
