# ecr-automation
Amazon ECR Automation

ECR Vulnerability Image Scanning Module

This module is part of the ECR automation project, focusing on vulnerability scanning for container images in Amazon Elastic Container Registry (ECR).

Version: 0.1.0

This package provides functionality to:
- Connect to AWS ECR
- Scan images for vulnerabilities
- Report on found vulnerabilities

Sample Run command
python -m ecr_vul_image --repository_name my_repo --registry_id 123456789 --image_digest sha256:1234... --image_tag latest


python -m ecr_vul_image --repository_name on-demand-scan  --registry_id 328753010123  --image_digest sha256:3109bef765bdfc6dd8efc1e649bd61141f67a50e0860c1a54847228264328650 --image_tag dev3