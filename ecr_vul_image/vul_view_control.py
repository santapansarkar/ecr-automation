from vul_image_model import aws_con,vul_iamge
import argparse


def image_verify():
    ecr_client = aws_con()
    parser = argparse.ArgumentParser(description='Check for vulnerabilities in an ECR image.')
    parser.add_argument('--repository_name', type=str, required=True, help='The name of the repository that contains the image.')
    parser.add_argument('--registry_id', type=str, required=True, help='The AWS account ID associated with the registry that contains the repository.')
    parser.add_argument('--image_digest', type=str, required=True, help='The sha256 digest of the image manifest.')
    parser.add_argument('--image_tag', type=str, required=True, help='The tag associated with the image.')
    args = parser.parse_args()
    image_digest = args.image_digest
    repository_name = args.repository_name
    registry_id = args.registry_id
    image_tag = args.image_tag
    vul_image_kwargs = {
        'ecr_client': ecr_client,
        'image_digest': image_digest,
        'repository_name': repository_name,
        'registry_id' : registry_id,
        'image_tag' : image_tag
    }
    vul_iamge(**vul_image_kwargs)
    vul_tag_kwargs = {
         'ecr_client': ecr_client,
         'resource_arn':'resource_arn' 
    }