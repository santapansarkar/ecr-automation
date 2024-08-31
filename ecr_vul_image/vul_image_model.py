"""
This Python script is designed to check for vulnerabilities in Amazon Elastic Container Registry (ECR) images and take appropriate actions based on the findings.

The script uses the boto3 library to interact with the Amazon ECR service and perform various operations, such as retrieving image scan findings, tagging vulnerable images, and deleting image tags.

The main functionality of the script is implemented in the `vul_iamge` function, which takes keyword arguments containing the necessary information about the ECR image to be scanned. If vulnerabilities are found, the script blocks the image from being downloaded and tags it with a specific label (e.g., "DEPLOY=NO"). Additionally, the script provides an option to send a notification about the vulnerable image.

The script also includes helper functions for establishing a connection to the Amazon ECR service (`aws_con`), tagging vulnerable images (`tag_vul_images`), deleting image tags (`delet_vul_iamge_tag`), and sending notifications (`send_notification`).

Note: This script assumes that the necessary AWS credentials are properly configured and available in the environment.
"""
import json
import boto3
import argparse

def aws_con():
    """
    Establish a connection to the Amazon ECR service.

    Returns:
        boto3.client: A low-level client representing Amazon ECR.
    """
    ecr_client = boto3.client('ecr', region_name='ap-south-1')
    return ecr_client


def vul_iamge(**vul_image_kwargs):
    """
    Check for vulnerabilities in an ECR image and take appropriate actions.

    Args:
        **vul_image_kwargs: Keyword arguments containing the following:
            ecr_client (boto3.client): A low-level client representing Amazon ECR.
            registry_id (str): The AWS account ID associated with the registry that contains the repository.
            repository_name (str): The name of the repository that contains the image.
            image_digest (str): The sha256 digest of the image manifest.
            image_tag (str): The tag associated with the image.
    """    
    # Get the image scan findings
    response = vul_image_kwargs['ecr_client'].describe_image_scan_findings(
                registryId=vul_image_kwargs['registry_id'],
                repositoryName=vul_image_kwargs['repository_name'],
                imageId={
                    'imageDigest': vul_image_kwargs['image_digest'],
                    'imageTag': vul_image_kwargs['image_tag']
                },
            )
    #print(response['imageScanFindings']['findingSeverityCounts'])
    resource_arn = response['imageScanFindings']['enhancedFindings'][0]['resources'][0]['id']
    end_index = resource_arn.index('/')
    resource_arn = resource_arn.split('/sha256')[0]
    print(resource_arn)
    # Check if any vulnerabilities were found
    vulnerabilities_found = False
    for finding in response['imageScanFindings']['findingSeverityCounts']:
            if finding in ('CRITICAL','HIGH'):
                 vulnerabilities_found = True
            break

    if vulnerabilities_found:
        # Prevent the image from being downloaded
        print(f"Vulnerabilities found in {vul_image_kwargs['repository_name']}:{vul_image_kwargs['image_digest']}. Blocking download.")

        print(f"Tagging the ECR image with DEPLOY=NO for this resource {resource_arn}")
        tag_vul_images(resource_arn)

        # Optionally, you can send a notification or take additional actions here
        #send_notification(repository_name, image_digest)
    else:
        print(f"No vulnerabilities found in {vul_image_kwargs['repository_name']}:{vul_image_kwargs['image_digest']}. Allowing download.")

def tag_vul_images(resource_arn):        
    """
    Tag a vulnerable ECR image with a specific tag.

    Args:
        resource_arn (str): The Amazon Resource Name (ARN) of the ECR image.
    """    
    ecr_client = aws_con()    
    response = ecr_client.batch_get_image(
        registryId='328753010123',
        repositoryName='on-demand-scan',
        imageIds=[
            {
                'imageDigest': 'sha256:3109bef765bdfc6dd8efc1e649bd61141f67a50e0860c1a54847228264328650',
                'imageTag': 'dev1'
            },
        ]
    )
    manifest = response['images'][0]['imageManifest']
    print(manifest)
    response = ecr_client.put_image(
        registryId='328753010123',
        repositoryName='on-demand-scan',
        imageManifest=manifest,
        imageManifestMediaType='application/vnd.docker.distribution.manifest.v2+json',
        imageTag='NoPull'
    )
    delete_vul_iamge_tag()
    
def delete_vul_iamge_tag():
    """
    Delete a specific tag from a vulnerable ECR image.
    """ 
    ecr_client = aws_con()   
    response = ecr_client.batch_delete_image(
    registryId='328753010123',
    repositoryName='on-demand-scan',
    imageIds=[
        {
            'imageDigest': 'sha256:3109bef765bdfc6dd8efc1e649bd61141f67a50e0860c1a54847228264328650',
            'imageTag': 'dev1'
        },
    ]
    )        
def send_notification(repository_name, image_digest):
    """
    Send a notification about a vulnerable ECR image.

    Args:
        repository_name (str): The name of the repository that contains the image.
        image_digest (str): The sha256 digest of the image manifest.
    """    
    # Code to send a notification (e.g., AWS SNS, email, etc.)
    # For example, using AWS SNS:
    sns = boto3.client('sns')
    topic_arn = 'your-sns-topic-arn'
    subject = 'Vulnerable ECR Image Detected'
    message = f"Vulnerabilities found in ECR image {repository_name}:{image_digest}. Download blocked."
    sns.publish(TopicArn=topic_arn, Subject=subject, Message=message)
