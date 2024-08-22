import json
import boto3

def aws_con():
    ecr_client = boto3.client('ecr', region_name='ap-south-1')
    return ecr_client


def vul_iamge(**vul_image_kwargs):
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
            imageTag='NotAllowed'
        )
        delet_vul_iamge_tag()
def delet_vul_iamge_tag():
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
    # Code to send a notification (e.g., AWS SNS, email, etc.)
    # For example, using AWS SNS:
    sns = boto3.client('sns')
    topic_arn = 'your-sns-topic-arn'
    subject = 'Vulnerable ECR Image Detected'
    message = f"Vulnerabilities found in ECR image {repository_name}:{image_digest}. Download blocked."
    sns.publish(TopicArn=topic_arn, Subject=subject, Message=message)


if __name__ == "__main__":
    ecr_client = aws_con()
    image_digest = 'sha256:3109bef765bdfc6dd8efc1e649bd61141f67a50e0860c1a54847228264328650'
    repository_name = 'on-demand-scan'
    registry_id = '328753010123'
    image_tag = 'dev1'
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