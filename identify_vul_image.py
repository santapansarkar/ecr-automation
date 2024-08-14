import json
import boto3

# Initialize the AWS clients
ecr = boto3.client('ecr')
events = boto3.client('events')

def lambda_handler(event, context):
    # Extract the image details from the event
    image_digest = event['detail']['image-digest']
    repository_name = event['detail']['repository-name']
    registry_id = event['detail']['registry-id']

    # Get the image scan findings
    response = ecr.describe_image_scan_findings(
        registryId=registry_id,
        repositoryName=repository_name,
        imageDigest=image_digest
    )

    # Check if any vulnerabilities were found
    vulnerabilities_found = False
    for finding in response['imageScanFindings']['findings']:
        if finding['severity'] in ['CRITICAL', 'HIGH', 'MEDIUM']:
            vulnerabilities_found = True
            break

    if vulnerabilities_found:
        # Prevent the image from being downloaded
        print(f"Vulnerabilities found in {repository_name}:{image_digest}. Blocking download.")

        # Optionally, you can send a notification or take additional actions here
        send_notification(repository_name, image_digest)
    else:
        print(f"No vulnerabilities found in {repository_name}:{image_digest}. Allowing download.")

def send_notification(repository_name, image_digest):
    # Code to send a notification (e.g., AWS SNS, email, etc.)
    # For example, using AWS SNS:
    sns = boto3.client('sns')
    topic_arn = 'your-sns-topic-arn'
    subject = 'Vulnerable ECR Image Detected'
    message = f"Vulnerabilities found in ECR image {repository_name}:{image_digest}. Download blocked."
    sns.publish(TopicArn=topic_arn, Subject=subject, Message=message)