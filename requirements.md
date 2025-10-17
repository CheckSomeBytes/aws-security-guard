# Requirements Document

## 1. Overview
Python script to query AWS security services and generate logs when specific configuration changes are made 
## 2. Objectives
Detect when changes are made to the following services:
- CloudTrail
   - StopLogging
   - DeleteTrail
   - Change to S3 Destination of Trail
   - Changes to data selectors
- GuardDuty
   - Creation, modification, and deletion of suppression rules
   - Change to S3 destination
   - Change to CloudWatch destination
   - Deletion of GuardDuty detector
- EventBridge
   - Creation, modification, and deletion of EventBridge rules (all rules monitored across all regions)

## 3. Functional Requirements

### Credentials and Authentication
- Support multiple credential sources:
  - Access keys specified in JSON configuration file
  - AWS environment variables
  - AWS credentials file (~/.aws/credentials)
- JSON configuration file includes both access keys and role/account information for multi-account access
- Support AssumeRole calls to access multiple AWS accounts using temporary credentials

### Monitoring Behavior
- API calls made every 2 minutes to check service configurations
- Monitor resources across ALL AWS regions
- Configuration state maintained in separate state files per AWS account (stored in project directory)
- Initial run establishes baseline state without generating logs
- Subsequent runs detect changes and generate logs only when configurations differ from previous state

### Log Format
- Logs written to file in pretty-printed JSON format
- Logs follow CloudTrail-style format
- Example log structure:
```json
{
  "eventTime": "2025-10-17T08:00:00Z",
  "eventSource": "cloudtrail.amazonaws.com",
  "eventName": "UpdateTrailS3Bucket",
  "responseElements": {
    "trailName": "trail-to-S3"
  },
  "eventID": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "readOnly": false,
  "eventType": "AWSSecurityWatch",
  "recipientAccountId": "123456789012"
}
```
## 4. Non-Functional Requirements

## 5. Technical Requirements

## 6. Dependencies

## 7. Input/Output Specifications

## 8. Error Handling
- Generate a log if the access key loses permissions to run any of the commands (log in CloudTrail-style format)
- On permission errors, script should continue monitoring other services and accounts
- Script should not halt completely when encountering errors in one service or account 

## 9. Testing Requirements
Build a test script that creates and modifies aws infrastructure using aws api calls. The script should also delete the resources when it's done. 
Build a IAM policy to match the exact API calls needed to run the test script. 
All of the test objects should be put into a directory called "testing"
## 10. Deployment

## 11. Future Enhancements
