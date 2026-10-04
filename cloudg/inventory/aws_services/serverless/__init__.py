"""Serverless and integration services: the event-driven wiring.

- Lambda: execution role, VPC, layers, container image (-> ECR), DLQ,
  KMS key, EFS access points, environment ARNs, event source mappings
  (SQS/Kinesis/DynamoDB/MSK -> function), resource-policy invokers
  (S3/SNS/EventBridge/API Gateway/logs -> function), function URLs.
- API Gateway REST and HTTP APIs -> Lambda / HTTP / VPC-link integrations.
- SQS queues (DLQ redrive, encryption, cross-account grants).
- SNS topics -> subscriptions (SQS, Lambda, Firehose, HTTP, email counts).
- EventBridge buses and rules -> targets (+ target roles).
- Step Functions state machines -> every resource their definition calls.
- Kinesis data streams.
"""

from __future__ import annotations

from cloudg.inventory._util import image_repository
from cloudg.inventory.aws_services._base import resource_policy_relations
from cloudg.inventory.aws_services.serverless.apigateway import (
    _APIGW_LAMBDA_RE,
    ApiGatewayCollectorsMixin,
)
from cloudg.inventory.aws_services.serverless.functions import FunctionCollectorsMixin
from cloudg.inventory.aws_services.serverless.messaging import MessagingCollectorsMixin

_resource_policy_relations = resource_policy_relations  # backward-compatible alias


class ServerlessCollectorsMixin(
    FunctionCollectorsMixin,
    ApiGatewayCollectorsMixin,
    MessagingCollectorsMixin,
):
    """Every serverless and integration collector."""


__all__ = [
    "_APIGW_LAMBDA_RE",
    "ApiGatewayCollectorsMixin",
    "FunctionCollectorsMixin",
    "MessagingCollectorsMixin",
    "ServerlessCollectorsMixin",
    "_resource_policy_relations",
    "image_repository",
]
