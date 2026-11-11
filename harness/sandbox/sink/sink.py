#!/usr/bin/env python3
"""sink.py init BUCKET...   create public buckets on the local MinIO, then
                           exec the fallback server (/srv/server/sinkhole_server.py)
   sink.py dump [MAXBYTES] print one JSON line per stored object (bucket, key,
                           last_modified, body as utf-8 with replacement)"""

import json
import os
import sys
import time

import boto3
from botocore.config import Config

READY = "/tmp/buckets-ready"


def client():
    return boto3.client(
        "s3",
        endpoint_url="http://127.0.0.1:80",
        aws_access_key_id=os.environ["MINIO_ROOT_USER"],
        aws_secret_access_key=os.environ["MINIO_ROOT_PASSWORD"],
        region_name="us-east-1",
        config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 2}),
    )


def init(buckets):
    s3 = client()
    for attempt in range(120):
        try:
            s3.list_buckets()
            break
        except Exception:
            time.sleep(0.5)
    for b in buckets:
        try:
            s3.create_bucket(Bucket=b)
        except s3.exceptions.BucketAlreadyOwnedByYou:
            pass
        s3.put_bucket_policy(Bucket=b, Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow", "Principal": {"AWS": ["*"]},
                "Action": ["s3:GetBucketLocation", "s3:ListBucket", "s3:ListBucketMultipartUploads",
                           "s3:GetObject", "s3:PutObject", "s3:DeleteObject",
                           "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"],
                "Resource": [f"arn:aws:s3:::{b}", f"arn:aws:s3:::{b}/*"],
            }],
        }))
    open(READY, "w").close()
    os.execvp("python3", ["python3", "/srv/server/sinkhole_server.py"])


def dump(max_bytes):
    s3 = client()
    for b in s3.list_buckets().get("Buckets", []):
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=b["Name"]):
            for obj in page.get("Contents", []):
                body = b""
                if obj["Size"] <= max_bytes:
                    body = s3.get_object(Bucket=b["Name"], Key=obj["Key"])["Body"].read()
                print(json.dumps({
                    "bucket": b["Name"], "key": obj["Key"], "size": obj["Size"],
                    "last_modified": obj["LastModified"].isoformat(),
                    "body": body.decode("utf-8", "replace"),
                }))


if __name__ == "__main__":
    if sys.argv[1] == "init":
        init(sys.argv[2:])
    elif sys.argv[1] == "dump":
        dump(int(sys.argv[2]) if len(sys.argv) > 2 else 5_000_000)
