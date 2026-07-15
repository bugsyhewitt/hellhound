"""Mock-transport tests for the twenty-second Phase 2 fingerprint tranche.

One test per new fingerprint entry added to the bundled ``default.yaml`` in the
twenty-second expansion (Spring Cloud Gateway API gateway, MinIO S3-compatible
object storage server console, Apache Kafka Connect distributed worker REST
API, Elasticsearch search and analytics engine, Apache Hadoop YARN
ResourceManager web UI, RabbitMQ message broker management UI, HashiCorp
Consul service discovery web UI, and Apache NiFi dataflow management web UI)
— additional internet-facing big-data, streaming, object-storage, message-
broker, service-discovery and dataflow servers mass-exploited across the CISA
Known Exploited Vulnerabilities (KEV) catalog. Each test drives the real
Scanner against an ``httpx.MockTransport`` emulating the target and asserts
BOTH that:

1. the device matches the intended bundled fingerprint, and
2. the device's documented default credential pair authenticates
   (``default_creds is True``).

These run with no network and no Docker. They load the actual bundled
fingerprint set so they double as a regression check on the YAML schema for the
new entries. Mirrors the conventions in ``test_fingerprints_phase2_tranche21.py``.
"""

import httpx

from hellhound.fingerprint import Credential
from _fingerprint_helpers import (
    BUNDLED,
    assert_flagged,
    basic_creds,
    form_field,
    fp,
    scan_one,
)


# -------------------------------------------------------- spring cloud gateway
def test_spring_cloud_gateway_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Spring Cloud Gateway</body></html>"
            )
        if request.url.path == "/login":
            if (
                form_field(request, "username") == "user"
                and form_field(request, "password") == "password"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Bad credentials")
        return httpx.Response(404)

    findings = scan_one("spring-cloud-gateway", handler)
    assert_flagged(
        findings,
        fingerprint_id="spring-cloud-gateway",
        vendor="VMware",
        cred=Credential("user", "password"),
    )


# ------------------------------------------------------------------- minio
def test_minio_server_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>MinIO Console</body></html>"
            )
        if request.url.path == "/api/v1/login":
            if (
                form_field(request, "accessKey") == "minioadmin"
                and form_field(request, "secretKey") == "minioadmin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Invalid Login")
        return httpx.Response(404)

    findings = scan_one("minio-server", handler)
    assert_flagged(
        findings,
        fingerprint_id="minio-server",
        vendor="MinIO",
        cred=Credential("minioadmin", "minioadmin"),
    )


# ------------------------------------------------------- kafka connect
def test_apache_kafka_connect_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                text='{"version":"3.5.0","commit":"abc","kafka_cluster_id":"xyz"}',
                headers={"Content-Type": "application/json"},
            )
        if request.url.path == "/connectors":
            user, pw = basic_creds(request)
            if user == "admin" and pw == "admin":
                return httpx.Response(200, text="[]")
            return httpx.Response(401, text="Unauthorized")
        return httpx.Response(404)

    findings = scan_one("apache-kafka-connect", handler)
    assert_flagged(
        findings,
        fingerprint_id="apache-kafka-connect",
        vendor="Apache Software Foundation",
        cred=Credential("admin", "admin"),
    )


# ---------------------------------------------------------- elasticsearch
def test_elasticsearch_server_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                text='{"name":"node-1","cluster_name":"docker-cluster","tagline":"You Know, for Search"}',
            )
        if request.url.path == "/_security/_authenticate":
            user, pw = basic_creds(request)
            if user == "elastic" and pw == "changeme":
                return httpx.Response(200, text='{"username":"elastic"}')
            return httpx.Response(401, text="unauthorized")
        return httpx.Response(404)

    findings = scan_one("elasticsearch-server", handler)
    assert_flagged(
        findings,
        fingerprint_id="elasticsearch-server",
        vendor="Elastic",
        cred=Credential("elastic", "changeme"),
    )


# -------------------------------------------------------------- hadoop
def test_apache_hadoop_yarn_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Hadoop ResourceManager</body></html>"
            )
        if request.url.path == "/hue/accounts/login":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Invalid username or password")
        return httpx.Response(404)

    findings = scan_one("apache-hadoop-yarn", handler)
    assert_flagged(
        findings,
        fingerprint_id="apache-hadoop-yarn",
        vendor="Apache Software Foundation",
        cred=Credential("admin", "admin"),
    )


# ------------------------------------------------------------- rabbitmq
def test_rabbitmq_management_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>RabbitMQ Management</body></html>"
            )
        if request.url.path == "/api/whoami":
            user, pw = basic_creds(request)
            if user == "guest" and pw == "guest":
                return httpx.Response(200, text='{"name":"guest"}')
            return httpx.Response(401, text="Not Authorized")
        return httpx.Response(404)

    findings = scan_one("rabbitmq-management", handler)
    assert_flagged(
        findings,
        fingerprint_id="rabbitmq-management",
        vendor="VMware",
        cred=Credential("guest", "guest"),
    )


# ------------------------------------------------------------- consul
def test_hashicorp_consul_ui_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Consul by HashiCorp</body></html>"
            )
        if request.url.path == "/v1/agent/self":
            user, pw = basic_creds(request)
            if user == "admin" and pw == "admin":
                return httpx.Response(200, text='{"Config":{}}')
            return httpx.Response(401, text="Unauthorized")
        return httpx.Response(404)

    findings = scan_one("hashicorp-consul-ui", handler)
    assert_flagged(
        findings,
        fingerprint_id="hashicorp-consul-ui",
        vendor="HashiCorp",
        cred=Credential("admin", "admin"),
    )


# --------------------------------------------------------------- nifi
def test_apache_nifi_ui_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>NiFi</body></html>"
            )
        if request.url.path == "/nifi-api/access/token":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "ctrlSecConfig19!?"
            ):
                return httpx.Response(200, text="eyJ.token.value")
            return httpx.Response(401, text="Unable to authenticate")
        return httpx.Response(404)

    findings = scan_one("apache-nifi-ui", handler)
    assert_flagged(
        findings,
        fingerprint_id="apache-nifi-ui",
        vendor="Apache Software Foundation",
        cred=Credential("admin", "ctrlSecConfig19!?"),
    )


# --------------------------------------------------- matched-but-rotated guard
def test_tranche22_entry_matched_but_creds_rotated_not_flagged():
    """A device matching a new tranche-22 fingerprint but rejecting the defaults
    is matched, not flagged — proving the auth check is real, not a free pass on
    a landing-page match.

    Uses the MinIO form-auth entry: the device advertises its fingerprint on
    the console landing page but the auth endpoint rejects the default
    credentials (returning the configured failure_body_contains marker)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>MinIO Console</body></html>"
            )
        if request.url.path == "/api/v1/login":
            return httpx.Response(200, text="Invalid Login")
        return httpx.Response(404)

    findings = scan_one("minio-server", handler)
    assert len(findings) == 1
    assert findings[0].fingerprint_id == "minio-server"
    assert findings[0].default_creds is False
    assert findings[0].matched_credential is None
