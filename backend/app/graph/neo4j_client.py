from __future__ import annotations
import os
from typing import Any

from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()


NEO4J_URI = os.getenv(
    "NEO4J_URI",
    "bolt://localhost:7687"
)

NEO4J_USERNAME = os.getenv(
    "NEO4J_USERNAME",
    "neo4j"
)

NEO4J_PASSWORD = os.getenv(
    "NEO4J_PASSWORD"
)


class Neo4jClient:

    def __init__(self):
        self.driver = None

    # ========================================================
    # CONNECT
    # ========================================================

    def connect(self):
        if self.driver is not None:
            return

        if not NEO4J_PASSWORD:
            raise RuntimeError(
                "NEO4J_PASSWORD is not configured in .env"
            )

        self.driver = GraphDatabase.driver(
            NEO4J_URI,
            auth=(
                NEO4J_USERNAME,
                NEO4J_PASSWORD
            )
        )

        self.driver.verify_connectivity()

    # ========================================================
    # CLOSE
    # ========================================================

    def close(self):
        if self.driver:
            self.driver.close()
            self.driver = None

    # ========================================================
    # HEALTH CHECK
    # ========================================================

    def health_check(self):
        self.connect()

        with self.driver.session(
            database="neo4j"
        ) as session:

            result = session.run(
                "RETURN 1 AS status"
            )

            record = result.single()

            return (
                record is not None
                and record["status"] == 1
            )

    # ========================================================
    # CREATE CASE GRAPH
    # ========================================================

    def create_case_graph(
        self,
        case_id: str,
        sender: str,
        recipient: str,
        subject: str,
        sender_domain: str,
        urls: list[str],
        ips: list[str],
        attachments: list[dict[str, Any]],
        ip_intelligence: list[dict[str, Any]] | None = None,
        domain_intelligence: dict[str, Any] | None = None
    ):

        self.connect()

        ip_intelligence = (
            ip_intelligence
            if ip_intelligence
            else []
        )

        domain_intelligence = (
            domain_intelligence
            if domain_intelligence
            else {}
        )

        # ----------------------------------------------------
        # Normalize attachment data
        # ----------------------------------------------------

        normalized_attachments = []

        for attachment in attachments or []:

            if not isinstance(
                attachment,
                dict
            ):
                continue

            sha256 = attachment.get(
                "sha256"
            )

            if not sha256:
                continue

            normalized_attachments.append({
                "sha256": sha256,
                "filename": attachment.get(
                    "filename"
                ),
                "content_type": attachment.get(
                    "content_type"
                ),
                "size": attachment.get(
                    "size"
                )
            })

        # ----------------------------------------------------
        # Create Email + Sender + Domain
        # ----------------------------------------------------

        email_query = """
        MERGE (email:Email {
            case_id: $case_id
        })

        SET
            email.sender = $sender,
            email.recipient = $recipient,
            email.subject = $subject

        MERGE (sender_node:Sender {
            address: $sender
        })

        MERGE (email)-[:SENT_BY]->(sender_node)

        MERGE (domain:Domain {
            name: $sender_domain
        })

        MERGE (email)-[:USES_DOMAIN]->(domain)

        RETURN email.case_id AS case_id
        """

        with self.driver.session(
            database="neo4j"
        ) as session:

            session.run(
                email_query,
                case_id=case_id,
                sender=sender or "",
                recipient=recipient or "",
                subject=subject or "",
                sender_domain=sender_domain or ""
            ).consume()

        # ----------------------------------------------------
        # URLs
        # ----------------------------------------------------

        url_query = """
        MATCH (email:Email {
            case_id: $case_id
        })

        MERGE (domain:Domain {
            name: $sender_domain
        })

        WITH email, domain

        UNWIND $urls AS url_value

        MERGE (url:URL {
            value: url_value
        })

        MERGE (email)-[:CONTAINS_URL]->(url)

        MERGE (url)-[:ASSOCIATED_WITH]->(domain)

        RETURN count(url) AS urls_created
        """

        with self.driver.session(
            database="neo4j"
        ) as session:

            session.run(
                url_query,
                case_id=case_id,
                sender_domain=sender_domain or "",
                urls=urls or []
            ).consume()

        # ----------------------------------------------------
        # IPs
        # ----------------------------------------------------

        ip_query = """
        MATCH (email:Email {
            case_id: $case_id
        })

        UNWIND $ips AS ip_value

        MERGE (ip:IP {
            address: ip_value
        })

        MERGE (email)-[:PASSED_THROUGH]->(ip)

        RETURN count(ip) AS ips_created
        """

        with self.driver.session(
            database="neo4j"
        ) as session:

            session.run(
                ip_query,
                case_id=case_id,
                ips=ips or []
            ).consume()

        # ----------------------------------------------------
        # IP Intelligence
        # ----------------------------------------------------

        for intel in ip_intelligence:

            if not isinstance(
                intel,
                dict
            ):
                continue

            ip_address = intel.get(
                "ip"
            )

            if not ip_address:
                continue

            classification = intel.get(
                "classification",
                {}
            )

            reverse_dns = intel.get(
                "reverse_dns",
                {}
            )

            geolocation = intel.get(
                "geolocation",
                {}
            )

            ip_query = """
            MERGE (ip:IP {
                address: $ip
            })

            SET
                ip.type = $type,
                ip.public = $public,
                ip.private = $private,
                ip.reserved = $reserved,
                ip.reverse_dns = $reverse_dns,
                ip.country = $country,
                ip.country_code = $country_code,
                ip.region = $region,
                ip.city = $city,
                ip.latitude = $latitude,
                ip.longitude = $longitude,
                ip.organization = $organization,
                ip.asn = $asn

            RETURN ip
            """

            with self.driver.session(
                database="neo4j"
            ) as session:

                session.run(
                    ip_query,
                    ip=ip_address,
                    type=classification.get(
                        "type"
                    ),
                    public=classification.get(
                        "public",
                        False
                    ),
                    private=classification.get(
                        "private",
                        False
                    ),
                    reserved=classification.get(
                        "reserved",
                        False
                    ),
                    reverse_dns=reverse_dns.get(
                        "hostname"
                    ),
                    country=geolocation.get(
                        "country"
                    ),
                    country_code=geolocation.get(
                        "country_code"
                    ),
                    region=geolocation.get(
                        "region"
                    ),
                    city=geolocation.get(
                        "city"
                    ),
                    latitude=geolocation.get(
                        "latitude"
                    ),
                    longitude=geolocation.get(
                        "longitude"
                    ),
                    organization=geolocation.get(
                        "organization"
                    ),
                    asn=geolocation.get(
                        "asn"
                    )
                ).consume()

        # ----------------------------------------------------
        # Attachments
        # ----------------------------------------------------

        attachment_query = """
        MATCH (email:Email {
            case_id: $case_id
        })

        UNWIND $attachments AS attachment

        MERGE (file:Attachment {
            sha256: attachment.sha256
        })

        SET
            file.filename =
                attachment.filename,
            file.content_type =
                attachment.content_type,
            file.size =
                attachment.size

        MERGE (email)-[:HAS_ATTACHMENT]->(file)

        RETURN count(file) AS attachments_created
        """

        with self.driver.session(
            database="neo4j"
        ) as session:

            session.run(
                attachment_query,
                case_id=case_id,
                attachments=normalized_attachments
            ).consume()

        # ----------------------------------------------------
        # Domain Intelligence
        # ----------------------------------------------------

        if sender_domain:

            domain_query = """
            MERGE (domain:Domain {
                name: $domain
            })

            SET
                domain.status = $status,
                domain.registrar = $registrar,
                domain.registration_date =
                    $registration_date

            RETURN domain
            """

            with self.driver.session(
                database="neo4j"
            ) as session:

                session.run(
                    domain_query,
                    domain=sender_domain,
                    status=domain_intelligence.get(
                        "status"
                    ),
                    registrar=domain_intelligence.get(
                        "registrar"
                    ),
                    registration_date=domain_intelligence.get(
                        "registration_date"
                    )
                ).consume()

        return {
            "case_id": case_id,
            "graph_created": True,
            "nodes": {
                "email": 1,
                "sender": 1 if sender else 0,
                "domain": 1 if sender_domain else 0,
                "urls": len(urls or []),
                "ips": len(ips or []),
                "attachments": len(
                    normalized_attachments
                )
            }
        }

    # ========================================================
    # GET CASE GRAPH
    # ========================================================

    def get_case_graph(
        self,
        case_id: str
    ):

        self.connect()

        query = """
        MATCH (email:Email {
            case_id: $case_id
        })

        OPTIONAL MATCH path =
            (email)-[*1..4]-(connected)

        RETURN
            email,
            collect(path) AS paths
        """

        with self.driver.session(
            database="neo4j"
        ) as session:

            result = session.run(
                query,
                case_id=case_id
            )

            return list(result)