from typing import Any


class IOCCorrelator:

    def __init__(self, driver):
        self.driver = driver

    # ============================================================
    # FIND RELATED CASES
    # ============================================================

    def find_related_cases(
        self,
        case_id: str
    ) -> list[dict[str, Any]]:

        query = """
        MATCH (email:Email {
            case_id: $case_id
        })

        MATCH (email)-[*1..3]-(shared)

        MATCH (other:Email)-[*1..3]-(shared)

        WHERE other.case_id <> $case_id

        RETURN DISTINCT
            other.case_id AS case_id,
            labels(shared) AS shared_node_type,
            coalesce(
                shared.address,
                shared.value,
                shared.name,
                shared.sha256
            ) AS shared_indicator
        """

        with self.driver.session(
            database="neo4j"
        ) as session:

            result = session.run(
                query,
                case_id=case_id
            )

            return [
                dict(record)
                for record in result
            ]

    # ============================================================
    # FIND SHARED INFRASTRUCTURE
    # ============================================================

    def find_shared_infrastructure(
        self,
        case_id: str
    ) -> list[dict[str, Any]]:

        query = """
        MATCH (email:Email {
            case_id: $case_id
        })

        MATCH (email)-[
            :USES_DOMAIN|
            :CONTAINS_URL|
            :PASSED_THROUGH|
            :HAS_ATTACHMENT
        ]->(ioc)

        MATCH (other:Email)-[*1..3]-(ioc)

        WHERE other.case_id <> $case_id

        RETURN DISTINCT
            other.case_id AS related_case,
            labels(ioc) AS indicator_type,
            coalesce(
                ioc.address,
                ioc.value,
                ioc.name,
                ioc.sha256
            ) AS indicator
        """

        with self.driver.session(
            database="neo4j"
        ) as session:

            result = session.run(
                query,
                case_id=case_id
            )

            return [
                dict(record)
                for record in result
            ]

    # ============================================================
    # GROUP INDICATORS BY TYPE
    # ============================================================

    def group_indicators(
        self,
        shared_infrastructure
    ) -> dict[str, set]:

        grouped = {
            "Domain": set(),
            "URL": set(),
            "IP": set(),
            "Attachment": set(),
            "Sender": set()
        }

        for item in shared_infrastructure:

            indicator_types = item.get(
                "indicator_type",
                []
            )

            indicator = item.get(
                "indicator"
            )

            if not indicator:
                continue

            for indicator_type in indicator_types:

                if indicator_type in grouped:

                    grouped[
                        indicator_type
                    ].add(
                        indicator
                    )

        return grouped

    # ============================================================
    # EVIDENCE WEIGHTING
    # ============================================================

    def calculate_evidence_score(
        self,
        grouped: dict[str, set]
    ) -> tuple[int, list[dict[str, Any]]]:

        score = 0
        evidence = []

        # --------------------------------------------------------
        # Attachment hash
        # --------------------------------------------------------

        if grouped["Attachment"]:

            score += 40

            evidence.append({
                "indicator_type": "Attachment",
                "weight": 40,
                "count": len(
                    grouped["Attachment"]
                ),
                "reason": (
                    "Same file hash observed "
                    "across cases"
                )
            })

        # --------------------------------------------------------
        # Domain
        # --------------------------------------------------------

        if grouped["Domain"]:

            score += 25

            evidence.append({
                "indicator_type": "Domain",
                "weight": 25,
                "count": len(
                    grouped["Domain"]
                ),
                "reason": (
                    "Same domain observed "
                    "across cases"
                )
            })

        # --------------------------------------------------------
        # URL
        # --------------------------------------------------------

        if grouped["URL"]:

            score += 20

            evidence.append({
                "indicator_type": "URL",
                "weight": 20,
                "count": len(
                    grouped["URL"]
                ),
                "reason": (
                    "Same URL observed "
                    "across cases"
                )
            })

        # --------------------------------------------------------
        # IP
        # --------------------------------------------------------

        if grouped["IP"]:

            score += 20

            evidence.append({
                "indicator_type": "IP",
                "weight": 20,
                "count": len(
                    grouped["IP"]
                ),
                "reason": (
                    "Same IP observed "
                    "across cases"
                )
            })

        # --------------------------------------------------------
        # Sender
        # --------------------------------------------------------

        if grouped["Sender"]:

            score += 10

            evidence.append({
                "indicator_type": "Sender",
                "weight": 10,
                "count": len(
                    grouped["Sender"]
                ),
                "reason": (
                    "Same sender observed "
                    "across cases"
                )
            })

        # --------------------------------------------------------
        # Cap score
        # --------------------------------------------------------

        score = min(
            score,
            100
        )

        return score, evidence

    # ============================================================
    # CLASSIFICATION
    # ============================================================

    def classify_score(
        self,
        score: int,
        related_case_count: int
    ) -> str:

        if (
            score >= 70
            and related_case_count >= 2
        ):

            return "POTENTIAL CAMPAIGN"

        if score >= 50:

            return "HIGH CORRELATION"

        if score >= 25:

            return "RELATED ACTIVITY"

        return "NO STRONG CORRELATION"

    # ============================================================
    # CALCULATE CORRELATION
    # ============================================================

    def calculate_correlation_score(
        self,
        case_id: str
    ) -> dict[str, Any]:

        related_cases_raw = (
            self.find_related_cases(
                case_id
            )
        )

        shared_infrastructure = (
            self.find_shared_infrastructure(
                case_id
            )
        )

        # --------------------------------------------------------
        # Related cases
        # --------------------------------------------------------

        related_cases = sorted(
            {
                item.get("case_id")
                for item in related_cases_raw
                if item.get("case_id")
            }
        )

        # --------------------------------------------------------
        # Group indicators
        # --------------------------------------------------------

        grouped = self.group_indicators(
            shared_infrastructure
        )

        # --------------------------------------------------------
        # Calculate evidence score
        # --------------------------------------------------------

        score, evidence = (
            self.calculate_evidence_score(
                grouped
            )
        )

        # --------------------------------------------------------
        # Classification
        # --------------------------------------------------------

        classification = (
            self.classify_score(
                score,
                len(related_cases)
            )
        )

        # --------------------------------------------------------
        # Shared indicator summary
        # --------------------------------------------------------

        shared_indicator_summary = {}

        for indicator_type, values in grouped.items():

            if values:

                shared_indicator_summary[
                    indicator_type
                ] = sorted(
                    values
                )

        # --------------------------------------------------------
        # Final result
        # --------------------------------------------------------

        return {

            "case_id": case_id,

            "correlation_score": score,

            "classification": classification,

            "related_case_count": len(
                related_cases
            ),

            "related_cases": related_cases,

            "shared_indicators": (
                shared_indicator_summary
            ),

            "evidence": evidence,

            "shared_infrastructure": (
                shared_infrastructure
            )
        }