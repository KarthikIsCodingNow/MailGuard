from uuid import uuid4
import inspect
from pathlib import Path

from pydantic import BaseModel
from fastapi import FastAPI, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from app.ml.evaluation import evaluator

from app.parsing.email_parser import parse_email
from app.parsing.header_parser import extract_header_evidence
from app.parsing.url_extractor import extract_urls

from app.forensics.auth_analysis import analyze_authentication
from app.forensics.received_chain import reconstruct_received_chain

from app.detection.feature_extractor import extract_feature_vector
from app.detection.risk_scorer import calculate_risk_score
from app.detection.lookalike_detector import (
    analyze_lookalike_domain,
    extract_email_domain,
)
from app.detection.evidence_fusion import fuse_evidence

from app.intelligence.url_intelligence import analyze_urls
from app.intelligence.domain_intelligence import analyze_domain
from app.intelligence.ip_intelligence import analyze_ips
from app.intelligence.nlp_analyzer import analyze_email_language

from app.graph.neo4j_client import Neo4jClient
from app.graph.correlation import IOCCorrelator


# ============================================================
# TEXT ML
# ============================================================

def run_text_ml(
    subject: str,
    body: str,
) -> dict:
    """
    Run the trained TRACE-AI text classifier.

    The helper intentionally isolates the ML component from
    the main forensic pipeline so that ML failure does not
    break the rest of the investigation.
    """

    try:

        from app.ml import text_integration

        # ----------------------------------------------------
        # Combined email text
        # ----------------------------------------------------

        combined_text = (
            f"Subject: {subject}\n\n"
            f"{body}"
        )

        # ----------------------------------------------------
        # Locate the prediction function.
        #
        # This supports the prediction function names used
        # across the TRACE-AI ML modules.
        # ----------------------------------------------------

        possible_functions = [
            "predict_text",
            "predict_email",
            "predict_email_text",
            "classify_text",
            "analyze_text",
            "run_prediction",
        ]

        prediction_function = None

        for function_name in possible_functions:

            candidate = getattr(
                text_integration,
                function_name,
                None,
            )

            if callable(candidate):
                prediction_function = candidate
                break

        if prediction_function is None:

            return {
                "available": False,
                "status": "unavailable",
                "error": (
                    "No compatible text ML prediction "
                    "function was found."
                ),
            }

        # ----------------------------------------------------
        # Determine function parameters.
        # ----------------------------------------------------

        try:

            signature = inspect.signature(
                prediction_function
            )

            parameters = list(
                signature.parameters.values()
            )

        except (TypeError, ValueError):

            parameters = []

        # ----------------------------------------------------
        # Call prediction function.
        #
        # Supports either:
        #
        # predict_text(text)
        #
        # or:
        #
        # predict_text(subject, body)
        # ----------------------------------------------------

        if len(parameters) >= 2:

            result = prediction_function(
                subject,
                body,
            )

        else:

            result = prediction_function(
                combined_text
            )

        # ----------------------------------------------------
        # Normalize result.
        # ----------------------------------------------------

        if isinstance(result, dict):

            result = dict(result)

            result.setdefault(
                "available",
                True,
            )

            result.setdefault(
                "status",
                "completed",
            )

            return result

        return {
            "available": True,
            "status": "completed",
            "result": result,
        }

    except Exception as exc:

        return {
            "available": False,
            "status": "error",
            "error": str(exc),
        }


# ============================================================
# APPLICATION
# ============================================================

app = FastAPI(
    title="TRACE-AI",
    description=(
        "AI-Assisted Email Threat Detection "
        "& Forensic Intelligence Platform"
    ),
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"

neo4j_client = Neo4jClient()


class AnalyzeTextRequest(BaseModel):
    sender: str = ""
    subject: str = ""
    body: str = ""
    threshold: float = 0.50


# ============================================================
# EVALUATION & THREAT SCANNER API
# ============================================================

@app.get("/api/evaluate")
def evaluate_model_endpoint(threshold: float = Query(0.50, ge=0.01, le=0.99)):
    return evaluator.evaluate_at_threshold(threshold)


@app.post("/api/analyze-text")
def analyze_text_endpoint(req: AnalyzeTextRequest):
    # 1. Linguistic NLP Threat Analysis
    nlp = analyze_email_language(subject=req.subject, body=req.body, sender=req.sender)

    # 2. Lookalike Domain Analysis
    sender_domain = extract_email_domain(req.sender)
    known_brands = ["microsoft.com", "google.com", "apple.com", "amazon.com", "paypal.com"]
    lookalike = analyze_lookalike_domain(sender_domain, known_brands)

    # 3. Text ML Classification
    ml_pred = evaluator.predict_custom_text(subject=req.subject, body=req.body, threshold=req.threshold)

    # 4. URLs
    urls = extract_urls(f"{req.subject}\n{req.body}")
    url_intel = analyze_urls(urls)

    categories = nlp.get("categories", {})
    urgency_count = len(categories.get("urgency", {}).get("matches", []))
    credential_count = len(categories.get("credential_request", {}).get("matches", []))
    threat_count = len(categories.get("fear_or_threat", {}).get("matches", []))
    financial_count = len(categories.get("financial_pressure", {}).get("matches", []))
    authority_count = len(categories.get("authority_or_impersonation", {}).get("matches", []))
    secrecy_count = len(categories.get("secrecy", {}).get("matches", []))

    # 5. Risk Scoring & Signals
    features = {
        "urgency_count": urgency_count,
        "credential_request_count": credential_count,
        "threat_language_count": threat_count,
        "url_count": len(urls),
    }
    risk_assessment = calculate_risk_score(features, lookalike)

    signals = []
    if urgency_count > 0:
        signals.append({"type": "danger", "text": f"🚨 Urgency language detected ({urgency_count} signals)"})
    if credential_count > 0:
        signals.append({"type": "danger", "text": f"🔑 Credential harvesting signals detected ({credential_count} signals)"})
    if threat_count > 0:
        signals.append({"type": "danger", "text": f"⚠️ Threat / penalty language detected ({threat_count} signals)"})
    if financial_count > 0:
        signals.append({"type": "danger", "text": f"💰 Financial pressure / wire transaction language ({financial_count} signals)"})
    if authority_count > 0:
        signals.append({"type": "warning", "text": f"👔 Authority / executive impersonation markers ({authority_count} signals)"})
    if secrecy_count > 0:
        signals.append({"type": "warning", "text": f"🤫 Secrecy / out-of-band prohibition language ({secrecy_count} signals)"})
    if lookalike.get("is_lookalike", False):
        signals.append({"type": "danger", "text": f"🚨 Lookalike domain: possible {lookalike.get('matched_brand')} impersonation ({lookalike.get('similarity')}% match)"})
    if len(urls) > 0:
        signals.append({"type": "warning", "text": f"🔗 Extracted {len(urls)} link(s)"})
    if not signals:
        signals.append({"type": "success", "text": "✅ Clean Email: No psychological pressure or threat signals found"})

    forensics_score = float(risk_assessment.get("threat_score", 0))
    nlp_score = float(nlp.get("nlp_score", 0))
    lookalike_score = 85.0 if lookalike.get("is_lookalike") else 0.0
    auth_score = 60.0 if lookalike.get("is_lookalike") else 0.0
    ml_score = ml_pred.get("probabilities", {}).get("spam", 0.0) * 100

    fused_score = min(100.0, (
        forensics_score * 0.225 +
        nlp_score * 0.180 +
        lookalike_score * 0.135 +
        auth_score * 0.135 +
        ml_score * 0.100
    ))

    active_sources = sum([
        forensics_score >= 40,
        nlp_score >= 40,
        lookalike_score >= 50,
        ml_score >= 70
    ])
    if active_sources >= 3:
        fused_score = min(100.0, fused_score + 15)

    level = "LOW"
    badge_class = "level-low"
    classification = "BENIGN / HAM"
    if fused_score >= 70:
        level = "HIGH"
        badge_class = "level-high"
        classification = "PHISHING / MALICIOUS"
    elif fused_score >= 40:
        level = "MEDIUM"
        badge_class = "level-medium"
        classification = "SUSPICIOUS / SPAM"

    return {
        "score": round(fused_score),
        "level": level,
        "badgeClass": badge_class,
        "classification": classification,
        "mlProb": round(ml_score, 1),
        "criticalCount": active_sources,
        "forensics": round(forensics_score),
        "nlp": round(nlp_score),
        "lookalike": round(lookalike_score),
        "auth": round(auth_score),
        "ml": round(ml_score),
        "attach": 0,
        "signals": signals
    }


# ============================================================
# STATIC FRONTEND ROUTES
# ============================================================

@app.get("/")
def serve_ui():
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {"message": "TRACE-AI API Running"}


@app.get("/styles.css")
def serve_css():
    return FileResponse(str(FRONTEND_DIR / "styles.css"))


@app.get("/app.js")
def serve_js():
    return FileResponse(str(FRONTEND_DIR / "app.js"))


@app.get("/api/info")
def api_info():
    return {
        "project": "TRACE-AI",
        "status": "running",
        "version": "0.2.0",
        "components": {
            "email_forensics": True,
            "nlp_analyzer": True,
            "text_ml": True,
            "neo4j": True,
            "evidence_fusion": True,
        },
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():

    neo4j_status = False
    neo4j_error = None

    try:

        neo4j_status = neo4j_client.health_check()

    except Exception as exc:

        neo4j_error = str(exc)

    # --------------------------------------------------------
    # ML availability check
    # --------------------------------------------------------

    ml_available = False
    ml_error = None

    try:

        from app.ml import text_integration

        ml_available = True

    except Exception as exc:

        ml_error = str(exc)

    return {

        "status": "healthy",

        "neo4j": (
            "connected"
            if neo4j_status
            else "unavailable"
        ),

        "neo4j_error": neo4j_error,

        "text_ml": (
            "available"
            if ml_available
            else "unavailable"
        ),

        "text_ml_error": ml_error,
    }


# ============================================================
# EMAIL ANALYSIS
# ============================================================

@app.post("/analyze")
async def analyze_email(
    file: UploadFile = File(...),
):

    # ========================================================
    # 1. FILE VALIDATION
    # ========================================================

    if not file.filename:

        return {
            "error": "No file provided."
        }

    if not file.filename.lower().endswith(".eml"):

        return {
            "error": "Only .eml files are supported."
        }


    # ========================================================
    # 2. READ FILE
    # ========================================================

    raw_email = await file.read()

    if not raw_email:

        return {
            "error": "The uploaded email file is empty."
        }


    # ========================================================
    # 3. PARSE EMAIL
    # ========================================================

    parsed_email = parse_email(
        raw_email
    )


    # ========================================================
    # 4. HEADER FORENSICS
    # ========================================================

    header_evidence = extract_header_evidence(
        parsed_email.get(
            "headers",
            {}
        )
    )


    # ========================================================
    # 5. AUTHENTICATION ANALYSIS
    # ========================================================

    authentication_results = (
        analyze_authentication(
            header_evidence.get(
                "authentication_results",
                []
            )
        )
    )


    # ========================================================
    # 6. RECEIVED / SMTP PATH
    # ========================================================

    received_chain = (
        reconstruct_received_chain(
            header_evidence.get(
                "received_chain",
                []
            )
        )
    )


    # ========================================================
    # 7. RECEIVED IPS
    # ========================================================

    received_ips = [

        hop.get("ip")

        for hop in received_chain

        if hop.get("ip")
    ]

    received_ips = list(
        dict.fromkeys(
            received_ips
        )
    )


    # ========================================================
    # 8. IP INTELLIGENCE
    # ========================================================

    ip_intelligence = analyze_ips(
        received_ips
    )


    # ========================================================
    # 9. URL EXTRACTION
    # ========================================================

    body = parsed_email.get(
        "body",
        ""
    )

    html_body = parsed_email.get(
        "html_body",
        ""
    )

    text_for_url_analysis = (
        body
        + "\n"
        + html_body
    )

    urls = extract_urls(
        text_for_url_analysis
    )

    urls = list(
        dict.fromkeys(
            urls
        )
    )


    # ========================================================
    # 10. URL INTELLIGENCE
    # ========================================================

    url_intelligence = analyze_urls(
        urls
    )


    # ========================================================
    # 11. BASIC EMAIL INFORMATION
    # ========================================================

    sender = header_evidence.get(
        "sender",
        ""
    )

    recipient = header_evidence.get(
        "recipient",
        ""
    )

    subject = header_evidence.get(
        "subject",
        ""
    )


    # ========================================================
    # 12. DETERMINISTIC NLP THREAT-LANGUAGE ANALYSIS
    # ========================================================

    nlp_analysis = analyze_email_language(
        subject=subject,
        body=body,
        sender=sender,
    )


    # ========================================================
    # 13. TEXT ML CLASSIFIER
    # ========================================================
    #
    # This is the real trained TF-IDF + Logistic Regression
    # model.
    #
    # It analyzes the actual email subject/body.
    #
    # IMPORTANT:
    # This result is kept separate from deterministic NLP.
    # Evidence fusion will combine them later.
    # ========================================================

    text_ml_analysis = run_text_ml(
        subject=subject,
        body=body,
    )


    # ========================================================
    # 14. FEATURE EXTRACTION
    # ========================================================

    features = extract_feature_vector(
        parsed_email=parsed_email,
        header_evidence=header_evidence,
        authentication_analysis=(
            authentication_results
        ),
        received_chain=received_chain,
        urls=urls,
    )


    # ========================================================
    # 15. SENDER DOMAIN
    # ========================================================

    sender_domain = extract_email_domain(
        sender
    )


    # ========================================================
    # 16. LOOKALIKE DOMAIN DETECTION
    # ========================================================

    legitimate_domains = [

        "microsoft.com",

        "google.com",

        "apple.com",

        "amazon.com",

    ]

    lookalike_analysis = (
        analyze_lookalike_domain(
            sender_domain,
            legitimate_domains,
        )
    )


    # ========================================================
    # 17. DOMAIN INTELLIGENCE
    # ========================================================

    domain_intelligence = analyze_domain(
        sender_domain
    )


    # ========================================================
    # 18. RISK ASSESSMENT
    # ========================================================

    risk_assessment = (
        calculate_risk_score(
            features,
            lookalike_analysis,
        )
    )


    # ========================================================
    # 19. GENERATE CASE ID
    # ========================================================

    case_id = (
        "TRC-"
        + uuid4().hex[:10].upper()
    )


    # ========================================================
    # 20. NEO4J GRAPH CREATION
    # ========================================================

    graph_result = None
    graph_error = None

    try:

        graph_result = (
            neo4j_client.create_case_graph(

                case_id=case_id,

                sender=sender,

                recipient=recipient,

                subject=subject,

                sender_domain=sender_domain,

                urls=urls,

                ips=received_ips,

                attachments=(
                    parsed_email.get(
                        "attachments",
                        []
                    )
                ),

                ip_intelligence=(
                    ip_intelligence
                ),

                domain_intelligence=(
                    domain_intelligence
                ),
            )
        )

    except Exception as exc:

        graph_error = str(exc)


    # ========================================================
    # 21. IOC CORRELATION
    # ========================================================

    correlation_result = None
    correlation_error = None

    if graph_result:

        try:

            neo4j_client.connect()

            correlator = IOCCorrelator(
                neo4j_client.driver
            )

            correlation_result = (
                correlator.calculate_correlation_score(
                    case_id
                )
            )

        except Exception as exc:

            correlation_error = str(exc)


    # ========================================================
    # 22. EVIDENCE FUSION
    # ========================================================

    evidence_fusion = None
    evidence_fusion_error = None

    try:

        evidence_fusion = fuse_evidence(

            risk_assessment=(
                risk_assessment
            ),

            nlp_analysis=(
                nlp_analysis
            ),

            lookalike_analysis=(
                lookalike_analysis
            ),

            authentication_analysis=(
                authentication_results
            ),

            url_intelligence=(
                url_intelligence
            ),

            attachments=(
                parsed_email.get(
                    "attachments",
                    []
                )
            ),

            correlation=(
                correlation_result
                or {}
            ),
        )

    except Exception as exc:

        evidence_fusion_error = str(exc)


    # ========================================================
    # 23. FINAL RESPONSE
    # ========================================================

    return {

        # ====================================================
        # CASE
        # ====================================================

        "case_id": case_id,

        "filename": file.filename,


        # ====================================================
        # EMAIL
        # ====================================================

        "headers": parsed_email.get(
            "headers",
            {}
        ),

        "body": body,

        "html_body": html_body,


        # ====================================================
        # HEADER FORENSICS
        # ====================================================

        "header_evidence": (
            header_evidence
        ),


        # ====================================================
        # AUTHENTICATION
        # ====================================================

        "authentication_analysis": (
            authentication_results
        ),


        # ====================================================
        # SMTP / RECEIVED PATH
        # ====================================================

        "received_chain_analysis": (
            received_chain
        ),


        # ====================================================
        # IP INTELLIGENCE
        # ====================================================

        "ip_intelligence": (
            ip_intelligence
        ),


        # ====================================================
        # URLS
        # ====================================================

        "urls": urls,


        # ====================================================
        # URL INTELLIGENCE
        # ====================================================

        "url_intelligence": (
            url_intelligence
        ),


        # ====================================================
        # ATTACHMENTS
        # ====================================================

        "attachments": (
            parsed_email.get(
                "attachments",
                []
            )
        ),


        # ====================================================
        # DETERMINISTIC NLP
        # ====================================================

        "nlp_analysis": nlp_analysis,


        # ====================================================
        # TEXT ML
        # ====================================================
        #
        # Real trained ML prediction.
        # ====================================================

        "text_ml_analysis": (
            text_ml_analysis
        ),


        # ====================================================
        # FEATURES
        # ====================================================

        "features": features,


        # ====================================================
        # SENDER DOMAIN
        # ====================================================

        "sender_domain": sender_domain,


        # ====================================================
        # LOOKALIKE
        # ====================================================

        "lookalike_analysis": (
            lookalike_analysis
        ),


        # ====================================================
        # DOMAIN INTELLIGENCE
        # ====================================================

        "domain_intelligence": (
            domain_intelligence
        ),


        # ====================================================
        # ORIGINAL RISK ENGINE
        # ====================================================

        "risk_assessment": (
            risk_assessment
        ),


        # ====================================================
        # EVIDENCE FUSION
        # ====================================================

        "evidence_fusion": {

            "status": (

                "completed"

                if evidence_fusion

                else "unavailable"

            ),

            "result": evidence_fusion,

            "error": evidence_fusion_error,
        },


        # ====================================================
        # NEO4J
        # ====================================================

        "graph": {

            "status": (

                "created"

                if graph_result

                else "unavailable"

            ),

            "result": graph_result,

            "error": graph_error,
        },


        # ====================================================
        # CORRELATION
        # ====================================================

        "correlation": {

            "status": (

                "completed"

                if correlation_result

                else "unavailable"

            ),

            "result": correlation_result,

            "error": correlation_error,
        },
    }


# ============================================================
# GRAPH ENDPOINT
# ============================================================

@app.get("/cases/{case_id}/graph")
def get_case_graph(
    case_id: str,
):

    try:

        records = (
            neo4j_client.get_case_graph(
                case_id
            )
        )

        nodes = []

        relationships = []

        seen_nodes = set()

        seen_relationships = set()


        # ----------------------------------------------------
        # Convert Neo4j paths into JSON-friendly objects
        # ----------------------------------------------------

        for record in records:

            paths = record.get(
                "paths",
                []
            )

            for path in paths:

                if path is None:
                    continue


                for node in path.nodes:

                    node_id = str(
                        node.element_id
                    )

                    if node_id not in seen_nodes:

                        seen_nodes.add(
                            node_id
                        )

                        nodes.append({

                            "id": node_id,

                            "labels": list(
                                node.labels
                            ),

                            "properties": dict(
                                node
                            ),
                        })


                for relationship in path.relationships:

                    relationship_id = str(
                        relationship.element_id
                    )

                    if (
                        relationship_id
                        not in seen_relationships
                    ):

                        seen_relationships.add(
                            relationship_id
                        )

                        relationships.append({

                            "id": relationship_id,

                            "type": relationship.type,

                            "start_node": str(
                                relationship.start_node.element_id
                            ),

                            "end_node": str(
                                relationship.end_node.element_id
                            ),

                            "properties": dict(
                                relationship
                            ),
                        })


        return {

            "case_id": case_id,

            "nodes": nodes,

            "relationships": relationships,
        }


    except Exception as exc:

        return {

            "case_id": case_id,

            "nodes": [],

            "relationships": [],

            "error": str(exc),
        }