#!/usr/bin/env python3
"""
AI Gateway Health Check v9.0
Tests all configured providers AND the dynamic model selector.
Exits 0 if any provider responds (degraded OK); 1 if all fail.
"""

import os, sys, json, argparse, time, logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
logger = logging.getLogger("health_check")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def check_model_selector() -> dict:
    """Run model selector status check without making any AI calls."""
    from torshield_ai_gateway.model_selector import CloudflareModelSelector
    sel = CloudflareModelSelector.instance()
    try:
        ranked = sel.ranked_models(task="general", top_n=5)
        top = ranked[0] if ranked else None
        return {
            "status":   "ok",
            "total":    len(ranked),
            "top_model": top.id if top else "none",
            "top_score": top.score if top else 0.0,
            "top_5": [
                {"rank": i+1, "id": m.id, "score": m.score, "tier": m.tier}
                for i, m in enumerate(ranked)
            ],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)[:300]}


def check_provider(provider_name: str, task: str = "general") -> dict:
    from torshield_ai_gateway.gateway import TorShieldAIGateway
    gw = TorShieldAIGateway()
    start = time.time()
    try:
        result = gw.chat(
            messages=[{"role": "user", "content": "Reply with exactly: TORSHIELD_OK"}],
            max_tokens=20,
            temperature=0.0,
            preferred_provider=provider_name,
            task=task,
        )
        latency = time.time() - start
        ok = "TORSHIELD_OK" in result.upper()
        return {
            "provider":   provider_name,
            "status":     "ok" if ok else "wrong_response",
            "latency_ms": round(latency * 1000),
            "response":   result[:100],
        }
    except Exception as e:
        latency = time.time() - start
        return {
            "provider":   provider_name,
            "status":     "error",
            "latency_ms": round(latency * 1000),
            "error":      str(e)[:300],
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output",  default="gateway_health_report.json")
    parser.add_argument("--task",    default="general",
        choices=["general", "reasoning", "coding", "vision", "fast"])
    parser.add_argument(
        "--providers", nargs="+",
        default=["cerebras", "cloudflare_ai_gateway",
                 "cloudflare_workers_ai", "portkey"],
    )
    args = parser.parse_args()

    report = {
        "timestamp":       time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "run_id":          os.environ.get("GITHUB_RUN_ID", "local"),
        "model_selector":  {},
        "results":         [],
        "summary":         {},
    }

    # Model selector status (always runs, never fails the health check)
    logger.info("Checking model selector …")
    ms_result = check_model_selector()
    report["model_selector"] = ms_result
    if ms_result.get("status") == "ok":
        logger.info(f"  Model selector OK — top: {ms_result['top_model']} "
                    f"(score={ms_result['top_score']})")
        for entry in ms_result.get("top_5", []):
            logger.info(f"    #{entry['rank']} {entry['id']} "
                        f"score={entry['score']} tier={entry['tier']}")
    else:
        logger.warning(f"  Model selector error: {ms_result.get('error')}")

    # Provider checks
    ok_count = 0
    for pname in args.providers:
        logger.info(f"Checking {pname} [task={args.task}] …")
        result = check_provider(pname, task=args.task)
        report["results"].append(result)
        if result["status"] == "ok":
            ok_count += 1
        logger.info(f"  {result['status'].upper()} ({result['latency_ms']}ms)")

    report["summary"] = {
        "total":   len(args.providers),
        "ok":      ok_count,
        "degraded": len(args.providers) - ok_count,
        "healthy": ok_count > 0,
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    logger.info(f"Health: {ok_count}/{len(args.providers)} providers OK")
    if ok_count == 0:
        logger.error("CRITICAL: No AI providers available")
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
