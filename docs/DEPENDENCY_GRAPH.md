graph LR
    M0_auto_debug_system --> M1_core_collector
    M0_auto_debug_system --> M3_core_history
    M1_core_collector --> M3_core_history
    M1_core_collector --> M18_sources_bridgedb_api
    M1_core_collector --> M19_sources_moat
    M1_core_collector --> M20_sources_telegram_bridges
    M1_core_collector --> M21_sources_torproject
    M2_core_formatter --> M3_core_history
    M2_core_formatter --> M5_core_scorer
    M2_core_formatter --> M7_core_tester
    M5_core_scorer --> M7_core_tester
    M6_core_smart_iran_scorer --> M5_core_scorer
    M10_main --> M0_auto_debug_system
    M10_main --> M1_core_collector
    M10_main --> M2_core_formatter
    M10_main --> M3_core_history
    M10_main --> M4_core_notifier
    M10_main --> M5_core_scorer
    M10_main --> M7_core_tester
    M10_main --> M9_iran_smart_anti_filter
    M11_monitoring___init__ --> M12_monitoring_provider_dashboard
    M11_monitoring___init__ --> M13_monitoring_structured_logging
    M16_scripts_ai_bridge_reranker --> M6_core_smart_iran_scorer
    M21_sources_torproject --> M7_core_tester
    M23_torshield_ai_gateway_iran_auto_defense --> M22_torshield_ai_gateway_ai_anti_dpi_iran_v2
    M23_torshield_ai_gateway_iran_auto_defense --> M24_torshield_ai_gateway_iran_smart_anti_filter_v2
    M24_torshield_ai_gateway_iran_smart_anti_filter_v2 --> M9_iran_smart_anti_filter

## Third-Party Dependencies

- `ai_anti_dpi_iran_v2`
- `aiohttp`
- `aioquic`
- `argparse`
- `ast`
- `bs4`
- `concurrent`
- `cryptography`
- `gateway`
- `importlib`
- `ipaddress`
- `iran_auto_defense`
- `iran_intelligence`
- `iran_smart_anti_filter_v2`
- `local_ai_engine`
- `model_selector`
- `numpy`
- `pickle`
- `platform`
- `providers`
- `requests`
- `rich`
- `rotator`
- `secrets`
- `sklearn`
- `smart_bypass_engine`
- `string`
- `tarfile`
- `torshield_ai_gateway`
- `yaml`
- `zipfile`
