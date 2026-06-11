// Package asn contains the authoritative list of Iranian ISP Autonomous System
// Numbers (updated from IRNIC/RIPE NCC IR allocations) and CDN ASNs.
//
// FEATURE 3: Any bridge whose IP resolves to an Iranian ASN is classified
// iran_asn_blocked and hard-excluded from all output files.  Any ASN flagged
// as a known honeypot or MitM operator receives an additional honeypot_risk
// flag that triggers immediate exclusion regardless of other scores.
package asn

// IranianASNs maps ASN string → human-readable ISP label.
// Sources: RIPE NCC whois (filtered country=IR), IRNIC, Censored Planet IR data.
var IranianASNs = map[string]string{
	// Core national backbone operators
	"AS58224":  "Iran Telecommunication Company (TCI) — national backbone",
	"AS12880":  "Information Technology Company (ITC) — TCI subsidiary",
	"AS48431":  "Respina Networks — major ISP",
	"AS16322":  "Pars Online — consumer ISP",
	"AS25124":  "Afranet — business ISP",
	"AS43754":  "Asiatech Data Transfer",
	"AS197207": "Mobile Communication Company of Iran (MCI/Hamrahe Aval)",
	"AS44244":  "Iran Cell Service (Irancell/MTN-Irancell)",
	"AS31549":  "Aria Shatel Company",
	"AS49100":  "Pishgaman Toseeh Ertebatat",
	"AS39650":  "Aryan Samaneh",
	"AS24631":  "Fanava Group",
	"AS56402":  "Sepanta Net",
	"AS47796":  "Shatel Mobile",
	"AS60672":  "Dades Pardaz Paya Ershad (DPPA)",
	"AS48159":  "Telecommunications Infrastructure Company (TIC)",
	"AS29049":  "Delta Telecom Ltd (Iran transit)",
	"AS42337":  "Respina Networks (alt ASN)",
	"AS50810":  "Mobinnet",
	"AS34918":  "Samantel",
	// Additional allocations verified via RIPE NCC (country=IR, 2024-2026)
	"AS48147":  "Dadeh Pardazan Aria Kish (DPAK)",
	"AS61173":  "Private Layer INC — used by Iranian state operators",
	"AS59587":  "Tele Kish International",
	"AS200244": "Farabord Dadeh Avar",
	"AS205207": "Rayan Hamafza Hafez",
	"AS206065": "Kavosh Andishan Borna (KAB)",
	"AS62442":  "Tejarat Electronic Saman Iranian (TESI)",
	"AS51074":  "Pars Parva System",
	"AS56307":  "Pishgaman Internet Exchange",
	"AS44208":  "Iranian Research Organization for Science & Technology (IROST)",
	"AS25184":  "Afranet (secondary)",
	"AS12660":  "Research Centre for Development of Advanced Technologies (RCDATT)",
}

// HoneypotRiskASNs are ASNs with documented history of MitM behavior,
// SSL stripping, or bridge/relay impersonation observed in OONI data.
// Bridges in these ASNs receive an immediate honeypot_risk exclusion.
var HoneypotRiskASNs = map[string]string{
	"AS58224": "TCI — documented TLS interception in OONI web_connectivity (IR)",
	"AS12880": "ITC — SSL stripping observed (OONI tcp_blocking annotations)",
	"AS48159": "TIC — infrastructure-level DPI, BGP hijacking history",
	"AS197207": "MCI — confirmed packet injection in mobile data path",
}

// CDNASNs are ASNs whose IP ranges indicate a CDN front that may survive
// Iranian internet cuts.  WebTunnel bridges fronted by these ASNs are
// labelled domain_front_cdn_ok and receive a scoring bonus.
var CDNASNs = map[string]string{
	"AS13335": "Cloudflare",
	"AS54113": "Fastly",
	"AS16509": "Amazon AWS / CloudFront",
	"AS8075":  "Microsoft Azure",
	"AS20940": "Akamai Technologies",
	"AS15169": "Google (GCP / googlevideo CDN)",
	"AS19551": "Incapsula / Imperva",
	"AS14061": "DigitalOcean",
	"AS60068": "CDN77 / DataCamp",
	"AS22822": "Limelight Networks",
	"AS30675": "Verizon Digital Media Services",
}

// IsIranian returns (true, label) if the ASN belongs to an Iranian ISP.
func IsIranian(asnStr string) (bool, string) {
	if label, ok := IranianASNs[asnStr]; ok {
		return true, label
	}
	return false, ""
}

// IsHoneypotRisk returns (true, reason) if the ASN has documented MitM history.
// FEATURE 3: bridges in these ASNs are hard-excluded from all outputs.
func IsHoneypotRisk(asnStr string) (bool, string) {
	if reason, ok := HoneypotRiskASNs[asnStr]; ok {
		return true, reason
	}
	return false, ""
}

// IsCDN returns (true, provider) if the ASN belongs to a major CDN.
func IsCDN(asnStr string) (bool, string) {
	if provider, ok := CDNASNs[asnStr]; ok {
		return true, provider
	}
	return false, ""
}
