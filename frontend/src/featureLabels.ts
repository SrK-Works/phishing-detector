// Turns raw feature keys like "host_domain_age_days" into short,
// non-technical phrases for the explanation list.
const LABELS: Record<string, string> = {
  lexical_has_ip_address: "URL uses a raw IP address instead of a domain name",
  lexical_uses_url_shortener: "URL uses a link-shortening service",
  lexical_has_at_symbol: "URL contains an '@' symbol",
  lexical_has_double_slash_redirect: "URL hides a redirect with '//'",
  lexical_subdomain_count: "Number of subdomains",
  lexical_uses_https: "Uses HTTPS",
  lexical_domain_entropy: "Domain name looks randomly generated",
  lexical_has_suspicious_tld: "Domain ends in a TLD often abused for phishing",
  lexical_brand_typosquat_distance: "How closely the domain name matches a well-known brand",
  lexical_is_exact_brand_domain: "Domain exactly matches a well-known brand",
  lexical_url_length: "URL length",
  lexical_digit_ratio_in_domain: "Domain name is mostly digits",
  host_dns_resolves: "Domain has a DNS record",
  host_domain_age_days: "Domain age",
  host_registration_length_days: "How far out the domain registration runs",
  host_has_valid_https: "Has a valid HTTPS certificate",
  host_tls_cert_age_days: "HTTPS certificate age",
  content_external_anchor_ratio: "Share of links pointing to other sites",
  content_has_iframe: "Page embeds an iframe",
  content_has_mailto_form: "Page submits form data via email",
  content_external_resource_ratio: "Share of scripts/styles loaded from other sites",
  content_redirect_count: "Number of redirects before landing on this page",
  content_fetch_succeeded: "Page content could be fetched",
};

export function humanizeFeature(key: string): string {
  return LABELS[key] ?? key.replace(/^(lexical|host|content)_/, "").replaceAll("_", " ");
}
