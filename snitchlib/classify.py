# -*- coding: utf-8 -*-
"""Domain classification, base-domain extraction and port/service names.

The old implementation used ``keyword in domain`` which misclassifies names
such as ``notgoogle.com`` and had no concept of registrable domains. This
module matches explicit suffixes first, then falls back to distinctive
substrings, and understands common multi-part public suffixes (``co.uk``...).
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Tuple

CAT_TARGET = "Target"
CAT_CHATBOT = "Chatbot / support"
CAT_TRACKING = "Ads / tracking"
CAT_ANALYTICS = "Analytics"
CAT_DEVICE = "Device / OS telemetry"
CAT_UPDATES = "Software updates"
CAT_APPS = "Other apps"
CAT_EMAIL = "Email"
CAT_SECURITY = "Security / VPN"
CAT_CDN = "CDN / infrastructure"
CAT_CLOUD = "Cloud / hosting"
CAT_OTHER = "Unclassified"

CATEGORY_ORDER = [
    CAT_TARGET, CAT_CHATBOT, CAT_TRACKING, CAT_ANALYTICS, CAT_DEVICE,
    CAT_UPDATES, CAT_APPS, CAT_EMAIL, CAT_SECURITY, CAT_CDN, CAT_CLOUD,
    CAT_OTHER,
]

CATEGORY_DESCRIPTIONS = {
    CAT_TARGET: "The domain you asked SNItch to follow (--target).",
    CAT_CHATBOT: "Support widgets and AI/chat assistants embedded in apps.",
    CAT_TRACKING: "Advertising, attribution and cross-site tracking.",
    CAT_ANALYTICS: "Product analytics, crash reporting and monitoring.",
    CAT_DEVICE: "Operating-system, browser and device telemetry.",
    CAT_UPDATES: "Application and operating-system update delivery.",
    CAT_APPS: "Social networks, media, shopping, work and other user apps.",
    CAT_EMAIL: "Mail providers and mail infrastructure.",
    CAT_SECURITY: "Antivirus, DNS resolvers and VPN providers.",
    CAT_CDN: "Content delivery and shared edge infrastructure.",
    CAT_CLOUD: "Cloud hosting and platform providers.",
    CAT_OTHER: "Domains no rule matched. Inspect them manually.",
}


# Domain suffixes are matched on label boundaries (``example.com`` matches
# ``cdn.example.com`` but not ``notexample.com``).
SUFFIX_RULES: List[Tuple[str, Tuple[str, ...]]] = [
    (CAT_CHATBOT, (
        "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
        "anthropic.com", "claude.ai", "perplexity.ai", "character.ai",
        "huggingface.co", "copilot.microsoft.com", "gemini.google.com",
        "zendesk.com", "zdassets.com", "zopim.com", "intercom.io",
        "intercomcdn.com", "tidio.co", "tawk.to", "drift.com",
        "livechatinc.com", "crisp.chat", "freshchat.com", "freshdesk.com",
        "landbot.io", "manychat.com", "dialogflow.com", "watsonplatform.net",
    )),
    (CAT_TRACKING, (
        "doubleclick.net", "googleadservices.com", "googlesyndication.com",
        "adservice.google.com", "adsystem.com", "scorecardresearch.com",
        "criteo.com", "criteo.net", "taboola.com", "outbrain.com",
        "adnxs.com", "rubiconproject.com", "pubmatic.com", "openx.net",
        "casalemedia.com", "moatads.com", "2mdn.net", "connect.facebook.net",
        "ads-twitter.com", "ads.linkedin.com", "analytics.twitter.com",
        "app-measurement.com", "adjust.com", "appsflyer.com", "branch.io",
        "marketingplatform.google.com", "cookiebot.com", "onetrust.com",
        "cookielaw.org", "demdex.net", "omtrdc.net", "everesttech.net",
        "bluekai.com", "krxd.net", "mathtag.com", "sharethis.com",
        "addthis.com", "quantserve.com", "chartbeat.com", "parsely.com",
    )),
    (CAT_ANALYTICS, (
        "google-analytics.com", "googletagmanager.com", "hotjar.com",
        "hotjar.io", "mixpanel.com", "segment.io", "segment.com",
        "amplitude.com", "heap.io", "heapanalytics.com", "fullstory.com",
        "newrelic.com", "nr-data.net", "sentry.io", "bugsnag.com",
        "datadoghq.com", "stats.wp.com", "matomo.cloud", "plausible.io",
        "umami.is", "clarity.ms", "mouseflow.com", "smartlook.com",
    )),
    (CAT_DEVICE, (
        "xiaomi.com", "miui.com", "mioffice.com", "firebaseio.com",
        "crashlytics.com", "safebrowsing.googleapis.com", "gvt1.com",
        "gvt2.com", "connectivitycheck.gstatic.com", "time.android.com",
        "android.clients.google.com", "play.googleapis.com",
        "telemetry.mozilla.org", "incoming.telemetry.mozilla.org",
        "firefox.com", "mozilla.net", "mozilla.org", "mozilla.com",
        "msftconnecttest.com", "msftncsi.com", "icloud.com",
        "apple.com", "apple-dns.net", "mzstatic.com", "umeng.com",
        "windowsupdate.com", "update.microsoft.com", "telemetry.microsoft.com",
        "settings-win.data.microsoft.com", "v10.events.data.microsoft.com",
        "watson.telemetry.microsoft.com", "samsungapps.com", "samsung.com",
        "hicloud.com", "huawei.com", "oneplus.net", "oplus.com",
        "coloros.com", "vivo.com", "oppo.com", "realme.com",
    )),
    (CAT_UPDATES, (
        "update.googleapis.com", "dl.google.com", "clients2.google.com",
        "clients3.google.com", "clients4.google.com",
        "redirector.gvt1.com", "download.windowsupdate.com",
        "swcdn.apple.com", "mesu.apple.com", "updates.cdn-apple.com",
        "archive.ubuntu.com", "security.ubuntu.com", "deb.debian.org",
        "cdn.fwupd.org", "firmware.microsoft.com",
    )),
    (CAT_EMAIL, (
        "gmail.com", "googlemail.com", "outlook.com", "outlook.office365.com",
        "office365.com", "hotmail.com", "live.com", "yahoo.com",
        "protonmail.com", "proton.me", "mail.ru", "yandex.com", "zoho.com",
        "fastmail.com", "mail.com", "gmx.com", "gmx.net", "tutanota.com",
    )),
    (CAT_SECURITY, (
        "avast.com", "avg.com", "kaspersky.com", "mcafee.com", "norton.com",
        "bitdefender.com", "malwarebytes.com", "eset.com", "sophos.com",
        "cloudflare-dns.com", "dns.google", "mozilla.cloudflare-dns.com",
        "nextdns.io", "quad9.net", "opendns.com", "expressvpn.com",
        "nordvpn.com", "surfshark.com", "protonvpn.com", "torproject.org",
        "torproject.net", "virustotal.com", "abuse.ch", "spamhaus.org",
    )),
    (CAT_CDN, (
        "cloudflare.com", "cloudflare.net", "cdn.cloudflare.net",
        "akamai.net", "akamaiedge.net", "akamaihd.net", "edgekey.net",
        "edgesuite.net", "fastly.net", "fastlylb.net", "cloudfront.net",
        "azureedge.net", "azurefd.net", "gstatic.com", "googleusercontent.com",
        "ggpht.com", "llnwd.net", "cdn77.org", "stackpathdns.com",
        "bunnycdn.com", "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
        "bootstrapcdn.com", "typekit.net", "fonts.googleapis.com",
        "msedge.net", "arpa",
    )),
    (CAT_CLOUD, (
        "amazonaws.com", "azure.com", "windows.net", "microsoftonline.com",
        "office.net", "digitalocean.com", "linode.com", "vultr.com",
        "herokuapp.com", "vercel.app", "netlify.app", "firebaseapp.com",
        "appspot.com", "cloudfunctions.net", "run.app", "workers.dev",
        "pages.dev", "github.io", "gitlab.io", "oraclecloud.com",
        "alibabacloud.com", "aliyuncs.com", "tencentcloud.com",
        "huaweicloud.com", "googleapis.com", "1e100.net",
    )),
    (CAT_APPS, (
        "spotify.com", "scdn.co", "whatsapp.com", "whatsapp.net",
        "instagram.com", "cdninstagram.com", "facebook.com", "fbcdn.net",
        "tiktok.com", "tiktokcdn.com", "bytedance.com", "byteoversea.com",
        "ibytedtos.com", "snssdk.com", "linkedin.com", "licdn.com",
        "snapchat.com", "sc-cdn.net", "telegram.org", "t.me",
        "telegram-cdn.org", "youtube.com", "ytimg.com", "googlevideo.com",
        "netflix.com", "nflxvideo.net", "twitch.tv", "ttvnw.net",
        "discord.com", "discordapp.com", "discord.gg", "twitter.com",
        "twimg.com", "x.com", "reddit.com", "redd.it", "redditmedia.com",
        "wikipedia.org", "wikimedia.org", "amazon.com", "media-amazon.com",
        "ebay.com", "paypal.com", "github.com", "githubusercontent.com",
        "gitlab.com", "steamcommunity.com", "steamstatic.com",
        "epicgames.com", "riotgames.com", "minecraft.net", "zoom.us",
        "teams.microsoft.com", "slack.com", "slack-edge.com",
        "pinterest.com", "tumblr.com", "vimeo.com", "soundcloud.com",
        "deezer.com", "tidal.com", "booking.com", "airbnb.com", "uber.com",
        "lyft.com", "dropbox.com", "box.com", "notion.so", "figma.com",
        # Broad vendor fallbacks: more specific rules above win first.
        "google.com", "withgoogle.com",
    )),
]

#: Hostname labels (or hyphen-separated parts, trailing digits ignored) that
#: mark an ad/tracking endpoint even under a vendor suffix that is otherwise
#: classified differently (``ads.mozilla.org``, ``pagead2.googlesyndication``).
AD_LABEL_TOKENS = frozenset({
    "ads", "adserver", "adservice", "adservices", "pagead", "ogads",
    "adtrafficquality", "adsrvr", "adnxs",
})
#: Tokens that only count as a whole label ("ad.example.com", not "my-ad-blocker").
AD_WHOLE_LABELS = frozenset({"ad"})

# Distinctive substrings that are useful when the exact suffix varies a lot.
SUBSTRING_RULES: List[Tuple[str, Tuple[str, ...]]] = [
    (CAT_TRACKING, ("doubleclick", "googlesyndication", "googleadservices",
                    "adservice", "scorecardresearch", "adnxs", "moatads")),
    (CAT_ANALYTICS, ("google-analytics", "googletagmanager", "hotjar",
                     "mixpanel", "amplitude", "fullstory", "bugsnag")),
    (CAT_CHATBOT, ("zendesk", "intercom", "tawk", "livechat", "freshdesk",
                   "openai", "anthropic", "dialogflow", "watson")),
    (CAT_DEVICE, ("telemetry", "crashlytics", "safebrowsing", "umeng",
                  "miui", "mioffice")),
    (CAT_UPDATES, ("windowsupdate", "update.google", "swcdn")),
    (CAT_SECURITY, ("antivirus", "vpn", "torproject")),
    (CAT_CDN, ("cloudflare", "akamai", "fastly", "cloudfront", "edgekey",
               "edgesuite", "cdn77", "jsdelivr")),
    (CAT_CLOUD, ("amazonaws", "digitalocean", "vultr", "herokuapp")),
    (CAT_APPS, ("spotify", "whatsapp", "instagram", "tiktok", "bytedance",
                "netflix", "twitch", "discord", "telegram", "wikipedia")),
]

# Common second-level labels used by public suffixes. Not a full PSL, but
# enough for grouping DNS names sensibly without an external dependency.
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "ac.uk", "gov.uk",
    "sch.uk", "nhs.uk", "police.uk", "mod.uk", "mil.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "co.in", "net.in", "org.in", "gov.in", "ac.in",
    "com.mx", "net.mx", "org.mx", "gob.mx", "edu.mx",
    "com.ar", "net.ar", "org.ar", "gob.ar",
    "co.za", "net.za", "org.za", "gov.za", "ac.za",
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw",
    "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk",
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
    "co.kr", "ne.kr", "or.kr", "go.kr", "ac.kr",
    "com.my", "net.my", "org.my", "gov.my", "edu.my",
    "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
    "com.vn", "net.vn", "org.vn", "gov.vn", "edu.vn",
    "co.id", "net.id", "or.id", "go.id", "ac.id",
    "com.pk", "net.pk", "org.pk", "gov.pk", "edu.pk",
    "com.sa", "net.sa", "org.sa", "gov.sa", "edu.sa",
    "com.eg", "net.eg", "org.eg", "gov.eg", "edu.eg",
    "com.ng", "net.ng", "org.ng", "gov.ng", "edu.ng",
    "com.co", "net.co", "org.co", "gov.co", "edu.co",
    "com.pe", "net.pe", "org.pe", "gob.pe", "edu.pe",
    "com.ve", "net.ve", "org.ve", "gob.ve", "edu.ve",
    "com.ec", "net.ec", "org.ec", "gob.ec", "edu.ec",
    "com.uy", "net.uy", "org.uy", "gub.uy", "edu.uy",
    "com.py", "net.py", "org.py", "gov.py", "edu.py",
    "com.bo", "net.bo", "org.bo", "gob.bo", "edu.bo",
    "com.do", "net.do", "org.do", "gob.do", "edu.do",
    "com.gt", "net.gt", "org.gt", "gob.gt", "edu.gt",
    "com.sv", "net.sv", "org.sv", "gob.sv", "edu.sv",
    "com.hn", "net.hn", "org.hn", "gob.hn", "edu.hn",
    "com.ni", "net.ni", "org.ni", "gob.ni", "edu.ni",
    "com.pa", "net.pa", "org.pa", "gob.pa", "edu.pa",
    "co.cr", "net.cr", "org.cr", "go.cr", "ac.cr",
    "com.ua", "net.ua", "org.ua", "gov.ua", "edu.ua",
    "com.pl", "net.pl", "org.pl", "gov.pl", "edu.pl",
    "com.ru", "net.ru", "org.ru", "gov.ru", "edu.ru",
    "co.il", "net.il", "org.il", "gov.il", "ac.il",
    "com.es", "net.es", "org.es", "gob.es", "edu.es",
    "com.pt", "net.pt", "org.pt", "gov.pt", "edu.pt",
    "com.gr", "net.gr", "org.gr", "gov.gr", "edu.gr",
}


def base_domain(domain: str) -> str:
    """Return the registrable-ish domain (``a.b.example.co.uk`` -> ``example.co.uk``)."""
    domain = (domain or "").strip(".").lower()
    if not domain:
        return ""
    labels = domain.split(".")
    if len(labels) < 3:
        return domain
    if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def subdomain_prefix(domain: str) -> str:
    """Return the part of ``domain`` that is not its base domain."""
    base = base_domain(domain)
    if not base or domain == base:
        return ""
    return domain[: -(len(base) + 1)]


def _suffix_match(domain: str, suffix: str) -> bool:
    return domain == suffix or domain.endswith("." + suffix)


def normalize_target(target: str) -> str:
    """Turn a URL/domain given to ``--target`` into a matching domain."""
    value = (target or "").strip().lower()
    if not value:
        return ""
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value)
    value = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    value = value.rsplit("@", 1)[-1]
    if value.startswith("["):  # IPv6 literal
        return ""
    value = value.split(":", 1)[0]
    return value.strip(".")


def matches_target(domain: str, target: str) -> bool:
    """True when ``domain`` is the target or a subdomain of it."""
    target = normalize_target(target)
    if not target or not domain:
        return False
    if "." in target:
        return _suffix_match(domain, target)
    return target in domain.split(".")


def _substring_match(domain: str, needle: str) -> bool:
    """Match a brand token on a label boundary.

    ``notgoogle-analytics.com`` must not be classified as Analytics just
    because it contains the token ``google-analytics``.  Tokens may start at
    the beginning of a label or after a non-alphanumeric separator, and must
    end at the label end or before such a separator.
    """
    if not needle or needle not in domain:
        return False
    for label in domain.split("."):
        start = 0
        while True:
            index = label.find(needle, start)
            if index < 0:
                break
            before = label[index - 1] if index > 0 else ""
            end = index + len(needle)
            after = label[end] if end < len(label) else ""
            if (not before or not before.isalnum()) and (not after or not after.isalnum()):
                return True
            start = index + 1
    return False


def _has_ad_label(domain: str) -> bool:
    """True when a non-TLD label names an ad/tracking endpoint."""
    labels = domain.split(".")[:-1]
    for label in labels:
        if label in AD_WHOLE_LABELS:
            return True
        for part in re.split(r"[-_]", label):
            if part.rstrip("0123456789") in AD_LABEL_TOKENS:
                return True
    return False


def classify_domain(domain: str, target: str = "") -> str:
    """Return the best category for ``domain`` (first matching rule wins)."""
    category, _ = classify_domain_detailed(domain, target)
    return category


def classify_domain_detailed(domain: str, target: str = "") -> Tuple[str, str]:
    """Return ``(category, confidence)`` where confidence is high/medium/low."""
    d = (domain or "").lower().strip(".")
    if not d:
        return CAT_OTHER, "low"
    if matches_target(d, target):
        return CAT_TARGET, "high"
    if _has_ad_label(d):
        return CAT_TRACKING, "high"
    for category, suffixes in SUFFIX_RULES:
        for suffix in suffixes:
            if _suffix_match(d, suffix):
                return category, "high"
    for category, needles in SUBSTRING_RULES:
        for needle in needles:
            if _substring_match(d, needle):
                return category, "medium"
    return CAT_OTHER, "low"


def classify_domains(domains: Iterable[str], target: str = "") -> Dict[str, List[str]]:
    """Group a list of domains by category, preserving :data:`CATEGORY_ORDER`."""
    groups: Dict[str, List[str]] = {}
    for domain in domains:
        category = classify_domain(domain, target)
        groups.setdefault(category, []).append(domain)
    return {category: groups[category] for category in CATEGORY_ORDER if category in groups}


# --------------------------------------------------------------------------
# Ports / services
# --------------------------------------------------------------------------

PORT_SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 111: "RPC", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS",
    138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    587: "SMTP submission", 636: "LDAPS", 853: "DNS over TLS",
    873: "rsync", 990: "FTPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle DB",
    1900: "SSDP", 1935: "RTMP", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 3478: "STUN/TURN", 5060: "SIP", 5061: "SIP-TLS",
    5222: "XMPP", 5353: "mDNS", 5432: "PostgreSQL", 5555: "ADB",
    6379: "Redis", 8080: "HTTP alt", 8443: "HTTPS alt",
    9000: "Tor / app", 9001: "Tor ORPort", 9030: "Tor DirPort",
    9050: "Tor SOCKS", 9150: "Tor Browser SOCKS", 11211: "Memcached",
    27017: "MongoDB", 51820: "WireGuard", 19302: "STUN",
}

CLEARTEXT_PORTS = {20, 21, 23, 25, 80, 110, 143, 389, 445, 5060, 8080}
ENCRYPTED_PORTS = {443, 465, 563, 636, 853, 990, 993, 995, 8443}
TOR_PORTS = {9000, 9001, 9030, 9050, 9150}


def port_service(port: int, proto: str = "") -> str:
    """Return a human-readable service name for a port."""
    if not port:
        return "unknown"
    name = PORT_SERVICES.get(int(port))
    if name:
        if name == "HTTPS" and proto == "udp":
            return "QUIC / HTTPS"
        return name
    return f"port {port}"


def is_cleartext_port(port: int) -> bool:
    return int(port or 0) in CLEARTEXT_PORTS
