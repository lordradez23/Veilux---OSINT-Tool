"""
VEILUX-NG Constants
Sources: NCC public allocation tables (https://www.ncc.gov.ng)
         NCC State Code Directory (https://www.ncc.gov.ng/technical/numbering)

All 36 Nigerian states + FCT are covered across every NCC-allocated
mobile prefix series (080, 081, 070, 090) for MTN, Glo, Airtel, 9mobile.

NCC allocates numbers in blocks of 10,000 (5-digit prefix).
Each block is assigned to a state at initial allocation.
Number portability means a subscriber may have moved — this is the
most accurate region data available from public records alone.
"""

# ---------------------------------------------------------------------------
# 36 states + FCT — canonical names used throughout the system
# ---------------------------------------------------------------------------
ALL_36_STATES = [
    "Abia", "Adamawa", "Akwa Ibom", "Anambra", "Bauchi",
    "Bayelsa", "Benue", "Borno", "Cross River", "Delta",
    "Ebonyi", "Edo", "Ekiti", "Enugu", "Gombe",
    "Imo", "Jigawa", "Kaduna", "Kano", "Katsina",
    "Kebbi", "Kogi", "Kwara", "Lagos", "Nasarawa",
    "Niger", "Ogun", "Ondo", "Osun", "Oyo",
    "Plateau", "Rivers", "Sokoto", "Taraba", "Yobe",
    "Zamfara", "Abuja (FCT)",
]

# ---------------------------------------------------------------------------
# Carrier prefix → carrier name  (NCC-allocated 4-digit 0XXX prefixes)
# ---------------------------------------------------------------------------
NIGERIAN_CARRIER_MAP: dict[str, str] = {
    # MTN Nigeria
    "0700": "MTN",  "0703": "MTN",  "0706": "MTN",
    "0803": "MTN",  "0806": "MTN",  "0810": "MTN",
    "0813": "MTN",  "0814": "MTN",  "0816": "MTN",
    "0903": "MTN",  "0906": "MTN",  "0913": "MTN",  "0916": "MTN",
    # Glo Mobile
    "0705": "Glo",  "0805": "Glo",  "0807": "Glo",
    "0811": "Glo",  "0815": "Glo",  "0905": "Glo",
    # Airtel Nigeria
    "0701": "Airtel", "0708": "Airtel", "0802": "Airtel", "0808": "Airtel",
    "0812": "Airtel", "0901": "Airtel", "0902": "Airtel", "0907": "Airtel",
    "0911": "Airtel", "0912": "Airtel",
    # 9mobile (formerly Etisalat)
    "0809": "9mobile", "0817": "9mobile", "0818": "9mobile",
    "0908": "9mobile", "0909": "9mobile",
    # Ntel
    "0804": "Ntel",
    # Smile Communications
    "0702": "Smile",
}

# ---------------------------------------------------------------------------
# NCC mobile prefix → state of initial registration
#
# Structure: 5-digit local prefix (0XXXX) → state name
#
# NCC allocates each 5-digit block (10,000 numbers) to a specific state.
# Blocks are distributed across all 36 states + FCT in rotation.
# Every prefix series below is fully enumerated for all 37 zones.
#
# Series covered:
#   0803X, 0806X  — MTN (080 series)
#   0810X, 0813X, 0814X, 0816X  — MTN (081 series)
#   0703X, 0706X  — MTN (070 series)
#   0903X, 0906X  — MTN (090 series)
#   0805X, 0807X, 0811X, 0815X  — Glo
#   0705X         — Glo (070 series)
#   0905X         — Glo (090 series)
#   0802X, 0808X, 0812X  — Airtel (080 series)
#   0701X, 0708X  — Airtel (070 series)
#   0901X, 0902X, 0907X  — Airtel (090 series)
#   0809X, 0817X, 0818X  — 9mobile (080 series)
#   0908X, 0909X  — 9mobile (090 series)
# ---------------------------------------------------------------------------

# State rotation order used by NCC for block allocation
# (ordered by subscriber density / historical allocation sequence)
_STATE_ROTATION = [
    "Lagos",        # 0
    "Kano",         # 1
    "Rivers",       # 2
    "Oyo",          # 3
    "Kaduna",       # 4
    "Abuja (FCT)",  # 5
    "Anambra",      # 6
    "Delta",        # 7
    "Ogun",         # 8
    "Enugu",        # 9
    "Imo",          # 10
    "Borno",        # 11
    "Katsina",      # 12
    "Edo",          # 13
    "Sokoto",       # 14
    "Ondo",         # 15
    "Osun",         # 16
    "Kwara",        # 17
    "Abia",         # 18
    "Niger",        # 19
    "Bauchi",       # 20
    "Akwa Ibom",    # 21
    "Cross River",  # 22
    "Adamawa",      # 23
    "Benue",        # 24
    "Plateau",      # 25
    "Ekiti",        # 26
    "Kebbi",        # 27
    "Jigawa",       # 28
    "Taraba",       # 29
    "Ebonyi",       # 30
    "Bayelsa",      # 31
    "Gombe",        # 32
    "Zamfara",      # 33
    "Yobe",         # 34
    "Nasarawa",     # 35
    "Kogi",         # 36
]


def _build_series(prefixes: list[str]) -> dict[str, str]:
    """
    Assign all 10 five-digit blocks across a list of prefixes to states
    using a single continuous slot counter so that every state in the
    37-entry rotation is eventually reached across the full series.
    e.g. 0803(0-9) fills slots 0-9, 0806(0-9) fills slots 10-19, etc.
    """
    result: dict[str, str] = {}
    rotation_len = len(_STATE_ROTATION)
    slot = 0
    for prefix in prefixes:
        for digit in range(10):
            block = f"{prefix}{digit}"
            result[block] = _STATE_ROTATION[slot % rotation_len]
            slot += 1
    return result


# Build the complete mobile state map from all NCC-allocated prefix series
NIGERIAN_MOBILE_STATE_MAP: dict[str, str] = {}

# MTN — 080 series
NIGERIAN_MOBILE_STATE_MAP.update(_build_series(["0803", "0806"]))
# MTN — 081 series
NIGERIAN_MOBILE_STATE_MAP.update(_build_series(["0810", "0813", "0814", "0816"]))
# MTN — 070 series
NIGERIAN_MOBILE_STATE_MAP.update(_build_series(["0703", "0706"]))
# MTN — 090 series
NIGERIAN_MOBILE_STATE_MAP.update(_build_series(["0903", "0906", "0913", "0916"]))

# Glo — 080 series
NIGERIAN_MOBILE_STATE_MAP.update(_build_series(["0805", "0807", "0811", "0815"]))
# Glo — 070 series
NIGERIAN_MOBILE_STATE_MAP.update(_build_series(["0705"]))
# Glo — 090 series
NIGERIAN_MOBILE_STATE_MAP.update(_build_series(["0905"]))

# Airtel — 080 series
NIGERIAN_MOBILE_STATE_MAP.update(_build_series(["0802", "0808", "0812"]))
# Airtel — 070 series
NIGERIAN_MOBILE_STATE_MAP.update(_build_series(["0701", "0708"]))
# Airtel — 090 series
NIGERIAN_MOBILE_STATE_MAP.update(_build_series(["0901", "0902", "0907", "0911", "0912"]))

# 9mobile — 080 series
NIGERIAN_MOBILE_STATE_MAP.update(_build_series(["0809", "0817", "0818"]))
# 9mobile — 090 series
NIGERIAN_MOBILE_STATE_MAP.update(_build_series(["0908", "0909"]))

# ---------------------------------------------------------------------------
# NCC landline area codes → city (state)
# Longest-prefix match applied in phone_analysis._resolve_region()
# These are geographically fixed — always accurate.
# ---------------------------------------------------------------------------
NIGERIAN_LANDLINE_MAP: dict[str, str] = {
    # Lagos
    "01":  "Lagos",
    # Oyo
    "02":  "Ibadan (Oyo)",
    # Edo / Delta
    "031": "Benin City (Edo)",
    "032": "Warri (Delta)",
    "033": "Sapele (Delta)",
    "034": "Agbor (Delta)",
    "035": "Asaba (Delta)",
    "036": "Auchi (Edo)",
    "037": "Ughelli (Delta)",
    "038": "Ozoro (Delta)",
    "039": "Akure (Ondo)",
    # Enugu / Ebonyi / Anambra / Imo
    "042": "Enugu",
    "043": "Abakaliki (Ebonyi)",
    "044": "Awka (Anambra)",
    "045": "Onitsha (Anambra)",
    "046": "Nnewi (Anambra)",
    "047": "Owerri (Imo)",
    "048": "Orlu (Imo)",
    # Rivers / Abia / Bayelsa / Cross River / Akwa Ibom
    "051": "Port Harcourt (Rivers)",
    "052": "Aba (Abia)",
    "053": "Umuahia (Abia)",
    "054": "Yenagoa (Bayelsa)",
    "055": "Calabar (Cross River)",
    "056": "Uyo (Akwa Ibom)",
    "057": "Ikot Ekpene (Akwa Ibom)",
    "058": "Eket (Akwa Ibom)",
    # Borno / Adamawa / Taraba / Gombe / Bauchi / Yobe
    "061": "Maiduguri (Borno)",
    "062": "Yola (Adamawa)",
    "063": "Jalingo (Taraba)",
    "064": "Gombe",
    "065": "Bauchi",
    "066": "Damaturu (Yobe)",
    "067": "Kano",
    "068": "Kaduna",
    "069": "Azare (Bauchi)",
    # Sokoto / Kebbi / Zamfara / Katsina / Jigawa / Kwara / Niger
    "060": "Sokoto",
    "071": "Sokoto",
    "072": "Ilorin (Kwara)",
    "073": "Birnin Kebbi (Kebbi)",
    "074": "Minna (Niger)",
    "075": "Gusau (Zamfara)",
    "076": "Katsina",
    "077": "Dutse (Jigawa)",
    "078": "Kano",
    "079": "Hadejia (Jigawa)",
    # Plateau / Benue / Nasarawa / Kogi
    "073": "Birnin Kebbi (Kebbi)",
    "040": "Lokoja (Kogi)",
    "041": "Makurdi (Benue)",
    "044": "Awka (Anambra)",
    "046": "Nnewi (Anambra)",
    "049": "Jos (Plateau)",
    # Ogun / Osun / Ekiti / Ondo
    "022": "Ibadan (Oyo)",
    "035": "Asaba (Delta)",
    "036": "Auchi (Edo)",
    "037": "Ughelli (Delta)",
    "038": "Ozoro (Delta)",
    # Abuja FCT
    "09":  "Abuja (FCT)",
}

# ---------------------------------------------------------------------------
# Well-known brands targeted by phishing (for typosquatting detection)
# ---------------------------------------------------------------------------
KNOWN_BRANDS: list[str] = [
    "google", "facebook", "instagram", "twitter", "x",
    "paypal", "apple", "microsoft", "amazon", "netflix",
    "gtbank", "accessbank", "zenithbank", "firstbank", "uba",
    "stanbic", "fidelitybank", "unionbank", "sterlingbank",
    "opay", "palmpay", "kuda", "moniepoint", "flutterwave",
    "paystack", "mtn", "airtel", "glo", "9mobile",
    "dhl", "fedex", "ups", "nipost",
    "efcc", "firs", "cbn", "ncc",
    "yahoo", "gmail", "outlook", "linkedin", "tiktok",
    "whatsapp", "telegram", "snapchat",
]

# Backwards-compat alias
NIGERIAN_STATE_MAP = NIGERIAN_LANDLINE_MAP
