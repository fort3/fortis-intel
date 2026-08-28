# -*- coding: utf-8 -*-
"""Country-specific visual feature database for vision geolocation.

Provides structured lookup of diagnostic visual features by country —
bollard styles, sign systems, road marking conventions, license plate
formats, power line types, and other GeoGuessr-grade clues.

Used to inject a reference table into the vision geolocation prompt so
the model can cross-check its observations against known country features.
"""

import logging
from typing import Any

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Driving side by country (comprehensive)
# ---------------------------------------------------------------------------
LEFT_DRIVING = frozenset({
    "United Kingdom", "Australia", "Japan", "India", "Thailand", "Indonesia",
    "Malaysia", "South Africa", "Kenya", "Tanzania", "Uganda", "Bangladesh",
    "Pakistan", "Sri Lanka", "Nepal", "Singapore", "Hong Kong", "Macau",
    "New Zealand", "Ireland", "Cyprus", "Malta", "Jamaica", "Trinidad and Tobago",
    "Barbados", "Bahamas", "Guyana", "Suriname", "Mozambique", "Botswana",
    "Zimbabwe", "Zambia", "Malawi", "Namibia", "Lesotho", "Eswatini",
    "Mauritius", "Seychelles", "Bhutan", "Brunei", "East Timor", "Fiji",
    "Papua New Guinea", "Solomon Islands", "Tonga", "Virgin Islands",
})

# ---------------------------------------------------------------------------
# Country visual feature database
# ---------------------------------------------------------------------------
COUNTRY_FEATURES: dict[str, dict[str, Any]] = {
    "United States": {
        "driving_side": "right",
        "sign_system": "MUTCD — green highway signs with white text, yellow warning diamonds, red octagons (STOP)",
        "road_markings": "Yellow centre line (double yellow = no passing), white lane lines, white edge lines",
        "bollards": "Flexible delineator posts (orange/white), concrete jersey barriers",
        "license_plates": "State-specific designs, rear plate required in all states, front plate varies by state",
        "power_lines": "Wooden utility poles (common), overhead transformers on poles",
        "street_lights": "Cobra head on curved steel/aluminum arms",
        "speed_units": "mph",
        "phone_format": "+1, 10-digit (3+3+4)",
        "postal_style": "Blue USPS mailboxes, flag-style residential boxes",
        "fire_hydrants": "Yellow/red/chrome, short barrel style",
        "pedestrian_signals": "White walking man / orange raised hand",
        "distinctive": "Wide multi-lane roads, strip malls, large parking lots, American flag prevalence",
    },
    "United Kingdom": {
        "driving_side": "left",
        "sign_system": "UK Traffic Signs — round speed limits with red border, triangular warnings, green A-road/blue motorway signs",
        "road_markings": "White centre dashes, double white lines = no overtaking, yellow edge lines (no parking), zigzag lines near crossings",
        "bollards": "Black and white striped cylindrical bollards, keep left/right arrows, Belisha beacons (orange globes) at crossings",
        "license_plates": "White front, yellow rear, EU-style format (AB12 CDE), blue GB/UK strip on left",
        "power_lines": "Concrete or wood poles in rural areas, underground in cities",
        "street_lights": "Swan neck cast iron (historic), modern flat LED panels",
        "speed_units": "mph",
        "phone_format": "+44",
        "postal_style": "Red Royal Mail pillar boxes (cylindrical), red post boxes on walls",
        "fire_hydrants": "Yellow H-markers on plates (underground hydrants), no visible hydrants",
        "pedestrian_signals": "Green/red standing man, puffin/pelican crossings, tactile paving at curbs",
        "distinctive": "Narrow roads, roundabouts (very common), brick terraced houses, hedgerows, red phone boxes (historic)",
    },
    "Germany": {
        "driving_side": "right",
        "sign_system": "StVO — round speed limits with red border, diamond-shaped priority signs, blue autobahn signs",
        "road_markings": "White dashed centre lines, solid white edge lines, zigzag yellow = bus stop",
        "bollards": "Red/white striped delineator posts, grey cylindrical urban bollards",
        "license_plates": "White EU format, blue EU strip left, city code prefix (e.g. M for Munich, B for Berlin)",
        "power_lines": "Steel lattice towers (Autobahn corridors), concrete poles rural",
        "street_lights": "Modern angular LED, historic lantern style in old towns",
        "speed_units": "km/h",
        "phone_format": "+49",
        "postal_style": "Yellow Deutsche Post mailboxes",
        "fire_hydrants": "Underground — marked by small red H-signs on plates",
        "pedestrian_signals": "Red/green Ampelmännchen (distinctive walking figure, especially former East Germany)",
        "distinctive": "Autobahn unrestricted sections, Ordnung (tidy streetscapes), half-timbered houses (Fachwerk), döner kebab shops",
    },
    "France": {
        "driving_side": "right",
        "sign_system": "Conforming to Vienna Convention — round speed limits red border, blue autoroute signs, green national road signs, yellow local roads",
        "road_markings": "White dashed centre, solid white edge, T-shaped lane separators on autoroutes",
        "bollards": "Red/white striped cylindrical, granite bollards in historic areas",
        "license_plates": "White EU format, blue strips both sides (left: EU flag, right: region logo)",
        "power_lines": "Concrete poles common (rural France), EDF green transformer boxes",
        "street_lights": "Ornate cast iron in Paris/cities, standard modern elsewhere",
        "speed_units": "km/h",
        "phone_format": "+33",
        "postal_style": "Yellow La Poste mailboxes",
        "fire_hydrants": "Red or yellow above-ground barrel style, less common than underground",
        "pedestrian_signals": "Red/green standing/walking figure",
        "distinctive": "Boulangeries, pharmacies with green cross sign, Haussmann architecture in Paris, shuttered windows, plane trees lining roads",
    },
    "Japan": {
        "driving_side": "left",
        "sign_system": "Diamond-shaped warning signs, blue information signs, hexagonal stop sign (止まれ), speed limits in km/h",
        "road_markings": "White centre lines, orange = no crossing, diamond shapes on road before crossings",
        "bollards": "Flexible reflective delineators, chrome/steel urban bollards",
        "license_plates": "Small white/green plates, hiragana character, regional name in kanji at top",
        "power_lines": "Dense overhead wiring (very distinctive), wooden/concrete poles with multiple transformers",
        "street_lights": "Modern LED, often on same poles as power lines",
        "speed_units": "km/h",
        "phone_format": "+81",
        "postal_style": "Red cylindrical post boxes (〒 symbol), Japan Post",
        "pedestrian_signals": "Blue/green walking figure (Japanese green is called 青/ao 'blue')",
        "distinctive": "Vending machines everywhere, kanji/hiragana/katakana signage, narrow streets, overhead wires, convenience stores (7-Eleven, FamilyMart, Lawson), temples/shrines, cherry blossoms",
    },
    "Brazil": {
        "driving_side": "right",
        "sign_system": "Round red-bordered speed limits, yellow diamond warnings, green highway signs",
        "road_markings": "Yellow centre (continuous = no passing), white lane lines and edge lines",
        "bollards": "Black/yellow striped, concrete barriers",
        "license_plates": "Mercosul format (white with blue strip, ABC1D23 format since 2018)",
        "power_lines": "Concrete poles, overhead transformer boxes, often tangled wiring in favelas",
        "street_lights": "Modern cobra head on steel poles",
        "speed_units": "km/h",
        "phone_format": "+55",
        "postal_style": "Yellow Correios mailboxes",
        "distinctive": "Tropical vegetation, colonial Portuguese architecture, favelas on hillsides, açaí shops, Portuguese-language signage",
    },
    "Russia": {
        "driving_side": "right",
        "sign_system": "GOST standards — round speed limits white with red border, blue information signs, Cyrillic text",
        "road_markings": "White dashed centre, solid white edge, yellow = no stopping zones",
        "bollards": "Black/white striped concrete posts, metal barriers",
        "license_plates": "White with black text, region code on right (2-3 digits), Russian flag",
        "power_lines": "Concrete poles (very common), steel lattice towers",
        "street_lights": "Soviet-era concrete poles, modern LED in major cities",
        "speed_units": "km/h",
        "phone_format": "+7",
        "postal_style": "Blue Pochta Rossii (Почта России) mailboxes",
        "distinctive": "Cyrillic signage, wide boulevards, Soviet apartment blocks (khrushchyovka), onion-dome churches, Lada/UAZ vehicles",
    },
    "India": {
        "driving_side": "left",
        "sign_system": "IRC standards — yellow diamond warnings, round speed limits, km/h, signs in Hindi + English + regional language",
        "road_markings": "White/yellow centre lines (often faded or absent), speed bumps marked in yellow/black",
        "bollards": "Black/yellow or red/white concrete, stone bollards",
        "license_plates": "White (private) or yellow (commercial), state code prefix (e.g. MH, DL, KA)",
        "power_lines": "Chaotic overhead wiring, concrete poles, visible transformers",
        "street_lights": "Concrete/steel poles, sodium vapour common, LED in newer areas",
        "speed_units": "km/h",
        "phone_format": "+91",
        "postal_style": "Red India Post mailboxes",
        "distinctive": "Auto-rickshaws, dense traffic mixing cars/bikes/trucks/cows, Hindi/regional script signs, bright colours on buildings/trucks, temples",
    },
    "China": {
        "driving_side": "right",
        "sign_system": "GB standards — blue information signs, green expressway signs, simplified Chinese characters, km/h",
        "road_markings": "White dashed centre, yellow solid = no crossing, white crosshatch at intersections",
        "bollards": "Steel/concrete, black/yellow striped",
        "license_plates": "Blue plates with white Chinese character (province code) + alphanumeric, green plates for electric vehicles",
        "power_lines": "High-voltage steel lattice towers, concrete poles locally",
        "street_lights": "Modern LED panels on tall poles, red lantern-style in tourist areas",
        "speed_units": "km/h",
        "phone_format": "+86",
        "postal_style": "Green China Post mailboxes (中国邮政)",
        "distinctive": "Simplified Chinese signage, high-rise apartment blocks, electric scooters, surveillance cameras, distinctive green highway signs",
    },
    "Australia": {
        "driving_side": "left",
        "sign_system": "AS standards — white speed limit circles with red border, yellow diamond warnings, green highway signs, km/h",
        "road_markings": "White dashed centre, white edge lines, yellow = no standing",
        "bollards": "Flexible red/white delineators, steel urban bollards",
        "license_plates": "State-specific colours and slogans, alphanumeric format varies by state",
        "power_lines": "Wooden poles common (bush/suburban), underground in newer suburbs",
        "street_lights": "Modern curved-arm LED, tall aluminium poles",
        "speed_units": "km/h",
        "phone_format": "+61",
        "postal_style": "Red Australia Post mailboxes (bright red, rectangular)",
        "distinctive": "Wide open landscapes, eucalyptus trees, kangaroo/koala warning signs, distinctive dry brown terrain, tin-roofed houses",
    },
    "South Korea": {
        "driving_side": "right",
        "sign_system": "Blue information signs, green expressway signs, round speed limits, Korean Hangul text, km/h",
        "road_markings": "White dashed centre, yellow solid = no parking, blue = bus lanes",
        "bollards": "Orange flexible delineators, steel urban bollards",
        "license_plates": "White/green/yellow based on vehicle type, Hangul text, 2-digit region code",
        "power_lines": "Concrete/steel poles, moving to underground",
        "street_lights": "Modern LED on steel poles",
        "speed_units": "km/h",
        "phone_format": "+82",
        "postal_style": "Red/orange Korea Post mailboxes",
        "distinctive": "Hangul (한글) signage, PC bangs, fried chicken shops, apartment complexes (아파트), Korean churches with red neon crosses",
    },
    "Mexico": {
        "driving_side": "right",
        "sign_system": "Similar to MUTCD — green highway signs with white text, yellow diamond warnings, octagonal ALTO signs, km/h",
        "road_markings": "Yellow centre line, white edge lines, topes (speed bumps) painted yellow",
        "bollards": "Black/yellow concrete, metal barriers",
        "license_plates": "State-specific designs, rear required, multiple colour schemes",
        "power_lines": "Concrete poles, overhead transformers, sometimes tangled",
        "street_lights": "Cobra head on concrete/steel poles, colonial lanterns in centro histórico",
        "speed_units": "km/h",
        "phone_format": "+52",
        "postal_style": "Red Correos de México mailboxes",
        "distinctive": "Colourful buildings, Spanish-language signs, taco/torta street vendors, OXXO convenience stores, speed bumps (topes)",
    },
    "Italy": {
        "driving_side": "right",
        "sign_system": "Vienna Convention — round speed limits red border, green autostrada signs, blue SS/SP road signs",
        "road_markings": "White dashed centre, solid white edge, blue zone parking markings",
        "bollards": "Stone/concrete in historic centres, red/white striped delineators",
        "license_plates": "White EU format, blue strips both sides, two-letter province code (legacy) or progressive format",
        "power_lines": "Concrete poles rural, underground in cities, ENEL green transformer boxes",
        "street_lights": "Ornate cast iron in historic areas, modern LED elsewhere",
        "speed_units": "km/h",
        "phone_format": "+39",
        "postal_style": "Red Poste Italiane mailboxes",
        "distinctive": "Terracotta/ochre buildings, Roman ruins, Vespa scooters, gelaterias, espresso bars, narrow cobblestone streets",
    },
    "Netherlands": {
        "driving_side": "right",
        "sign_system": "Round speed limits red border, blue motorway signs, ANWB mushroom-shaped direction signs",
        "road_markings": "White dashed centre, thick white edge lines, separate red-surfaced cycle paths",
        "bollards": "Amsterdam-style cast iron (3-cross design), red/white delineators",
        "license_plates": "Yellow (rear), white (front — pre-2023 all yellow), EU format, sidecode format (XX-999-X)",
        "power_lines": "Generally underground, overhead in rural polder areas",
        "street_lights": "Modern design, often integrated with cycle path lighting",
        "speed_units": "km/h",
        "phone_format": "+31",
        "postal_style": "Orange PostNL mailboxes",
        "distinctive": "Flat terrain, canals, brick architecture, extensive cycle paths (red surface), windmills, tulip fields",
    },
    "Turkey": {
        "driving_side": "right",
        "sign_system": "Vienna Convention — round speed limits red border, green motorway signs, Turkish text",
        "road_markings": "White dashed centre, yellow edge lines, concrete median barriers on highways",
        "bollards": "Red/white striped, concrete barriers",
        "license_plates": "White with blue TR strip left, two-digit city code (34 = Istanbul, 06 = Ankara)",
        "power_lines": "Concrete poles, steel lattice towers",
        "street_lights": "Modern LED, Ottoman-style lanterns in tourist areas",
        "speed_units": "km/h",
        "phone_format": "+90",
        "postal_style": "Yellow PTT mailboxes",
        "distinctive": "Mosques with minarets, Turkish script (Latin with ç, ğ, ı, ö, ş, ü), tea gardens, kebab shops, stray cats",
    },
    "Nigeria": {
        "driving_side": "right",
        "sign_system": "Based on UK/SADC standards — triangular warnings, round speed limits, km/h, English text",
        "road_markings": "White/yellow where present (often faded or absent)",
        "bollards": "Concrete barriers, painted kerbs yellow/black",
        "license_plates": "White with green text, state code prefix (e.g. LA = Lagos, AB = Abuja)",
        "power_lines": "Concrete/wooden poles, overhead transformers, visible generator infrastructure",
        "street_lights": "Where functional — concrete/steel poles, many non-operational",
        "speed_units": "km/h",
        "phone_format": "+234",
        "postal_style": "Green NIPOST mailboxes",
        "distinctive": "Yellow danfo buses (Lagos), generators outside buildings, commercial motorbikes (okada), vibrant market scenes, concrete block buildings",
    },
    "South Africa": {
        "driving_side": "left",
        "sign_system": "SADC standards — round speed limits blue circle, triangular warnings, green national road signs, km/h",
        "road_markings": "Yellow centre no-passing lines, white lane markings",
        "bollards": "Red/white delineators, concrete barriers",
        "license_plates": "White with embossed text, province code (GP = Gauteng, WC = Western Cape)",
        "power_lines": "Concrete/steel poles, Eskom infrastructure",
        "street_lights": "Modern LED on steel poles, cobra head style",
        "speed_units": "km/h",
        "phone_format": "+27",
        "postal_style": "Red SA Post Office boxes",
        "distinctive": "Braai culture, diverse architecture (from Cape Dutch to township), security walls with electric fencing, blue-gum eucalyptus, minibus taxis",
    },
    "Spain": {
        "driving_side": "right",
        "sign_system": "Vienna Convention — round speed limits red border, blue autopista signs, green national road signs",
        "road_markings": "White dashed centre, continuous white = no overtaking, blue zone parking",
        "bollards": "Metal bollards in pedestrian zones, red/white delineators",
        "license_plates": "White EU format, blue EU strip left, no region identifier (since 2000)",
        "power_lines": "Concrete poles rural, underground in cities",
        "street_lights": "Ornate in historic centres, modern elsewhere",
        "speed_units": "km/h",
        "phone_format": "+34",
        "postal_style": "Yellow Correos mailboxes",
        "distinctive": "Terracotta roofs, whitewashed buildings (Andalusia), balconies with wrought iron, tapas bars, bull warning signs on rural roads",
    },
    "Canada": {
        "driving_side": "right",
        "sign_system": "Similar to MUTCD but bilingual (English/French in some provinces), green highway signs, km/h, diamond-shaped warnings",
        "road_markings": "Yellow centre line, white lane lines (similar to US)",
        "bollards": "Flexible orange delineators, concrete barriers",
        "license_plates": "Province-specific designs and slogans, bilingual in some provinces",
        "power_lines": "Wooden utility poles common (similar to US)",
        "street_lights": "Modern cobra head, LED in urban areas",
        "speed_units": "km/h",
        "phone_format": "+1",
        "postal_style": "Red Canada Post community mailboxes, standalone red boxes",
        "distinctive": "Bilingual signs (French/English) in Quebec/federal areas, Tim Hortons, wide roads, metric speed limits (unlike US), LCBO/SAQ (liquor stores)",
    },
    "Egypt": {
        "driving_side": "right",
        "sign_system": "Vienna Convention style — round speed limits, Arabic + English/French text, km/h",
        "road_markings": "White/yellow where present, often faded in rural areas",
        "bollards": "Concrete barriers, painted kerbs",
        "license_plates": "White with Arabic numerals + Latin numerals, blue strip left",
        "power_lines": "Concrete poles, overhead transformers",
        "street_lights": "Concrete/steel poles, sodium vapour common",
        "speed_units": "km/h",
        "phone_format": "+20",
        "postal_style": "Green Egypt Post mailboxes",
        "distinctive": "Arabic signage, desert/arid landscape, Nile delta green, minarets, satellite dishes on rooftops, microbus taxis",
    },
    "Poland": {
        "driving_side": "right",
        "sign_system": "Vienna Convention — round speed limits red border, green/blue motorway signs, Polish text",
        "road_markings": "White dashed centre, solid white edge, yellow = no parking",
        "bollards": "Red/white striped delineators, concrete barriers",
        "license_plates": "White EU format, blue EU strip, 2-3 letter region code (e.g. WA = Warszawa)",
        "power_lines": "Concrete poles common, steel lattice rural",
        "street_lights": "Soviet-era concrete poles still common, modern LED in cities",
        "speed_units": "km/h",
        "phone_format": "+48",
        "postal_style": "Red Poczta Polska mailboxes",
        "distinctive": "Żabka convenience stores (green frog logo), Biedronka supermarkets, Polish diacritics (ą, ć, ę, ł, ń, ó, ś, ź, ż), Catholic churches",
    },
    "Thailand": {
        "driving_side": "left",
        "sign_system": "International style — round speed limits, Thai script + English on major roads, km/h",
        "road_markings": "White/yellow centre lines, raised reflective road markers",
        "bollards": "Concrete barriers, red/white delineators",
        "license_plates": "White with red/blue/green text, Thai script province name, Thai numerals optional",
        "power_lines": "Concrete poles, chaotic overhead wiring in cities",
        "street_lights": "Modern on main roads, less consistent in rural areas",
        "speed_units": "km/h",
        "phone_format": "+66",
        "postal_style": "Red Thailand Post mailboxes",
        "distinctive": "Thai script (ภาษาไทย), Buddhist temples (wat), tuk-tuks, 7-Eleven stores (very dense), spirit houses, tropical vegetation",
    },
    "Indonesia": {
        "driving_side": "left",
        "sign_system": "International style — triangular warnings, round speed limits, Bahasa Indonesia text, km/h",
        "road_markings": "White/yellow where present, often minimal on local roads",
        "bollards": "Concrete/painted steel, black/yellow",
        "license_plates": "Black with white text, region code (B = Jakarta, D = Bandung, L = Surabaya)",
        "power_lines": "Concrete poles, PLN infrastructure",
        "street_lights": "Concrete poles, LED in urban areas",
        "speed_units": "km/h",
        "phone_format": "+62",
        "postal_style": "Orange Pos Indonesia mailboxes",
        "distinctive": "Bahasa Indonesia signage, motorcycles (extremely prevalent), mosques, warung (small food stalls), batik patterns, lush tropical vegetation",
    },
    "Argentina": {
        "driving_side": "right",
        "sign_system": "Vienna Convention — round speed limits red border, green autopista signs, Spanish text, km/h",
        "road_markings": "Yellow centre, white edge lines",
        "bollards": "Concrete barriers, yellow/black striped",
        "license_plates": "Mercosul format (white, blue strip, AA 000 AA format)",
        "power_lines": "Wooden/concrete poles, overhead transformers",
        "street_lights": "Modern LED in cities, sodium vapour elsewhere",
        "speed_units": "km/h",
        "phone_format": "+54",
        "postal_style": "Blue Correo Argentino mailboxes",
        "distinctive": "Wide avenues (Buenos Aires), Spanish-language signs, parrillas (grill restaurants), mate culture, Pampas grasslands",
    },
    "Sweden": {
        "driving_side": "right",
        "sign_system": "Scandinavian style — round speed limits red border, blue motorway signs, Swedish/English text",
        "road_markings": "White dashed centre, solid edge, 2+1 roads with cable barriers",
        "bollards": "Grey/reflective delineators, steel urban bollards",
        "license_plates": "White EU format, blue S strip, ABC 12D format (since 2019)",
        "power_lines": "Mostly underground in urban, wooden poles rural",
        "street_lights": "Modern LED, cobra head style",
        "speed_units": "km/h",
        "phone_format": "+46",
        "postal_style": "Yellow PostNord mailboxes",
        "distinctive": "Red wooden houses (Falu red/rödfärg), IKEA, Volvo/Scania vehicles, birch forests, moose warning signs, å/ä/ö characters",
    },
    "Philippines": {
        "driving_side": "right",
        "sign_system": "MUTCD-influenced — green highway signs, yellow warning diamonds, English/Filipino text, km/h",
        "road_markings": "Yellow centre, white lanes (where present)",
        "bollards": "Concrete barriers, painted kerbs",
        "license_plates": "White with coloured text, 3-letter + 4-digit format",
        "power_lines": "Concrete/wooden poles, dense overhead wiring in cities",
        "street_lights": "Concrete poles, LED in major roads",
        "speed_units": "km/h",
        "phone_format": "+63",
        "postal_style": "Red/white PhilPost mailboxes",
        "distinctive": "Jeepneys (colourful modified jeeps), tricycles, English + Filipino signage, sari-sari stores, dense tropical vegetation, concrete block houses",
    },
    "Colombia": {
        "driving_side": "right",
        "sign_system": "MUTCD-influenced — green highway signs, yellow diamond warnings, PARE (stop) signs, km/h",
        "road_markings": "Yellow centre, white lanes",
        "license_plates": "Yellow with black text, 3-letter + 3-digit format",
        "power_lines": "Concrete/wooden poles, overhead transformers",
        "speed_units": "km/h",
        "phone_format": "+57",
        "distinctive": "Spanish-language signage, mountainous terrain (Andes), colonial architecture in old towns, colourful houses, emerald green vegetation",
    },
    "Vietnam": {
        "driving_side": "right",
        "sign_system": "Vietnamese standard — round blue mandatory signs, triangular warnings, Vietnamese text, km/h",
        "road_markings": "White/yellow where present, often minimal",
        "license_plates": "White with black text (personal) or yellow (commercial), province code prefix",
        "power_lines": "Concrete poles, dense overhead wiring",
        "speed_units": "km/h",
        "phone_format": "+84",
        "distinctive": "Vietnamese script (Latin with extensive diacritics: ă, â, đ, ê, ô, ơ, ư), motorbike dominance, phở shops, narrow tube houses, communist-era signage",
    },
    "Kenya": {
        "driving_side": "left",
        "sign_system": "British-influenced — triangular warnings, round speed limits, English/Swahili text",
        "road_markings": "White centre, yellow = no overtaking",
        "license_plates": "White front, yellow rear, KAA-KZZ format",
        "power_lines": "Concrete/wooden poles, KPLC infrastructure",
        "speed_units": "km/h",
        "phone_format": "+254",
        "distinctive": "Matatu (decorated minibuses), M-Pesa signs, Swahili signage, red laterite soil, acacia trees, Great Rift Valley landscape",
    },
    "UAE": {
        "driving_side": "right",
        "sign_system": "International style — round speed limits, Arabic + English text, green highway signs, km/h",
        "road_markings": "White lanes, yellow median",
        "license_plates": "Various emirate-specific designs, Arabic + Latin text",
        "speed_units": "km/h",
        "phone_format": "+971",
        "distinctive": "Modern skyscrapers (Dubai/Abu Dhabi), Arabic + English bilingual signs, desert landscape, luxury vehicles, mosque architecture, date palms",
    },
    "Greece": {
        "driving_side": "right",
        "sign_system": "Vienna Convention — round speed limits red border, blue motorway signs, Greek + Latin text",
        "road_markings": "White dashed centre, solid white = no passing",
        "license_plates": "White EU format, blue GR strip, ABC-1234 format",
        "speed_units": "km/h",
        "phone_format": "+30",
        "postal_style": "Yellow ELTA (ΕΛΤΑ) mailboxes",
        "distinctive": "Greek alphabet signage (Ελληνικά), white/blue buildings (islands), Orthodox churches with domes, olive trees, dry Mediterranean landscape",
    },
    "Norway": {
        "driving_side": "right",
        "sign_system": "Scandinavian style — round speed limits red border, blue motorway signs, Norwegian text",
        "road_markings": "White dashed centre, solid yellow edge",
        "license_plates": "White EU format, blue N strip, AB 12345 format",
        "speed_units": "km/h",
        "phone_format": "+47",
        "postal_style": "Red Posten mailboxes",
        "distinctive": "Fjords, wooden stave churches, red/brown wooden houses, tunnel entrances, Norwegian text (æ/ø/å), Tesla density, salmon farming infrastructure",
    },
}


def get_country_features(country_name: str) -> dict[str, Any] | None:
    """Look up visual features for a country by name."""
    if not country_name:
        return None
    key = country_name.strip()
    if key in COUNTRY_FEATURES:
        return COUNTRY_FEATURES[key]
    for k, v in COUNTRY_FEATURES.items():
        if k.lower() == key.lower():
            return v
    return None


def get_driving_side(country_name: str) -> str:
    """Return 'left' or 'right' driving side for a country."""
    if not country_name:
        return "unknown"
    features = get_country_features(country_name)
    if features:
        return features.get("driving_side", "unknown")
    if country_name.strip() in LEFT_DRIVING:
        return "left"
    return "right"


def build_feature_reference(observations: dict[str, Any] | None = None) -> str:
    """Build a compact feature reference table for the vision model.

    If observations are provided, only includes countries that could
    match the observed driving side and other strong signals. Otherwise
    returns the top ~15 most common countries.
    """
    candidates = list(COUNTRY_FEATURES.keys())

    if observations:
        infra = observations.get("infrastructure", {})
        driving_side = infra.get("driving_side", "").lower()
        if driving_side in ("left", "right"):
            candidates = [
                c for c in candidates
                if COUNTRY_FEATURES[c].get("driving_side") == driving_side
            ]

    if len(candidates) > 18:
        priority = [
            "United States", "United Kingdom", "Germany", "France",
            "Japan", "Brazil", "Russia", "India", "China", "Australia",
            "South Korea", "Mexico", "Italy", "Netherlands", "Turkey",
            "Nigeria", "South Africa", "Spain",
        ]
        ordered = [c for c in priority if c in candidates]
        for c in candidates:
            if c not in ordered:
                ordered.append(c)
        candidates = ordered[:18]

    lines = ["COUNTRY VISUAL FEATURE REFERENCE (use to cross-check your observations):"]
    lines.append("")

    for country in candidates:
        feat = COUNTRY_FEATURES[country]
        parts = [f"**{country}** (drives {feat.get('driving_side', '?')})"]
        if feat.get("sign_system"):
            parts.append(f"  Signs: {feat['sign_system']}")
        if feat.get("road_markings"):
            parts.append(f"  Road markings: {feat['road_markings']}")
        if feat.get("bollards"):
            parts.append(f"  Bollards: {feat['bollards']}")
        if feat.get("license_plates"):
            parts.append(f"  Plates: {feat['license_plates']}")
        if feat.get("distinctive"):
            parts.append(f"  Distinctive: {feat['distinctive']}")
        lines.append("\n".join(parts))
        lines.append("")

    return "\n".join(lines)


def build_focused_reference(country_names: list[str]) -> str:
    """Build a detailed feature reference for specific candidate countries."""
    if not country_names:
        return ""

    lines = ["DETAILED FEATURES FOR CANDIDATE COUNTRIES:"]
    lines.append("")

    for name in country_names[:5]:
        feat = get_country_features(name)
        if not feat:
            continue
        lines.append(f"**{name}**:")
        for key, value in feat.items():
            if value and key != "driving_side":
                label = key.replace("_", " ").title()
                lines.append(f"  {label}: {value}")
        lines.append("")

    return "\n".join(lines)
