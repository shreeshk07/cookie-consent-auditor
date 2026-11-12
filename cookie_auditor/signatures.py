"""Known cookie and tracker signatures.

Each cookie signature is (regex on cookie name, vendor, category).
Patterns are matched case insensitively against the full cookie name.

Each domain signature is (domain suffix, vendor, category). A host matches when it
equals the suffix or ends with "." + suffix.

Extend these lists with --signatures path/to/custom.json (see README).
"""

from __future__ import annotations

from .models import ADVERTISING, ANALYTICS, ESSENTIAL, FUNCTIONAL, SOCIAL

# ---------------------------------------------------------------------------
# Essential cookies (strictly necessary: sessions, security, load balancing,
# and the consent cookies themselves). These never raise a finding.
# ---------------------------------------------------------------------------
ESSENTIAL_COOKIE_SIGNATURES = [
    (r"PHPSESSID", "PHP", ESSENTIAL),
    (r"JSESSIONID", "Java servlet", ESSENTIAL),
    (r"ASP\.NET_SessionId", "ASP.NET", ESSENTIAL),
    (r"ASPSESSIONID.*", "Classic ASP", ESSENTIAL),
    (r"\.AspNetCore\..*", "ASP.NET Core", ESSENTIAL),
    (r"connect\.sid", "Express", ESSENTIAL),
    (r"laravel_session", "Laravel", ESSENTIAL),
    (r"(_?)session(_?id)?", "Session", ESSENTIAL),
    (r"sess(ion)?[-_]?id", "Session", ESSENTIAL),
    (r"csrf.*|.*[-_]csrf[-_]?token|XSRF-TOKEN|_csrf", "CSRF protection", ESSENTIAL),
    (r"__Host-.*", "Host-prefixed cookie", ESSENTIAL),
    (r"cf_clearance|__cf_bm|__cfduid|__cflb|_cfuvid", "Cloudflare", ESSENTIAL),
    (r"AWSALB.*|AWSELB.*|AWSALBCORS", "AWS load balancer", ESSENTIAL),
    (r"ARRAffinity.*", "Azure App Service affinity", ESSENTIAL),
    (r"BIGipServer.*|TS[0-9a-f]{8,}", "F5 load balancer", ESSENTIAL),
    (r"incap_ses_.*|visid_incap_.*|nlbi_.*", "Imperva security", ESSENTIAL),
    (r"_GRECAPTCHA", "reCAPTCHA", ESSENTIAL),
    (r"wordpress_test_cookie|wordpress_logged_in_.*|wordpress_sec_.*", "WordPress", ESSENTIAL),
    (r"wp_woocommerce_session_.*|woocommerce_cart_hash|woocommerce_items_in_cart", "WooCommerce", ESSENTIAL),
    (r"PrestaShop-.*", "PrestaShop", ESSENTIAL),
    (r"form_key|mage-cache-sessid|mage-cache-storage.*", "Magento", ESSENTIAL),
    # Consent management platforms: the cookie that stores the choice itself.
    (r"CookieConsent", "Cookiebot", ESSENTIAL),
    (r"OptanonConsent|OptanonAlertBoxClosed", "OneTrust", ESSENTIAL),
    (r"euconsent-v2|eupubconsent-v2|__cmpconsent.*|__cmpcccx.*", "IAB TCF", ESSENTIAL),
    (r"cookieyes-consent", "CookieYes", ESSENTIAL),
    (r"cmplz_.*", "Complianz", ESSENTIAL),
    (r"cookie_notice_accepted", "Cookie Notice", ESSENTIAL),
    (r"CookieScriptConsent", "CookieScript", ESSENTIAL),
    (r"borlabs-cookie", "Borlabs", ESSENTIAL),
    (r"viewed_cookie_policy|cookielawinfo-.*", "Cookie Law Info", ESSENTIAL),
    (r"moove_gdpr_popup", "GDPR Cookie Compliance", ESSENTIAL),
    (r"didomi_token|euconsent", "Didomi", ESSENTIAL),
    (r"usercentrics.*|uc_user_interaction|uc_settings", "Usercentrics", ESSENTIAL),
    (r"osano_consentmanager.*", "Osano", ESSENTIAL),
    (r"cookie[-_]?consent|cookie[-_]?(accepted|preferences|policy)|gdpr[-_]?consent", "Consent preference", ESSENTIAL),
    (r"consentUUID|usnatUUID|_sp_su|_sp_user_consent_.*|_sp_v1_.*", "Sourcepoint", ESSENTIAL),
]

# ---------------------------------------------------------------------------
# Functional but not strictly necessary (preferences). Reported as REVIEW.
# ---------------------------------------------------------------------------
FUNCTIONAL_COOKIE_SIGNATURES = [
    (r"NEXT_LOCALE|i18n(ext)?|lang(uage)?|locale|country|currency", "Preference", FUNCTIONAL),
    (r"theme|dark[-_]?mode|color[-_]?scheme", "Preference", FUNCTIONAL),
    (r"intercom-(id|session|device-id)-.*", "Intercom", FUNCTIONAL),
    (r"__stripe_mid|__stripe_sid", "Stripe", FUNCTIONAL),
    (r"__zlcmid|zte2095|zlcstore.*", "Zendesk chat", FUNCTIONAL),
    (r"drift.*|driftt_.*", "Drift", FUNCTIONAL),
    (r"crisp-client.*", "Crisp", FUNCTIONAL),
]

# ---------------------------------------------------------------------------
# Tracking cookies that require consent.
# ---------------------------------------------------------------------------
TRACKER_COOKIE_SIGNATURES = [
    # Google Analytics / Tag Manager
    (r"_ga", "Google Analytics", ANALYTICS),
    (r"_ga_[A-Z0-9]+", "Google Analytics 4", ANALYTICS),
    (r"_gid", "Google Analytics", ANALYTICS),
    (r"_gat(_.*)?", "Google Analytics", ANALYTICS),
    (r"__utm[abcvxz]|__utmt.*", "Google Analytics (Universal)", ANALYTICS),
    (r"_gac_.*", "Google Ads conversion linker", ADVERTISING),
    (r"_gcl_(au|aw|dc|gb|gf|ha)", "Google Ads conversion linker", ADVERTISING),
    (r"_dc_gtm_.*", "Google Tag Manager", ANALYTICS),
    (r"__gads|__gpi|__eoi", "Google Ad Manager", ADVERTISING),
    (r"IDE|DSID|test_cookie|1P_JAR|ANID|NID|AEC|__Secure-3PSID|__Secure-3PAPISID|__Secure-1PSID|__Secure-3PSIDCC", "Google Ads", ADVERTISING),
    (r"receive-cookie-deprecation", "Google Privacy Sandbox", ADVERTISING),
    # Meta
    (r"_fbp|_fbc|fr|datr|sb|act|c_user|xs", "Meta (Facebook)", ADVERTISING),
    # Microsoft
    (r"_uetsid|_uetvid|_uetmsclkid", "Microsoft Advertising (UET)", ADVERTISING),
    (r"MUID|MR|MSPTC|SRM_B|ANONCHK|CLID|SM", "Microsoft / Bing", ADVERTISING),
    (r"_clck|_clsk", "Microsoft Clarity", ANALYTICS),
    # TikTok, Pinterest, Snap, Reddit, X, LinkedIn
    (r"_ttp|_tt_enable_cookie|ttwid|tt_chain_token|tt_csrf_token", "TikTok", ADVERTISING),
    (r"_pin_unauth|_pinterest_ct_ua|_pinterest_sess|_derived_epik", "Pinterest", ADVERTISING),
    (r"_scid|_sctr|sc_at|_schn|_scid_r", "Snapchat", ADVERTISING),
    (r"_rdt_uuid|_rdt_cid", "Reddit", ADVERTISING),
    (r"personalization_id|guest_id(_ads|_marketing)?|muc_ads|_twitter_sess|twid", "X (Twitter)", ADVERTISING),
    (r"li_sugr|bcookie|bscookie|lidc|UserMatchHistory|AnalyticsSyncHistory|li_fat_id|li_gc", "LinkedIn", ADVERTISING),
    (r"VISITOR_INFO1_LIVE|YSC|YEC|GPS|VISITOR_PRIVACY_METADATA", "YouTube", ADVERTISING),
    (r"__qca", "Quantcast", ADVERTISING),
    (r"cto_bundle|cto_bidid|cto_.*|_cc_id", "Criteo", ADVERTISING),
    (r"__adroll.*|_adroll.*", "AdRoll", ADVERTISING),
    (r"_kuid_.*", "Salesforce DMP (Krux)", ADVERTISING),
    (r"t_gid|tuuid|tuuid_lu|_taboola.*|trc_cookie_storage", "Taboola", ADVERTISING),
    (r"obuid|outbrain.*", "Outbrain", ADVERTISING),
    (r"_pubcid|_pubcid_.*", "Prebid Publisher Common ID", ADVERTISING),
    (r"uuid2|anj|icu", "Xandr (AppNexus)", ADVERTISING),
    (r"demdex|dpm|AMCV_.*|AMCVS_.*|s_vi|s_fid|s_cc|s_sq|s_ecid|mbox|at_check", "Adobe Experience Cloud", ANALYTICS),
    # Session replay, product analytics, A/B testing
    (r"_hjSessionUser_.*|_hjSession_.*|_hjid|_hjFirstSeen|_hjAbsoluteSessionInProgress|_hjIncludedInPageviewSample|_hjIncludedInSessionSample.*|_hjTLDTest|_hjRecordingEnabled|_hjRecordingLastActivity", "Hotjar", ANALYTICS),
    (r"ajs_user_id|ajs_anonymous_id|ajs_group_id|analytics_session_id.*", "Segment", ANALYTICS),
    (r"mp_.*_mixpanel|mixpanel.*", "Mixpanel", ANALYTICS),
    (r"amplitude_id.*|AMP_.*|amp_.*", "Amplitude", ANALYTICS),
    (r"_pk_id\..*|_pk_ses\..*|_pk_ref\..*|_pk_cvar\..*|_pk_hsr\..*|mtm_.*|MATOMO_SESSID", "Matomo", ANALYTICS),
    (r"hubspotutk|__hstc|__hssc|__hssrc|__hs_opt_out|__hs_do_not_track|__hs_initial_opt_in|messagesUtk", "HubSpot", ANALYTICS),
    (r"_ce\.s|_ce\.clock_data|_ce\.clock_event|cebs|cebsp_", "Crazy Egg", ANALYTICS),
    (r"_vwo_.*|_vis_opt_.*|_vwo_uuid_v2|_vwo_ds|_vwo_sn", "VWO", ANALYTICS),
    (r"optimizelyEndUserId|optimizelySegments|optimizelyBuckets|optimizelyPendingLogEvents|optimizelyRedirectData", "Optimizely", ANALYTICS),
    (r"_fs_.*|fs_uid|fs_lua", "FullStory", ANALYTICS),
    (r"mf_[0-9a-f-]{8,}|mf_user", "Mouseflow", ANALYTICS),
    (r"_lo_uid|_lo_v|_lo_v_.*", "Lucky Orange", ANALYTICS),
    (r"_hp2_.*", "Heap", ANALYTICS),
    (r"__insp_.*|_inspectlet.*|__inspectlet.*", "Inspectlet", ANALYTICS),
    (r"_biz_.*|_mkto_trk", "Marketo / Bizible", ANALYTICS),
    (r"visitor_id[0-9]+(-hash)?|lpv[0-9]+", "Pardot", ANALYTICS),
    (r"__q_state_.*|_ym_.*|_ymab_param|yandexuid|yabs-sid|yp|ymex", "Yandex Metrica", ANALYTICS),
    (r"_cs_c|_cs_id|_cs_s|_cs_mk|_cs_cvars|_cs_same_site|_cs_ex", "Contentsquare", ANALYTICS),
    (r"kampyle.*", "Medallia", ANALYTICS),
    (r"WRIgnore|WRUIDCD.*|WRUID", "WebTrends", ANALYTICS),
    (r"__ssid|_sp_id\..*|_sp_ses\..*", "Snowplow", ANALYTICS),
    (r"NREUM", "New Relic", ANALYTICS),
    (r"__atuvc|__atuvs|__atrfs|__atssc|__atuvc_.*", "AddThis", SOCIAL),
    (r"__sharethis_cookie_test__|__unam|_stid|_stidv", "ShareThis", SOCIAL),
    (r"fbm_.*|fbsr_.*", "Facebook social login", SOCIAL),
    # Publisher analytics and audience measurement
    (r"_cb|_chartbeat2|_chartbeat4|_cb_svref|_cb_ls|_cb_lm|_cbt", "Chartbeat", ANALYTICS),
    (r"cX_P|cX_G|cX_S", "Cxense", ADVERTISING),
    (r"IMRID", "Nielsen", ANALYTICS),
    (r"__tbc|__pvi|__pat|xbc|_pprv|_pctx|_pcid|_pcus|pa_vid", "Piano", ANALYTICS),
]

# Tracker cookie names that are too short or generic to match on name alone
# (for example "id", "fr", "sb", "act", "xs", "c_user", "lang", "sess", "icu", "SM").
# They only match a tracker signature when the cookie domain also belongs to the
# vendor, which avoids flagging a first party cookie that happens to be named "id".
NAME_REQUIRES_DOMAIN = {
    "fr", "sb", "act", "xs", "c_user", "datr", "icu", "anj", "uuid2", "mr", "sm",
    "dpm", "yp", "ide", "dsid", "nid", "aec", "test_cookie", "gps", "ysc", "yec",
    "clid", "muid",
}

# ---------------------------------------------------------------------------
# Tracker domains (cookies set by or requests sent to these hosts).
# ---------------------------------------------------------------------------
TRACKER_DOMAIN_SIGNATURES = [
    # Google
    ("google-analytics.com", "Google Analytics", ANALYTICS),
    ("analytics.google.com", "Google Analytics", ANALYTICS),
    ("googletagmanager.com", "Google Tag Manager", ANALYTICS),
    ("doubleclick.net", "Google Ads / DoubleClick", ADVERTISING),
    ("googlesyndication.com", "Google AdSense", ADVERTISING),
    ("googleadservices.com", "Google Ads", ADVERTISING),
    ("googletagservices.com", "Google Publisher Tag", ADVERTISING),
    ("adservice.google.com", "Google Ads", ADVERTISING),
    ("youtube.com", "YouTube", ADVERTISING),
    ("youtube-nocookie.com", "YouTube (privacy enhanced)", FUNCTIONAL),
    # Meta
    ("facebook.net", "Meta Pixel / SDK", ADVERTISING),
    ("facebook.com", "Meta (Facebook)", ADVERTISING),
    ("fbcdn.net", "Meta", ADVERTISING),
    ("instagram.com", "Instagram", SOCIAL),
    # Microsoft
    ("clarity.ms", "Microsoft Clarity", ANALYTICS),
    ("bat.bing.com", "Microsoft Advertising (UET)", ADVERTISING),
    ("bing.com", "Microsoft / Bing", ADVERTISING),
    ("ads.linkedin.com", "LinkedIn Ads", ADVERTISING),
    ("px.ads.linkedin.com", "LinkedIn Insight Tag", ADVERTISING),
    ("licdn.com", "LinkedIn", SOCIAL),
    ("linkedin.com", "LinkedIn", SOCIAL),
    # Other social and ad platforms
    ("analytics.tiktok.com", "TikTok Pixel", ADVERTISING),
    ("tiktok.com", "TikTok", ADVERTISING),
    ("ads-twitter.com", "X (Twitter) Ads", ADVERTISING),
    ("twitter.com", "X (Twitter)", SOCIAL),
    ("t.co", "X (Twitter)", ADVERTISING),
    ("pinterest.com", "Pinterest", ADVERTISING),
    ("snapchat.com", "Snapchat", ADVERTISING),
    ("sc-static.net", "Snapchat Pixel", ADVERTISING),
    ("redditstatic.com", "Reddit", ADVERTISING),
    ("addthis.com", "AddThis", SOCIAL),
    ("sharethis.com", "ShareThis", SOCIAL),
    # Ad tech
    ("criteo.com", "Criteo", ADVERTISING),
    ("criteo.net", "Criteo", ADVERTISING),
    ("taboola.com", "Taboola", ADVERTISING),
    ("outbrain.com", "Outbrain", ADVERTISING),
    ("adsrvr.org", "The Trade Desk", ADVERTISING),
    ("rubiconproject.com", "Magnite (Rubicon)", ADVERTISING),
    ("pubmatic.com", "PubMatic", ADVERTISING),
    ("openx.net", "OpenX", ADVERTISING),
    ("casalemedia.com", "Index Exchange", ADVERTISING),
    ("amazon-adsystem.com", "Amazon Advertising", ADVERTISING),
    ("adnxs.com", "Xandr (AppNexus)", ADVERTISING),
    ("scorecardresearch.com", "Comscore", ANALYTICS),
    ("quantserve.com", "Quantcast", ADVERTISING),
    ("quantcount.com", "Quantcast", ADVERTISING),
    ("bluekai.com", "Oracle BlueKai", ADVERTISING),
    ("demdex.net", "Adobe Audience Manager", ADVERTISING),
    ("everesttech.net", "Adobe Advertising", ADVERTISING),
    ("omtrdc.net", "Adobe Analytics", ANALYTICS),
    ("2o7.net", "Adobe Analytics", ANALYTICS),
    ("agkn.com", "Neustar", ADVERTISING),
    ("mathtag.com", "MediaMath", ADVERTISING),
    ("adform.net", "Adform", ADVERTISING),
    ("smartadserver.com", "Equativ (Smart)", ADVERTISING),
    ("teads.tv", "Teads", ADVERTISING),
    ("yahoo.com", "Yahoo", ADVERTISING),
    ("analytics.yahoo.com", "Yahoo Analytics", ANALYTICS),
    # Product analytics, session replay, marketing automation
    ("hotjar.com", "Hotjar", ANALYTICS),
    ("hotjar.io", "Hotjar", ANALYTICS),
    ("fullstory.com", "FullStory", ANALYTICS),
    ("mouseflow.com", "Mouseflow", ANALYTICS),
    ("crazyegg.com", "Crazy Egg", ANALYTICS),
    ("luckyorange.com", "Lucky Orange", ANALYTICS),
    ("inspectlet.com", "Inspectlet", ANALYTICS),
    ("heapanalytics.com", "Heap", ANALYTICS),
    ("segment.io", "Segment", ANALYTICS),
    ("segment.com", "Segment", ANALYTICS),
    ("mixpanel.com", "Mixpanel", ANALYTICS),
    ("amplitude.com", "Amplitude", ANALYTICS),
    ("optimizely.com", "Optimizely", ANALYTICS),
    ("vwo.com", "VWO", ANALYTICS),
    ("hs-analytics.net", "HubSpot", ANALYTICS),
    ("hubspot.com", "HubSpot", ANALYTICS),
    ("hsforms.com", "HubSpot", ANALYTICS),
    ("marketo.net", "Marketo", ANALYTICS),
    ("mktoresp.com", "Marketo", ANALYTICS),
    ("pardot.com", "Pardot", ANALYTICS),
    ("mc.yandex.ru", "Yandex Metrica", ANALYTICS),
    ("yandex.ru", "Yandex", ANALYTICS),
    ("contentsquare.net", "Contentsquare", ANALYTICS),
    ("matomo.cloud", "Matomo Cloud", ANALYTICS),
    ("snowplowanalytics.com", "Snowplow", ANALYTICS),
    ("nr-data.net", "New Relic Browser", ANALYTICS),
    ("chartbeat.com", "Chartbeat", ANALYTICS),
    ("chartbeat.net", "Chartbeat", ANALYTICS),
    ("cxense.com", "Cxense", ADVERTISING),
    ("imrworldwide.com", "Nielsen", ANALYTICS),
    ("stackadapt.com", "StackAdapt", ADVERTISING),
    ("rlcdn.com", "LiveRamp", ADVERTISING),
    ("3lift.com", "TripleLift", ADVERTISING),
    ("tapad.com", "Tapad", ADVERTISING),
    ("simpli.fi", "Simpli.fi", ADVERTISING),
    ("gumgum.com", "GumGum", ADVERTISING),
    ("yieldmo.com", "Yieldmo", ADVERTISING),
    ("sitescout.com", "SiteScout", ADVERTISING),
    ("contextweb.com", "PulsePoint", ADVERTISING),
    ("semasio.net", "Semasio", ADVERTISING),
    ("360yield.com", "Improve Digital", ADVERTISING),
    ("seedtag.com", "Seedtag", ADVERTISING),
    ("media.net", "Media.net", ADVERTISING),
]

# Domains used only to validate generic cookie names (see NAME_REQUIRES_DOMAIN).
# They are not used to flag network requests, because requests to these hosts are
# often legitimate (maps, captcha, fonts, search).
COOKIE_ONLY_DOMAIN_SIGNATURES = [
    ("google.com", "Google", ADVERTISING),
    ("google.ie", "Google", ADVERTISING),
    ("google.co.uk", "Google", ADVERTISING),
    ("microsoft.com", "Microsoft", ADVERTISING),
    ("live.com", "Microsoft", ADVERTISING),
    ("yandex.com", "Yandex", ANALYTICS),
]
